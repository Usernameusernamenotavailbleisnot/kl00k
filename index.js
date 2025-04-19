const { ethers } = require('ethers');
const axios = require('axios');
const fs = require('fs');
const YAML = require('yaml');
const http = require('http');
const https = require('https');
const chalk = require('chalk');
const figlet = require('figlet');
const path = require('path');
const gradient = require('gradient-string');
const ora = require('ora');
// For boxen, we need to import it correctly depending on version
let boxen;
try {
  // Try to import boxen as a function (older versions)
  boxen = require('boxen');
  // Test if it's a function
  if (typeof boxen !== 'function') {
    // If not a function, it might be a default export (newer versions)
    boxen = require('boxen').default;
  }
} catch (error) {
  // Fallback if boxen fails to load
  boxen = (text, options) => {
    // Simple fallback for boxen if it's not available
    const paddingLine = '│' + ' '.repeat(text.split('\n')[0].length + 2) + '│';
    const topLine = '┌' + '─'.repeat(text.split('\n')[0].length + 2) + '┐';
    const bottomLine = '└' + '─'.repeat(text.split('\n')[0].length + 2) + '┘';
    
    return topLine + '\n' + 
           paddingLine + '\n' + 
           text.split('\n').map(line => `│ ${line} │`).join('\n') + '\n' + 
           paddingLine + '\n' + 
           bottomLine;
  };
}
const Table = require('cli-table3');
// Import dependencies
const axiosRetry = require('axios-retry').default;

// Load configuration
const config = YAML.parse(fs.readFileSync('./config.yaml', 'utf8'));

// Load private keys and proxies
const privateKeys = fs.readFileSync('./pk.txt', 'utf8').split('\n').filter(Boolean);
const proxies = fs.readFileSync('./proxy.txt', 'utf8').split('\n').filter(Boolean);

// Enhanced Logging utility with better formatting and colors
const logger = {
  formatDate: (date) => {
    const dd = String(date.getDate()).padStart(2, '0');
    const mm = String(date.getMonth() + 1).padStart(2, '0');
    const yyyy = date.getFullYear();
    const hh = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    const ss = String(date.getSeconds()).padStart(2, '0');
    return `${dd}/${mm}/${yyyy} - ${hh}:${min}:${ss}`;
  },
  info: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? chalk.bold.cyan('SYSTEM') : `${chalk.bold.blue(wallet.slice(0, 6))}...${chalk.bold.blue(wallet.slice(-4))}`;
    console.log(`[${chalk.gray(timestamp)}] [${truncatedWallet}] ${chalk.blue('ℹ')} ${chalk.blue(message)}`);
  },
  error: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? chalk.bold.cyan('SYSTEM') : `${chalk.bold.red(wallet.slice(0, 6))}...${chalk.bold.red(wallet.slice(-4))}`;
    console.log(`[${chalk.gray(timestamp)}] [${truncatedWallet}] ${chalk.red('✖')} ${chalk.red(message)}`);
  },
  success: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? chalk.bold.cyan('SYSTEM') : `${chalk.bold.green(wallet.slice(0, 6))}...${chalk.bold.green(wallet.slice(-4))}`;
    console.log(`[${chalk.gray(timestamp)}] [${truncatedWallet}] ${chalk.green('✓')} ${chalk.green(message)}`);
  },
  warning: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? chalk.bold.cyan('SYSTEM') : `${chalk.bold.yellow(wallet.slice(0, 6))}...${chalk.bold.yellow(wallet.slice(-4))}`;
    console.log(`[${chalk.gray(timestamp)}] [${truncatedWallet}] ${chalk.yellow('⚠')} ${chalk.yellow(message)}`);
  },
  sectionHeader: (title) => {
    console.log('\n' + chalk.bold.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log(chalk.bold.cyan('  ' + title));
    console.log(chalk.bold.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━') + '\n');
  },
  pointsTable: (wallet, initial, final, earned) => {
    try {
      const table = new Table({
        head: [chalk.cyan('Point Type'), chalk.cyan('Initial'), chalk.cyan('Final'), chalk.cyan('Earned')],
        style: {
          head: [],
          border: []
        }
      });
      
      // Create rows for each point type
      for (const type in initial.points) {
        const initialVal = initial.points[type] || 0;
        const finalVal = final.points[type] || 0;
        const earnedVal = finalVal - initialVal;
        
        table.push([
          type,
          initialVal,
          finalVal,
          earnedVal > 0 ? chalk.green(`+${earnedVal}`) : earnedVal === 0 ? chalk.gray(earnedVal) : chalk.red(earnedVal)
        ]);
      }
      
      // Total row
      table.push([
        chalk.bold('TOTAL'),
        chalk.bold(initial.total_points || 0),
        chalk.bold(final.total_points || 0),
        chalk.bold.green(`+${earned}`)
      ]);
      
      try {
        // Try to use boxen with error handling
        console.log(boxen(table.toString(), {
          padding: 1,
          margin: 1,
          borderStyle: 'round',
          borderColor: 'cyan',
          title: `Points for ${wallet.slice(0, 6)}...${wallet.slice(-4)}`,
          titleAlignment: 'center'
        }));
      } catch (error) {
        // Fallback if boxen fails
        console.log(`\n--- Points for ${wallet.slice(0, 6)}...${wallet.slice(-4)} ---\n`);
        console.log(table.toString());
        console.log('\n----------------------\n');
      }
    } catch (error) {
      // Simple fallback if table creation fails
      logger.info(wallet, `Points earned: +${earned}`);
      logger.info(wallet, `Initial points: ${initial.total_points || 0}, Final points: ${final.total_points || 0}`);
    }
  }
};

// Random delay utility with progressive backoff
function getRandomDelay(attempt = 1) {
  const baseDelay = Math.floor(Math.random() * (config.delays.max - config.delays.min + 1)) + config.delays.min;
  return baseDelay * Math.pow(1.5, attempt - 1);
}

// Sleep utility
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Circuit breaker implementation
class CircuitBreaker {
  constructor() {
    this.failures = 0;
    this.lastFailureTime = null;
    this.state = 'CLOSED';
    this.threshold = 5;
    this.timeout = 60000; // 1 minute timeout
  }

  async execute(operation) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime >= this.timeout) {
        this.state = 'HALF-OPEN';
      } else {
        throw new Error('Circuit breaker is OPEN');
      }
    }

    try {
      const result = await operation();
      if (this.state === 'HALF-OPEN') {
        this.state = 'CLOSED';
        this.failures = 0;
      }
      return result;
    } catch (error) {
      this.failures++;
      this.lastFailureTime = Date.now();
      
      if (this.failures >= this.threshold) {
        this.state = 'OPEN';
      }
      throw error;
    }
  }
}

// CapSolver API Client for reCAPTCHA solving
class CapSolverClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://api.capsolver.com';
  }

  async createTask(siteKey, siteUrl, pageAction = "WALLET_CONNECT") {
    try {
      const response = await axios.post(`${this.baseUrl}/createTask`, {
        clientKey: this.apiKey,
        task: {
          type: "ReCaptchaV3EnterpriseTaskProxyless",
          websiteURL: siteUrl,
          websiteKey: siteKey,
          pageAction: pageAction
        }
      });

      if (response.data.errorId !== 0) {
        throw new Error(`CapSolver error: ${response.data.errorDescription}`);
      }

      return response.data.taskId;
    } catch (error) {
      throw new Error(`Failed to create CapSolver task: ${error.message}`);
    }
  }

  async getTaskResult(taskId) {
    try {
      let retries = 0;
      const maxRetries = 20; // 20 attempts with 2-second intervals = max 40 seconds wait
      
      while (retries < maxRetries) {
        const response = await axios.post(`${this.baseUrl}/getTaskResult`, {
          clientKey: this.apiKey,
          taskId: taskId
        });

        if (response.data.errorId !== 0) {
          throw new Error(`CapSolver error: ${response.data.errorDescription}`);
        }

        if (response.data.status === 'ready') {
          return response.data.solution.gRecaptchaResponse;
        }

        await sleep(2000); // Wait 2 seconds before trying again
        retries++;
      }

      throw new Error('Timed out waiting for CapSolver task result');
    } catch (error) {
      throw new Error(`Failed to get CapSolver task result: ${error.message}`);
    }
  }

  async solveRecaptcha(siteKey, siteUrl, pageAction = "WALLET_CONNECT") {
    let spinner = null;
    try {
      spinner = ora('Solving reCAPTCHA...').start();
      const taskId = await this.createTask(siteKey, siteUrl, pageAction);
      
      if (spinner) {
        spinner.text = 'Waiting for reCAPTCHA solution...';
      } else {
        logger.info('SYSTEM', 'Waiting for reCAPTCHA solution...');
      }
      
      const token = await this.getTaskResult(taskId);
      
      if (spinner) {
        spinner.succeed('reCAPTCHA solved successfully');
      } else {
        logger.success('SYSTEM', 'reCAPTCHA solved successfully');
      }
      
      return token;
    } catch (error) {
      if (spinner) {
        spinner.fail(`reCAPTCHA solving failed: ${error.message}`);
      } else {
        logger.error('SYSTEM', `reCAPTCHA solving failed: ${error.message}`);
      }
      throw error;
    }
  }
}

// Enhanced retry mechanism with circuit breaker
async function withRetry(operation, wallet, maxRetries = config.retries.max) {
  const circuitBreaker = new CircuitBreaker();
  let attempt = 1;

  while (attempt <= maxRetries) {
    try {
      return await circuitBreaker.execute(operation);
    } catch (error) {
      if (attempt === maxRetries) throw error;
      
      const delay = getRandomDelay(attempt);
      logger.error(wallet, `Retry ${attempt}/${maxRetries}: ${error.message}`);
      if (error.response) {
        logger.error(wallet, `Response data: ${JSON.stringify(error.response.data)}`);
      }
      
      try {
        const spinner = ora(`Waiting ${Math.round(delay/1000)}s before retry...`).start();
        await sleep(delay);
        if (spinner && spinner.stop) {
          spinner.stop();
        }
      } catch (spinnerError) {
        // Fallback if the spinner fails
        logger.info(wallet, `Waiting ${Math.round(delay/1000)}s before retry...`);
        await sleep(delay);
      }
      
      attempt++;
    }
  }
}

// Create axios instance with enhanced proxy configuration
function createAxiosInstance(proxy) {
  try {
    const [auth, address] = proxy.split('@');
    const [username, password] = auth.split(':');
    const [host, port] = address.split(':');
    
    logger.info('SYSTEM', `Creating axios instance with host: ${host}, port: ${port}`);
    
    const proxyUrl = `http://${username}:${password}@${host}:${port}`;
    
    const httpsAgent = new https.Agent({
      proxy: proxyUrl,
      keepAlive: true,
      keepAliveMsecs: 1000000,
      timeout: config.timeouts.connect,
      rejectUnauthorized: false,
      maxSockets: 1,
      maxFreeSockets: 1
    });

    const instance = axios.create({
      proxy: false,
      httpsAgent,
      timeout: config.timeouts.request,
      timeoutErrorMessage: 'Request timeout exceeded',
      maxRedirects: 5,
      validateStatus: function (status) {
        return status >= 200 && status < 600;
      },
      headers: {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br, zstd',
        'accept-language': 'en-US,en;q=0.9',
        'content-type': 'application/json',
        'origin': 'https://klokapp.ai',
        'priority': 'u=1, i',
        'referer': 'https://klokapp.ai/',
        'sec-ch-ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'
      }
    });

    // Add custom retry mechanism
    instance.interceptors.response.use(
      response => response,
      async error => {
        const config = error.config;
        
        // Initialize retry count if not exists
        if (!config.retryCount) {
          config.retryCount = 0;
        }

        // Check if we should retry
        if (config.retryCount < 3 && (
          error.code === 'ECONNABORTED' ||
          error.code === 'ETIMEDOUT' ||
          error.code === 'ECONNREFUSED' ||
          (error.response && [408, 429, 500, 502, 503, 504].includes(error.response.status))
        )) {
          config.retryCount += 1;
          const delay = getRandomDelay(config.retryCount);
          await sleep(delay);
          return instance(config);
        }

        return Promise.reject(error);
      }
    );

    // Add response interceptor for stream handling
    instance.interceptors.response.use(
      response => response,
      async error => {
        if (error.code === 'ECONNABORTED') {
          logger.warning('SYSTEM', 'Connection aborted, retrying...');
          return instance(error.config);
        }
        throw error;
      }
    );

    return instance;
  } catch (error) {
    throw new Error(`Failed to create axios instance: ${error.message}`);
  }
}

// Enhanced KlokApp API class with reCAPTCHA and session token support
class KlokAppAPI {
  constructor(privateKey, proxy, capSolverApiKey) {
    this.wallet = new ethers.Wallet(privateKey);
    this.axiosInstance = createAxiosInstance(proxy);
    this.sessionToken = null;
    this.proxy = proxy;
    this.retryCount = 0;
    this.maxRetries = config.retries.max;
    this.capSolver = new CapSolverClient(capSolverApiKey);
    this.recaptchaSiteKey = config.capsolver?.siteKey || '6LcZrRMrAAAAAKllb4TLb1CWH2LR7iNOKmT7rt3L';
    this.pageAction = config.capsolver?.pageAction || 'WALLET_CONNECT';
    this.siteUrl = 'https://klokapp.ai';
  }

  async verify() {
    let spinner = null;
    try {
      logger.info(this.wallet.address, `Using proxy: ${this.proxy}`);
      
      // Test proxy connection
      try {
        spinner = ora('Testing proxy connection...').start();
        await this.axiosInstance.get('https://api.ipify.org?format=json');
        if (spinner) {
          spinner.succeed('Proxy connection successful');
        } else {
          logger.success(this.wallet.address, 'Proxy connection successful');
        }
      } catch (error) {
        if (spinner) {
          spinner.fail(`Proxy test failed: ${error.message}`);
        }
        logger.error(this.wallet.address, `Proxy test failed: ${error.message}`);
        throw new Error(`Proxy connection failed: ${error.message}`);
      }
  
      // Try different pageAction values if first one fails
      let recaptchaToken;
      const pageActions = ["WALLET_CONNECT", "page_load"];
      let successfulAction = null;
      let lastError = null;
      
      for (const action of pageActions) {
        try {
          logger.info(this.wallet.address, `Solving reCAPTCHA Enterprise Invisible with page action: ${action}...`);
          recaptchaToken = await this.capSolver.solveRecaptcha(this.recaptchaSiteKey, this.siteUrl, action);
          successfulAction = action;
          logger.success(this.wallet.address, `Successfully solved reCAPTCHA with page action: ${action}`);
          break;
        } catch (error) {
          logger.warning(this.wallet.address, `Failed to solve reCAPTCHA with page action ${action}: ${error.message}`);
          lastError = error;
        }
      }
      
      if (!recaptchaToken) {
        throw new Error(`Failed to solve reCAPTCHA with any page action: ${lastError?.message}`);
      }
      
      const nonce = ethers.utils.hexlify(ethers.utils.randomBytes(48)).slice(2);
      const message = `klokapp.ai wants you to sign in with your Ethereum account:\n${this.wallet.address}\n\n\nURI: https://klokapp.ai/\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
      
      spinner = ora('Signing message...').start();
      const signedMessage = await this.wallet.signMessage(message);
      
      if (spinner) {
        spinner.succeed('Message signed successfully');
        spinner.text = 'Making verification request...';
        spinner.start();
      } else {
        logger.success(this.wallet.address, 'Message signed successfully');
        logger.info(this.wallet.address, 'Making verification request...');
      }
      
      try {
        logger.info(this.wallet.address, 'Sending verification request with reCAPTCHA token...');
        
        const verifyResponse = await this.axiosInstance.post('https://api1-pp.klokapp.ai/v1/verify', {
          signedMessage,
          message,
          referral_code: null,
          recaptcha_token: recaptchaToken
        });
        
        // Check if the response contains the expected session_token
        if (verifyResponse.data && verifyResponse.data.session_token) {
          this.sessionToken = verifyResponse.data.session_token;
          
          // Update axios instance to include session token in headers for all future requests
          this.axiosInstance.defaults.headers.common['x-session-token'] = this.sessionToken;
          
          if (spinner) {
            spinner.succeed('Verification successful');
          } else {
            logger.success(this.wallet.address, 'Verification successful');
          }
          
          if (this.sessionToken) {
            logger.success(this.wallet.address, `Session token acquired: ${this.sessionToken.substring(0, 10)}...`);
          }
        } else {
          // If session token is missing from response
          if (spinner) {
            spinner.warn('Verification response missing session token');
          } else {
            logger.warning(this.wallet.address, 'Verification response missing session token');
          }
          logger.warning(this.wallet.address, `Response data: ${JSON.stringify(verifyResponse.data)}`);
          throw new Error('Session token not found in verification response');
        }
        
        return verifyResponse.data;
      } catch (error) {
        if (spinner) {
          spinner.fail(`Verification request failed: ${error.message}`);
        } else {
          logger.error(this.wallet.address, `Verification request failed: ${error.message}`);
        }
        throw error;
      }
    } catch (error) {
      logger.error(this.wallet.address, `Verification failed: ${error.message}`);
      if (error.response) {
        logger.error(this.wallet.address, `Response data: ${JSON.stringify(error.response.data)}`);
      }
      throw error;
    }
  }

  async getUserInfo() {
    let spinner = null;
    try {
      spinner = ora('Fetching user info...').start();
      const response = await this.axiosInstance.get('https://api1-pp.klokapp.ai/v1/me');
      
      if (spinner) {
        spinner.succeed('User info fetched successfully');
      } else {
        logger.success(this.wallet.address, 'User info fetched successfully');
      }
      
      logger.info(this.wallet.address, `User ID: ${response.data.user_id}`);
      logger.info(this.wallet.address, `Tier: ${response.data.tier}`);
      
      return response.data;
    } catch (error) {
      if (spinner) {
        spinner.fail(`Failed to get user info: ${error.message}`);
      }
      logger.error(this.wallet.address, `Failed to get user info: ${error.message}`);
      throw error;
    }
  }

  async checkPoints() {
    let spinner = null;
    try {
      spinner = ora('Checking points...').start();
      const response = await this.axiosInstance.get('https://api1-pp.klokapp.ai/v1/points');
      
      if (spinner) {
        spinner.succeed('Points fetched successfully');
      } else {
        logger.success(this.wallet.address, 'Points fetched successfully');
      }
      
      const totalPoints = response.data.total_points || Object.values(response.data.points).reduce((sum, val) => sum + val, 0);
      logger.info(this.wallet.address, `Total Points: ${chalk.cyan(totalPoints)}`);
      
      return response.data;
    } catch (error) {
      if (spinner) {
        spinner.fail(`Failed to check points: ${error.message}`);
      }
      logger.error(this.wallet.address, `Failed to check points: ${error.message}`);
      throw error;
    }
  }

  async checkRateLimit() {
    let spinner = null;
    try {
      spinner = ora('Checking rate limit...').start();
      const response = await this.axiosInstance.get('https://api1-pp.klokapp.ai/v1/rate-limit');
      
      if (spinner) {
        spinner.succeed('Rate limit fetched successfully');
      } else {
        logger.success(this.wallet.address, 'Rate limit fetched successfully');
      }
      
      logger.info(this.wallet.address, `Limit: ${response.data.limit}, Remaining: ${response.data.remaining}, Reset in: ${Math.floor(response.data.reset_time/60)} minutes`);
      
      // Create a visual representation of the rate limit
      const usedBars = response.data.current_usage;
      const remainingBars = response.data.remaining;
      const totalBars = response.data.limit;
      
      let progressBar = '';
      for (let i = 0; i < totalBars; i++) {
        if (i < usedBars) {
          progressBar += chalk.red('■ ');
        } else {
          progressBar += chalk.green('■ ');
        }
      }
      
      console.log(progressBar);
      console.log(`${chalk.red(`Used: ${usedBars}`)} | ${chalk.green(`Remaining: ${remainingBars}`)}`);
      
      return response.data;
    } catch (error) {
      if (spinner) {
        spinner.fail(`Failed to check rate limit: ${error.message}`);
      }
      logger.error(this.wallet.address, `Failed to check rate limit: ${error.message}`);
      throw error;
    }
  }

  async chat(message) {
    let spinner = null;
    try {
      const chatId = ethers.utils.id(Date.now().toString()).slice(2, 38);
      
      spinner = ora(`Sending chat: "${message.substring(0, 30)}${message.length > 30 ? '...' : ''}"`).start();
      
      const response = await this.axiosInstance.post('https://api1-pp.klokapp.ai/v1/chat', {
        id: chatId,
        title: "",
        messages: [{ role: "user", content: message }],
        sources: [],
        model: "llama-3.3-70b-instruct",
        created_at: new Date().toISOString(),
        language: "english"
      });
      
      if (spinner) {
        spinner.succeed('Chat message sent successfully');
      } else {
        logger.success(this.wallet.address, 'Chat message sent successfully');
      }
      
      // No need to get chat title as it's only saved locally
      // Skipping the chat title request
      
      this.retryCount = 0; // Reset retry count on success
      return response.data;
    } catch (error) {
      if (error.code === 'ECONNABORTED' && this.retryCount < this.maxRetries) {
        this.retryCount++;
        logger.warning(this.wallet.address, `Chat request aborted, retry attempt ${this.retryCount}...`);
        await sleep(getRandomDelay(this.retryCount));
        return this.chat(message);
      }
      
      if (spinner) {
        spinner.fail(`Failed to send chat: ${error.message}`);
      }
      logger.error(this.wallet.address, `Failed to send chat: ${error.message}`);
      throw error;
    }
  }
}

// Enhanced wallet processing with better visuals
async function processWallet(privateKey, proxy, capSolverApiKey) {
  const api = new KlokAppAPI(privateKey, proxy, capSolverApiKey);
  const wallet = new ethers.Wallet(privateKey).address;
  
  logger.sectionHeader(`Processing Wallet: ${wallet.slice(0, 6)}...${wallet.slice(-4)}`);
  
  try {
    // Verify
    logger.info(wallet, 'Starting verification process...');
    await withRetry(() => api.verify(), wallet);
    await sleep(getRandomDelay());

    // Get user info
    logger.info(wallet, 'Fetching user information...');
    await withRetry(() => api.getUserInfo(), wallet);
    await sleep(getRandomDelay());

    // Check rate limit
    logger.info(wallet, 'Checking rate limit...');
    const rateLimit = await withRetry(() => api.checkRateLimit(), wallet);
    const chatLimit = rateLimit.remaining;
    await sleep(getRandomDelay());

    // Check initial points
    logger.info(wallet, 'Checking initial points...');
    const initialPoints = await withRetry(() => api.checkPoints(), wallet);
    await sleep(getRandomDelay());

    // Perform chats with enhanced error handling
    const chatMessages = config.chat.messages || ["what is klok AI"];

    const maxAttempts = Math.min(chatLimit, config.maxOperations);
    logger.sectionHeader(`Sending ${maxAttempts} Chat Messages`);
    
    let successfulChats = 0;
    for (let i = 0; i < maxAttempts; i++) {
      logger.info(wallet, `Sending chat ${i + 1}/${maxAttempts}...`);
      const message = chatMessages[i % chatMessages.length];
      
      try {
        await withRetry(() => api.chat(message), wallet);
        successfulChats++;
        
        // Check rate limit after each successful chat
        if (i < maxAttempts - 1) {
          await withRetry(() => api.checkRateLimit(), wallet);
        }
        
        await sleep(getRandomDelay());
      } catch (error) {
        logger.error(wallet, `Failed to send chat ${i + 1}, skipping to next: ${error.message}`);
        continue;
      }
    }

    // Check final points
    logger.info(wallet, 'Checking final points...');
    const finalPoints = await withRetry(() => api.checkPoints(), wallet);
    
    // Calculate and display points earned
    const pointsEarned = finalPoints.total_points - initialPoints.total_points;
    logger.pointsTable(wallet, initialPoints, finalPoints, pointsEarned);
    
    logger.success(wallet, `All operations completed successfully (${successfulChats}/${maxAttempts} chats sent)`);
    
    return {
      wallet,
      status: 'success',
      initialPoints: initialPoints.total_points,
      finalPoints: finalPoints.total_points,
      pointsEarned,
      chatsCompleted: successfulChats
    };
  } catch (error) {
    logger.error(wallet, `Fatal error: ${error.message}`);
    if (error.response) {
      logger.error(wallet, `Response data: ${JSON.stringify(error.response.data)}`);
    }
    
    return {
      wallet,
      status: 'failed',
      error: error.message
    };
  }
}

// Results tracker for session summary
class ResultsTracker {
  constructor() {
    this.results = [];
    this.startTime = Date.now();
  }
  
  addResult(result) {
    this.results.push(result);
  }
  
  displaySummary() {
    try {
      const duration = (Date.now() - this.startTime) / 1000 / 60; // minutes
      const successful = this.results.filter(r => r.status === 'success').length;
      const failed = this.results.filter(r => r.status === 'failed').length;
      const totalPointsEarned = this.results.reduce((sum, r) => sum + (r.pointsEarned || 0), 0);
      const totalChatsCompleted = this.results.reduce((sum, r) => sum + (r.chatsCompleted || 0), 0);
      
      logger.sectionHeader('Session Summary');
      
      // Create a summary table
      const table = new Table({
        head: [
          chalk.cyan('Metric'), 
          chalk.cyan('Value')
        ],
        style: {
          head: [],
          border: []
        }
      });
      
      table.push(
        ['Total Duration', `${duration.toFixed(2)} minutes`],
        ['Wallets Processed', this.results.length],
        ['Successful', chalk.green(successful)],
        ['Failed', failed > 0 ? chalk.red(failed) : chalk.green(failed)],
        ['Total Points Earned', chalk.green(totalPointsEarned)],
        ['Total Chats Completed', totalChatsCompleted],
        ['Points per Wallet (avg)', (totalPointsEarned / (successful || 1)).toFixed(2)]
      );
      
      try {
        // Try to use boxen with error handling
        console.log(boxen(table.toString(), {
          padding: 1,
          margin: 1,
          borderStyle: 'round',
          borderColor: 'cyan',
          title: 'Results Summary',
          titleAlignment: 'center'
        }));
      } catch (error) {
        // Fallback if boxen fails
        console.log('\n--- Results Summary ---\n');
        console.log(table.toString());
        console.log('\n----------------------\n');
      }
      
      // Display errors if any
      const errors = this.results.filter(r => r.status === 'failed');
      if (errors.length > 0) {
        logger.sectionHeader('Errors Summary');
        
        const errorTable = new Table({
          head: [
            chalk.red('Wallet'), 
            chalk.red('Error')
          ],
          style: {
            head: [],
            border: []
          },
          colWidths: [20, 80]
        });
        
        errors.forEach(e => {
          const truncatedWallet = `${e.wallet.slice(0, 6)}...${e.wallet.slice(-4)}`;
          errorTable.push([truncatedWallet, e.error]);
        });
        
        console.log(errorTable.toString());
      }
    } catch (error) {
      // Fallback if anything fails in the display summary
      logger.error('SYSTEM', `Failed to display summary: ${error.message}`);
      console.log('\nSession Results:');
      console.log(`- Successful: ${this.results.filter(r => r.status === 'success').length}`);
      console.log(`- Failed: ${this.results.filter(r => r.status === 'failed').length}`);
    }
  }
}

// Main loop with enhanced error handling and visualizations
async function main() {
  try {
    // Display header with gradient colors
    console.log('\n');
    console.log(gradient.rainbow(figlet.textSync('KlokAPP Bot', { 
      font: 'Big',
      horizontalLayout: 'full' 
    })));
    console.log('\n');
    
    // Load configuration
    logger.sectionHeader('Loading Configuration');
    
    // Check if CAPSOLVER_API_KEY is in environment or config
    const capSolverApiKey = process.env.CAPSOLVER_API_KEY || config.capsolver?.apiKey;
    if (!capSolverApiKey) {
      throw new Error('CapSolver API key is required. Set it in environment variable CAPSOLVER_API_KEY or in config.yaml');
    }
    
    // Validate configuration
    if (!privateKeys.length) {
      throw new Error('No private keys found in pk.txt');
    }
    if (!proxies.length) {
      throw new Error('No proxies found in proxy.txt');
    }
    
    logger.info('SYSTEM', `Loaded ${chalk.green(privateKeys.length)} wallets and ${chalk.green(proxies.length)} proxies`);
    logger.info('SYSTEM', `CapSolver API key: ${chalk.green('✓')} (configured)`);
    
    const resultsTracker = new ResultsTracker();
    
    while (true) {
      logger.sectionHeader('Starting New Round');
      
      for (let i = 0; i < privateKeys.length; i++) {
        const privateKey = privateKeys[i];
        const proxy = proxies[i % proxies.length];
        
        try {
          logger.info('SYSTEM', `Processing wallet ${i + 1}/${privateKeys.length}`);
          const result = await processWallet(privateKey, proxy, capSolverApiKey);
          resultsTracker.addResult(result);
        } catch (error) {
          logger.error('SYSTEM', `Failed to process wallet ${i + 1}: ${error.message}`);
          resultsTracker.addResult({
            wallet: new ethers.Wallet(privateKey).address,
            status: 'failed',
            error: error.message
          });
          continue; // Continue with next wallet even if current one fails
        }
        
        // Add delay between wallets
        if (i < privateKeys.length - 1) {
          const delay = getRandomDelay();
          try {
            const spinner = ora(`Waiting ${Math.round(delay/1000)}s before next wallet...`).start();
            await sleep(delay);
            if (spinner && spinner.stop) {
              spinner.stop();
            }
          } catch (error) {
            logger.info('SYSTEM', `Waiting ${Math.round(delay/1000)}s before next wallet...`);
            await sleep(delay);
          }
        }
      }
      
      // Display session summary
      resultsTracker.displaySummary();
      
      logger.sectionHeader('Round Completed');
      logger.info('SYSTEM', `Waiting 25 hours before next round...`);
      
      // Visual countdown for next round
      const nextRoundTime = 25 * 60 * 60 * 1000; // 25 hours in milliseconds
      const startWait = Date.now();
      const endWait = startWait + nextRoundTime;
      
      try {
        let spinner = ora('Waiting for next round...').start();
        
        while (Date.now() < endWait) {
          const remaining = endWait - Date.now();
          const hours = Math.floor(remaining / (60 * 60 * 1000));
          const minutes = Math.floor((remaining % (60 * 60 * 1000)) / (60 * 1000));
          
          if (spinner) {
            spinner.text = `Next round in ${hours}h ${minutes}m`;
          } else {
            logger.info('SYSTEM', `Next round in ${hours}h ${minutes}m`);
          }
          await sleep(60000); // Update every minute
        }
        
        if (spinner && spinner.succeed) {
          spinner.succeed('Starting next round');
        } else {
          logger.success('SYSTEM', 'Starting next round');
        }
      } catch (error) {
        logger.info('SYSTEM', 'Waiting for next round...');
        // Fallback to simple wait without spinner
        await sleep(nextRoundTime);
        logger.success('SYSTEM', 'Starting next round');
      }
    }
  } catch (error) {
    logger.error('SYSTEM', `Fatal error in main loop: ${error.message}`);
    process.exit(1);
  }
}

// Enhanced error handling for process
process.on('uncaughtException', (error) => {
  logger.error('SYSTEM', `Uncaught exception: ${error.message}`);
  logger.error('SYSTEM', error.stack);
  process.exit(1);
});

process.on('unhandledRejection', (error) => {
  logger.error('SYSTEM', `Unhandled rejection: ${error.message}`);
  logger.error('SYSTEM', error.stack);
  process.exit(1);
});

// Start the application with error handling
main().catch((error) => {
  logger.error('SYSTEM', `Failed to start application: ${error.message}`);
  logger.error('SYSTEM', error.stack);
  process.exit(1);
});
