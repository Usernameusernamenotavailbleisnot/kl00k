const { ethers } = require('ethers');
const axios = require('axios');
const fs = require('fs');
const YAML = require('yaml');
const http = require('http');
const https = require('https');
const chalk = require('chalk');
const figlet = require('figlet');
const path = require('path');
// Import dependencies
const axiosRetry = require('axios-retry').default;

// Load configuration
const config = YAML.parse(fs.readFileSync('./config.yaml', 'utf8'));

// Load private keys and proxies
const privateKeys = fs.readFileSync('./pk.txt', 'utf8').split('\n').filter(Boolean);
const proxies = fs.readFileSync('./proxy.txt', 'utf8').split('\n').filter(Boolean);

// Logging utility
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
    const truncatedWallet = wallet === 'SYSTEM' ? 'SYSTEM' : `${wallet.slice(0, 6)}...${wallet.slice(-4)}`;
    console.log(chalk.blue(`[${timestamp}] [${truncatedWallet}] ${message}`));
  },
  error: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? 'SYSTEM' : `${wallet.slice(0, 6)}...${wallet.slice(-4)}`;
    console.log(chalk.red(`[${timestamp}] [${truncatedWallet}] ${message}`));
  },
  success: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? 'SYSTEM' : `${wallet.slice(0, 6)}...${wallet.slice(-4)}`;
    console.log(chalk.green(`[${timestamp}] [${truncatedWallet}] ${message}`));
  },
  warning: (wallet, message) => {
    const timestamp = logger.formatDate(new Date());
    const truncatedWallet = wallet === 'SYSTEM' ? 'SYSTEM' : `${wallet.slice(0, 6)}...${wallet.slice(-4)}`;
    console.log(chalk.yellow(`[${timestamp}] [${truncatedWallet}] ${message}`));
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
      
      await sleep(delay);
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

// Enhanced KlokApp API class
class KlokAppAPI {
  constructor(privateKey, proxy) {
    this.wallet = new ethers.Wallet(privateKey);
    this.axiosInstance = createAxiosInstance(proxy);
    this.sessionToken = null;
    this.proxy = proxy;
    this.retryCount = 0;
    this.maxRetries = config.retries.max;
  }

  async verify() {
    try {
      logger.info(this.wallet.address, `Using proxy: ${this.proxy}`);
      
      // Test proxy connection
      try {
        logger.info(this.wallet.address, 'Testing proxy connection...');
        await this.axiosInstance.get('https://api.ipify.org?format=json');
        logger.success(this.wallet.address, 'Proxy connection successful');
      } catch (error) {
        logger.error(this.wallet.address, `Proxy test failed: ${error.message}`);
        throw new Error(`Proxy connection failed: ${error.message}`);
      }
  
      const nonce = ethers.utils.hexlify(ethers.utils.randomBytes(48)).slice(2);
      const message = `klokapp.ai wants you to sign in with your Ethereum account:\n${this.wallet.address}\n\n\nURI: https://klokapp.ai/\nVersion: 1\nChain ID: 1\nNonce: ${nonce}\nIssued At: ${new Date().toISOString()}`;
      
      logger.info(this.wallet.address, 'Signing message...');
      const signedMessage = await this.wallet.signMessage(message);
      
      logger.info(this.wallet.address, 'Making verification request...');
      const response = await this.axiosInstance.post('https://api1-pp.klokapp.ai/v1/verify', {
        signedMessage,
        message,
        referral_code: null
      });
      
      this.sessionToken = response.data.session_token;
      logger.success(this.wallet.address, 'Verification successful');
      return response.data;
    } catch (error) {
      logger.error(this.wallet.address, `Verification failed: ${error.message}`);
      if (error.response) {
        logger.error(this.wallet.address, `Response data: ${JSON.stringify(error.response.data)}`);
      }
      throw error;
    }
  }

  async checkPoints() {
    try {
      const response = await this.axiosInstance.get('https://api1-pp.klokapp.ai/v1/points', {
        headers: { 'x-session-token': this.sessionToken }
      });
      logger.info(this.wallet.address, `Points: ${JSON.stringify(response.data)}`);
      return response.data;
    } catch (error) {
      logger.error(this.wallet.address, `Failed to check points: ${error.message}`);
      throw error;
    }
  }

  async checkRateLimit() {
    try {
      const response = await this.axiosInstance.get('https://api1-pp.klokapp.ai/v1/rate-limit', {
        headers: { 'x-session-token': this.sessionToken }
      });
      logger.info(this.wallet.address, `Rate limit: ${JSON.stringify(response.data)}`);
      return response.data;
    } catch (error) {
      logger.error(this.wallet.address, `Failed to check rate limit: ${error.message}`);
      throw error;
    }
  }

  async chat(message) {
    try {
      const chatId = ethers.utils.id(Date.now().toString()).slice(2, 38);
      const response = await this.axiosInstance.post('https://api1-pp.klokapp.ai/v1/chat', {
        id: chatId,
        title: "",
        messages: [{ role: "user", content: message }],
        sources: [],
        model: "llama-3.3-70b-instruct",
        created_at: new Date().toISOString(),
        language: "english"
      }, {
        headers: { 'x-session-token': this.sessionToken }
      });
      
      logger.success(this.wallet.address, `Chat message sent successfully`);
      this.retryCount = 0; // Reset retry count on success
      return response.data;
    } catch (error) {
      if (error.code === 'ECONNABORTED' && this.retryCount < this.maxRetries) {
        this.retryCount++;
        logger.warning(this.wallet.address, `Chat request aborted, retry attempt ${this.retryCount}...`);
        await sleep(getRandomDelay(this.retryCount));
        return this.chat(message);
      }
      
      logger.error(this.wallet.address, `Failed to send chat: ${error.message}`);
      throw error;
    }
  }
}

// Enhanced wallet processing
async function processWallet(privateKey, proxy) {
  const api = new KlokAppAPI(privateKey, proxy);
  const wallet = new ethers.Wallet(privateKey).address;
  try {
    // Verify
    logger.info(wallet, 'Starting verification...');
    await withRetry(() => api.verify(), wallet);
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
    const chatMessages = [
      "what is klok AI"
    ];

    const maxAttempts = Math.min(chatLimit, config.maxOperations);
    for (let i = 0; i < maxAttempts; i++) {
      logger.info(wallet, `Sending chat ${i + 1}/${maxAttempts}...`);
      const message = chatMessages[i % chatMessages.length];
      
      try {
        await withRetry(() => api.chat(message), wallet);
        await sleep(getRandomDelay());
      } catch (error) {
        logger.error(wallet, `Failed to send chat ${i + 1}, skipping to next: ${error.message}`);
        continue;
      }
    }

    // Check final points
    logger.info(wallet, 'Checking final points...');
    const finalPoints = await withRetry(() => api.checkPoints(), wallet);
    
    // Calculate points earned
    const pointsEarned = finalPoints.total - initialPoints.total;
    logger.success(wallet, `Points earned: ${pointsEarned}`);
    logger.success(wallet, 'All operations completed successfully');
  } catch (error) {
    logger.error(wallet, `Fatal error: ${error.message}`);
    if (error.response) {
      logger.error(wallet, `Response data: ${JSON.stringify(error.response.data)}`);
    }
  }
}

// Main loop with enhanced error handling
async function main() {
  try {
    // Display header
    console.log(chalk.green(figlet.textSync('KlokAPP Bot', { horizontalLayout: 'full' })));
    
    // Validate configuration
    if (!privateKeys.length) {
      throw new Error('No private keys found in pk.txt');
    }
    if (!proxies.length) {
      throw new Error('No proxies found in proxy.txt');
    }
    
    logger.info('SYSTEM', `Loaded ${privateKeys.length} wallets and ${proxies.length} proxies`);
    
    while (true) {
      logger.info('SYSTEM', 'Starting new round...');
      
      for (let i = 0; i < privateKeys.length; i++) {
        const privateKey = privateKeys[i];
        const proxy = proxies[i % proxies.length];
        
        try {
          logger.info('SYSTEM', `Processing wallet ${i + 1}/${privateKeys.length}`);
          await processWallet(privateKey, proxy);
        } catch (error) {
          logger.error('SYSTEM', `Failed to process wallet ${i + 1}: ${error.message}`);
          continue; // Continue with next wallet even if current one fails
        }
        
        // Add delay between wallets
        if (i < privateKeys.length - 1) {
          const delay = getRandomDelay();
          logger.info('SYSTEM', `Waiting ${delay}ms before next wallet...`);
          await sleep(delay);
        }
      }
      
      logger.info('SYSTEM', `Round completed. Waiting 25 hours before next round...`);
      await sleep(25 * 60 * 60 * 1000); // 25 hours in milliseconds
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
