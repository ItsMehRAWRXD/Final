/**
 * Security Utilities for RawrZ Platform
 * Provides secure error handling, input validation, and security functions
 */

const crypto = require('crypto');

class SecurityUtils {
    constructor() {
        this.logger = this.createLogger();
        this.sanitizationRules = this.initializeSanitizationRules();
    }

    /**
     * Create a secure logger that doesn't expose sensitive information
     */
    createLogger() {
        return {
            error: (message, error = null) => {
                const sanitizedMessage = this.sanitizeErrorMessage(message, error);
                console.error(`[SECURITY-ERROR] ${sanitizedMessage}`);
            },
            warn: (message) => {
                console.warn(`[SECURITY-WARN] ${message}`);
            },
            info: (message) => {
                console.log(`[SECURITY-INFO] ${message}`);
            },
            debug: (message) => {
                if (process.env.DEBUG_SECURITY === 'true') {
                    console.log(`[SECURITY-DEBUG] ${message}`);
                }
            }
        };
    }

    /**
     * Initialize input sanitization rules
     */
    initializeSanitizationRules() {
        return {
            // Dangerous patterns to block
            dangerousPatterns: [
                /eval\s*\(/i,
                /function\s*\(/i,
                /=>/,
                /process\./i,
                /require\s*\(/i,
                /import\s+/i,
                /console\./i,
                /global\./i,
                /window\./i,
                /document\./i,
                /setTimeout\s*\(/i,
                /setInterval\s*\(/i,
                /new\s+Function/i,
                /\.constructor/i,
                /__proto__/i,
                /prototype/i,
                /child_process/i,
                /fs\./i,
                /path\./i,
                /os\./i,
                /crypto\./i,
                /Buffer\./i,
                /JSON\.parse/i,
                /JSON\.stringify/i
            ],
            // Allowed characters for different input types
            allowedChars: {
                math: /^[0-9+\-*/().\s,]+$/,
                filename: /^[a-zA-Z0-9._-]+$/,
                alphanumeric: /^[a-zA-Z0-9]+$/,
                safeString: /^[a-zA-Z0-9\s._-]+$/
            }
        };
    }

    /**
     * Sanitize error messages to prevent information disclosure
     */
    sanitizeErrorMessage(message, error = null) {
        // Generic error messages for different error types
        const genericMessages = {
            'ENOENT': 'File or directory not found',
            'EACCES': 'Permission denied',
            'EMFILE': 'Too many open files',
            'ENOSPC': 'No space left on device',
            'ECONNREFUSED': 'Connection refused',
            'ETIMEDOUT': 'Operation timed out',
            'ENOTFOUND': 'Host not found',
            'EADDRINUSE': 'Address already in use',
            'EINVAL': 'Invalid argument',
            'EPERM': 'Operation not permitted'
        };

        // If it's a known system error, return generic message
        if (error && error.code && genericMessages[error.code]) {
            return genericMessages[error.code];
        }

        // Remove sensitive information from error messages
        let sanitized = message;
        
        // Remove file paths
        sanitized = sanitized.replace(/\/[^\s]*/g, '[PATH]');
        
        // Remove IP addresses
        sanitized = sanitized.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[IP]');
        
        // Remove email addresses
        sanitized = sanitized.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]');
        
        // Remove potential sensitive data patterns
        sanitized = sanitized.replace(/[A-Za-z0-9+/]{40,}={0,2}/g, '[HASH]');
        
        return sanitized;
    }

    /**
     * Validate and sanitize input based on type
     */
    validateInput(input, type = 'safeString', options = {}) {
        if (!input) {
            throw new Error('Input is required');
        }

        if (typeof input !== 'string') {
            throw new Error('Input must be a string');
        }

        // Check for dangerous patterns
        for (const pattern of this.sanitizationRules.dangerousPatterns) {
            if (pattern.test(input)) {
                throw new Error('Input contains potentially dangerous content');
            }
        }

        // Validate against allowed character set
        const allowedPattern = this.sanitizationRules.allowedChars[type];
        if (allowedPattern && !allowedPattern.test(input)) {
            throw new Error(`Input contains invalid characters for type: ${type}`);
        }

        // Additional length validation
        if (options.maxLength && input.length > options.maxLength) {
            throw new Error(`Input exceeds maximum length of ${options.maxLength}`);
        }

        if (options.minLength && input.length < options.minLength) {
            throw new Error(`Input is shorter than minimum length of ${options.minLength}`);
        }

        return input.trim();
    }

    /**
     * Secure random string generation
     */
    generateSecureRandom(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    /**
     * Secure hash generation
     */
    generateSecureHash(data, algorithm = 'sha256') {
        const hash = crypto.createHash(algorithm);
        hash.update(data);
        return hash.digest('hex');
    }

    /**
     * Rate limiting implementation
     */
    createRateLimiter(maxRequests = 100, windowMs = 60000) {
        const requests = new Map();
        
        return (identifier) => {
            const now = Date.now();
            const windowStart = now - windowMs;
            
            // Clean old entries
            for (const [key, timestamp] of requests.entries()) {
                if (timestamp < windowStart) {
                    requests.delete(key);
                }
            }
            
            // Check current requests
            const userRequests = Array.from(requests.entries())
                .filter(([key, timestamp]) => key.startsWith(identifier) && timestamp > windowStart);
            
            if (userRequests.length >= maxRequests) {
                throw new Error('Rate limit exceeded');
            }
            
            // Add current request
            requests.set(`${identifier}-${now}`, now);
        };
    }

    /**
     * Secure file path validation
     */
    validateFilePath(filePath, allowedExtensions = []) {
        // Normalize path
        const normalizedPath = filePath.replace(/[\\/]+/g, '/');
        
        // Check for directory traversal
        if (normalizedPath.includes('..') || normalizedPath.includes('~')) {
            throw new Error('Invalid file path: directory traversal detected');
        }
        
        // Check for absolute paths (if not allowed)
        if (normalizedPath.startsWith('/') && !process.env.ALLOW_ABSOLUTE_PATHS) {
            throw new Error('Invalid file path: absolute paths not allowed');
        }
        
        // Check file extension
        if (allowedExtensions.length > 0) {
            const ext = normalizedPath.split('.').pop().toLowerCase();
            if (!allowedExtensions.includes(ext)) {
                throw new Error(`Invalid file extension: ${ext}`);
            }
        }
        
        return normalizedPath;
    }

    /**
     * Secure environment variable access
     */
    getSecureEnvVar(name, defaultValue = null, required = false) {
        const value = process.env[name];
        
        if (required && !value) {
            throw new Error(`Required environment variable ${name} is not set`);
        }
        
        return value || defaultValue;
    }

    /**
     * Memory usage monitoring
     */
    checkMemoryUsage() {
        const usage = process.memoryUsage();
        const maxMemory = 1024 * 1024 * 1024; // 1GB limit
        
        if (usage.heapUsed > maxMemory) {
            this.logger.warn('High memory usage detected');
            return false;
        }
        
        return true;
    }

    /**
     * Process monitoring
     */
    monitorProcess() {
        // Check for debugging tools
        const isDebugging = process.env.NODE_OPTIONS && 
            process.env.NODE_OPTIONS.includes('--inspect');
        
        if (isDebugging) {
            this.logger.warn('Debugging mode detected');
        }
        
        // Monitor CPU usage
        const cpuUsage = process.cpuUsage();
        if (cpuUsage.user > 1000000) { // 1 second in microseconds
            this.logger.warn('High CPU usage detected');
        }
    }
}

module.exports = SecurityUtils;