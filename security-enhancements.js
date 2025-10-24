// RawrZ Security Platform - Critical Security Enhancements
// This module implements the critical security fixes identified in the audit

const crypto = require('crypto');
const path = require('path');
const fs = require('fs').promises;

class SecurityEnhancements {
    constructor() {
        this.rateLimits = new Map();
        this.securityEvents = [];
        this.maxFileSize = 100 * 1024 * 1024; // 100MB
        this.dangerousPaths = [
            '/etc/', '/proc/', '/sys/', '/root/', '/boot/',
            'C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\',
            'C:\\Program Files\\', 'C:\\Program Files (x86)\\'
        ];
    }

    // CRITICAL FIX 1: Secure Math Evaluation (replaces eval())
    safeMathEval(expression) {
        // Input validation
        if (typeof expression !== 'string') {
            throw new Error('Expression must be a string');
        }
        
        if (expression.length > 1000) {
            throw new Error('Expression too long');
        }

        // Sanitize expression - only allow numbers, operators, parentheses, and basic math functions
        const sanitized = expression.replace(/\s+/g, '');
        const allowedPattern = /^[0-9+\-*/.()sqrt()pow()sin()cos()tan()log()abs()ceil()floor()round()pi()e()]+$/i;
        
        if (!allowedPattern.test(sanitized)) {
            throw new Error('Invalid characters in expression');
        }

        // Check for dangerous patterns
        const dangerousPatterns = [
            /eval/i, /function/i, /constructor/i, /prototype/i, 
            /process/i, /require/i, /import/i, /export/i,
            /global/i, /this/i, /window/i, /document/i,
            /__/i, /\[/i, /\]/i
        ];
        
        for (const pattern of dangerousPatterns) {
            if (pattern.test(expression)) {
                throw new Error('Potentially dangerous expression');
            }
        }

        try {
            // Create a safe evaluation context
            const mathContext = {
                sqrt: Math.sqrt,
                pow: Math.pow,
                sin: Math.sin,
                cos: Math.cos,
                tan: Math.tan,
                log: Math.log,
                abs: Math.abs,
                ceil: Math.ceil,
                floor: Math.floor,
                round: Math.round,
                pi: Math.PI,
                e: Math.E
            };

            // Use Function constructor with restricted context (safer than eval)
            const func = new Function('Math', `
                "use strict";
                const {sqrt, pow, sin, cos, tan, log, abs, ceil, floor, round, pi, e} = Math;
                return ${sanitized};
            `);
            
            return func(mathContext);
        } catch (error) {
            throw new Error('Invalid mathematical expression');
        }
    }

    // CRITICAL FIX 2: Comprehensive Input Validation
    validateInput(input, type, options = {}) {
        if (input === null || input === undefined) {
            throw new Error('Input cannot be null or undefined');
        }

        switch (type) {
            case 'string':
                if (typeof input !== 'string') {
                    throw new Error('Input must be a string');
                }
                if (options.maxLength && input.length > options.maxLength) {
                    throw new Error(`Input too long (max: ${options.maxLength})`);
                }
                if (options.minLength && input.length < options.minLength) {
                    throw new Error(`Input too short (min: ${options.minLength})`);
                }
                break;
            
            case 'number':
                if (typeof input !== 'number' || isNaN(input)) {
                    throw new Error('Input must be a valid number');
                }
                if (options.min !== undefined && input < options.min) {
                    throw new Error(`Number too small (min: ${options.min})`);
                }
                if (options.max !== undefined && input > options.max) {
                    throw new Error(`Number too large (max: ${options.max})`);
                }
                break;
            
            case 'filename':
                if (typeof input !== 'string') {
                    throw new Error('Filename must be a string');
                }
                // Check for path traversal attempts
                if (input.includes('..') || input.includes('//') || /[<>:"|?*\x00-\x1F]/.test(input)) {
                    throw new Error('Invalid filename characters');
                }
                break;
            
            case 'algorithm':
                if (typeof input !== 'string') {
                    throw new Error('Algorithm must be a string');
                }
                const validAlgorithms = [
                    'aes256', 'aes192', 'aes128', 'aes-256-gcm', 'aes-192-gcm', 'aes-128-gcm',
                    'camellia256', 'camellia192', 'camellia128', 'chacha20'
                ];
                if (!validAlgorithms.includes(input.toLowerCase())) {
                    throw new Error('Invalid or insecure algorithm specified');
                }
                break;

            case 'path':
                if (typeof input !== 'string') {
                    throw new Error('Path must be a string');
                }
                // Check for dangerous path patterns
                const normalizedPath = path.normalize(input).toLowerCase();
                for (const dangerousPath of this.dangerousPaths) {
                    if (normalizedPath.includes(dangerousPath.toLowerCase())) {
                        throw new Error('Access to sensitive directory denied');
                    }
                }
                break;
        }
        
        return true;
    }

    // CRITICAL FIX 3: Input Sanitization
    sanitizeInput(input, type) {
        if (typeof input !== 'string') {
            return input;
        }

        switch (type) {
            case 'filename':
                // Remove dangerous characters and normalize path
                return path.basename(input).replace(/[^a-zA-Z0-9._-]/g, '_').substring(0, 255);
            
            case 'text':
                // Remove control characters and normalize whitespace
                return input.replace(/[\x00-\x1F\x7F]/g, '').trim().substring(0, 10000);
            
            case 'path':
                // Resolve and normalize path to prevent traversal
                const resolved = path.resolve(path.normalize(input));
                // Ensure it doesn't contain dangerous patterns
                if (resolved.includes('..') || resolved.includes('//')) {
                    throw new Error('Invalid path');
                }
                return resolved;
            
            case 'algorithm':
                // Normalize algorithm names
                return input.toLowerCase().replace(/[^a-z0-9-]/g, '');
            
            default:
                return input;
        }
    }

    // CRITICAL FIX 4: Rate Limiting System
    checkRateLimit(operation = 'default', limit = 10, windowMs = 60000) {
        const now = Date.now();
        const key = `${operation}_${Math.floor(now / windowMs)}`;
        
        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, 0);
        }
        
        const count = this.rateLimits.get(key);
        if (count >= limit) {
            this.logSecurityEvent({
                type: 'rate_limit_exceeded',
                severity: 'warn',
                message: `Rate limit exceeded for operation: ${operation}`,
                details: { operation, count, limit }
            });
            throw new Error('Rate limit exceeded. Please try again later.');
        }
        
        this.rateLimits.set(key, count + 1);
        
        // Clean up old entries
        for (const [k, v] of this.rateLimits.entries()) {
            const keyTime = parseInt(k.split('_')[1]) * windowMs;
            if (now - keyTime > windowMs * 2) {
                this.rateLimits.delete(k);
            }
        }
        
        return true;
    }

    // CRITICAL FIX 5: Secure File Operations
    async secureFileRead(filePath, options = {}) {
        // Validate and sanitize input
        this.validateInput(filePath, 'string', { maxLength: 1000 });
        this.validateInput(filePath, 'path');
        
        const sanitizedPath = this.sanitizeInput(filePath, 'path');
        
        // Check rate limits
        this.checkRateLimit('file_read', 20, 60000);
        
        try {
            // Check file stats before reading
            const stats = await fs.stat(sanitizedPath);
            
            if (stats.size > this.maxFileSize) {
                throw new Error(`File too large (max: ${this.maxFileSize / 1024 / 1024}MB)`);
            }
            
            // Read file with size limit
            const data = await fs.readFile(sanitizedPath, options);
            
            this.logSecurityEvent({
                type: 'file_access',
                severity: 'info',
                message: 'File read successfully',
                details: { path: sanitizedPath, size: stats.size }
            });
            
            return data;
        } catch (error) {
            this.logSecurityEvent({
                type: 'file_error',
                severity: 'warn',
                message: 'File read failed',
                details: { path: sanitizedPath, error: error.message }
            });
            throw new Error('File access denied or file not found');
        }
    }

    // CRITICAL FIX 6: Secure Cryptographic Operations
    async secureEncrypt(data, algorithm = 'aes-256-gcm') {
        // Validate inputs
        this.validateInput(algorithm, 'algorithm');
        
        if (!Buffer.isBuffer(data) && typeof data !== 'string') {
            throw new Error('Data must be a Buffer or string');
        }
        
        const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
        
        // Check rate limits
        this.checkRateLimit('encrypt', 5, 60000);
        
        try {
            // Generate secure random values
            const salt = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            const password = crypto.randomBytes(32);
            
            // Derive key using PBKDF2
            const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha512');
            
            let encrypted, authTag;
            
            if (algorithm.includes('gcm')) {
                // Authenticated encryption
                const cipher = crypto.createCipheriv(algorithm, key, iv);
                encrypted = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
                authTag = cipher.getAuthTag();
            } else {
                // Standard encryption
                const cipher = crypto.createCipheriv(algorithm, key, iv);
                encrypted = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
            }
            
            this.logSecurityEvent({
                type: 'encryption_success',
                severity: 'info',
                message: 'Data encrypted successfully',
                details: { 
                    algorithm, 
                    dataSize: dataBuffer.length,
                    authenticated: !!authTag 
                }
            });
            
            return {
                encrypted,
                password: password.toString('hex'),
                salt: salt.toString('hex'),
                iv: iv.toString('hex'),
                algorithm,
                authTag: authTag ? authTag.toString('hex') : null
            };
        } catch (error) {
            this.logSecurityEvent({
                type: 'encryption_failed',
                severity: 'error',
                message: 'Encryption failed',
                details: { algorithm, error: error.message }
            });
            throw new Error('Encryption operation failed');
        }
    }

    // Security Event Logging
    logSecurityEvent(event) {
        const timestamp = new Date().toISOString();
        const eventId = crypto.randomUUID();
        
        const securityEvent = {
            id: eventId,
            timestamp,
            type: event.type || 'security',
            severity: event.severity || 'info',
            message: event.message,
            details: event.details || {},
            source: event.source || 'security-enhancements'
        };
        
        this.securityEvents.push(securityEvent);
        
        // Keep only recent events in memory
        if (this.securityEvents.length > 1000) {
            this.securityEvents = this.securityEvents.slice(-500);
        }
        
        // Log to console for immediate visibility
        console.log(`[SECURITY] ${securityEvent.severity.toUpperCase()}: ${securityEvent.message}`);
        
        return securityEvent;
    }

    // Get security statistics
    getSecurityStats() {
        const now = Date.now();
        const oneHour = 60 * 60 * 1000;
        
        const recentEvents = this.securityEvents.filter(
            event => now - new Date(event.timestamp).getTime() < oneHour
        );
        
        const eventsByType = {};
        const eventsBySeverity = {};
        
        for (const event of recentEvents) {
            eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
            eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;
        }
        
        return {
            totalEvents: this.securityEvents.length,
            recentEvents: recentEvents.length,
            eventsByType,
            eventsBySeverity,
            rateLimitEntries: this.rateLimits.size
        };
    }
}

module.exports = SecurityEnhancements;