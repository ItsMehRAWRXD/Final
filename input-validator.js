/**
 * Comprehensive Input Validation System for RawrZ Platform
 * Provides secure input validation, sanitization, and type checking
 */

const SecurityUtils = require('./security-utils');

class InputValidator {
    constructor() {
        this.security = new SecurityUtils();
        this.validationRules = this.initializeValidationRules();
        this.sanitizationRules = this.initializeSanitizationRules();
    }

    /**
     * Initialize validation rules for different input types
     */
    initializeValidationRules() {
        return {
            // Mathematical expressions
            mathExpression: {
                pattern: /^[0-9+\-*/().\s,]+$/,
                maxLength: 1000,
                minLength: 1,
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
                    /prototype/i
                ]
            },
            
            // File paths
            filePath: {
                pattern: /^[a-zA-Z0-9._\-\/\\]+$/,
                maxLength: 4096,
                minLength: 1,
                dangerousPatterns: [
                    /\.\./,
                    /~/
                ]
            },
            
            // Filenames
            filename: {
                pattern: /^[a-zA-Z0-9._-]+$/,
                maxLength: 255,
                minLength: 1,
                dangerousPatterns: [
                    /[<>:"|?*]/,
                    /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i
                ]
            },
            
            // URLs
            url: {
                pattern: /^https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/[^\s]*)?$/,
                maxLength: 2048,
                minLength: 10,
                dangerousPatterns: [
                    /javascript:/i,
                    /data:/i,
                    /vbscript:/i,
                    /file:/i
                ]
            },
            
            // IP addresses
            ipAddress: {
                pattern: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
                maxLength: 15,
                minLength: 7
            },
            
            // Email addresses
            email: {
                pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
                maxLength: 254,
                minLength: 5
            },
            
            // Cryptographic keys
            cryptoKey: {
                pattern: /^[a-fA-F0-9]+$/,
                maxLength: 128,
                minLength: 32
            },
            
            // Base64 encoded data
            base64: {
                pattern: /^[A-Za-z0-9+/]*={0,2}$/,
                maxLength: 10000,
                minLength: 4
            },
            
            // JSON strings
            json: {
                pattern: /^[\s\S]*$/,
                maxLength: 10000,
                minLength: 2,
                validateFunction: (input) => {
                    try {
                        JSON.parse(input);
                        return true;
                    } catch {
                        return false;
                    }
                }
            },
            
            // Command line arguments
            commandArgs: {
                pattern: /^[a-zA-Z0-9\s._-]+$/,
                maxLength: 1000,
                minLength: 1,
                dangerousPatterns: [
                    /[;&|`$]/,
                    /\.\./,
                    /eval\s*\(/i,
                    /exec\s*\(/i,
                    /system\s*\(/i
                ]
            }
        };
    }

    /**
     * Initialize sanitization rules
     */
    initializeSanitizationRules() {
        return {
            // HTML sanitization
            html: {
                allowedTags: ['b', 'i', 'em', 'strong', 'p', 'br'],
                allowedAttributes: []
            },
            
            // SQL injection prevention
            sql: {
                dangerousPatterns: [
                    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/i,
                    /(--|\/\*|\*\/)/,
                    /(;|\||&)/
                ]
            },
            
            // XSS prevention
            xss: {
                dangerousPatterns: [
                    /<script[^>]*>[\s\S]*?<\/script>/gi,
                    /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
                    /<object[^>]*>[\s\S]*?<\/object>/gi,
                    /<embed[^>]*>[\s\S]*?<\/embed>/gi,
                    /<link[^>]*>[\s\S]*?<\/link>/gi,
                    /<meta[^>]*>[\s\S]*?<\/meta>/gi,
                    /javascript:/gi,
                    /vbscript:/gi,
                    /onload\s*=/gi,
                    /onerror\s*=/gi,
                    /onclick\s*=/gi
                ]
            }
        };
    }

    /**
     * Validate input based on type
     */
    validate(input, type, options = {}) {
        // Basic input validation
        if (input === null || input === undefined) {
            throw new Error('Input cannot be null or undefined');
        }

        if (typeof input !== 'string') {
            input = String(input);
        }

        // Get validation rules for type
        const rules = this.validationRules[type];
        if (!rules) {
            throw new Error(`Unknown validation type: ${type}`);
        }

        // Length validation
        if (rules.maxLength && input.length > rules.maxLength) {
            throw new Error(`Input exceeds maximum length of ${rules.maxLength} characters`);
        }

        if (rules.minLength && input.length < rules.minLength) {
            throw new Error(`Input is shorter than minimum length of ${rules.minLength} characters`);
        }

        // Pattern validation
        if (rules.pattern && !rules.pattern.test(input)) {
            throw new Error(`Input does not match required pattern for type: ${type}`);
        }

        // Dangerous pattern detection
        if (rules.dangerousPatterns) {
            for (const pattern of rules.dangerousPatterns) {
                if (pattern.test(input)) {
                    throw new Error(`Input contains potentially dangerous content`);
                }
            }
        }

        // Custom validation function
        if (rules.validateFunction && !rules.validateFunction(input)) {
            throw new Error(`Input failed custom validation for type: ${type}`);
        }

        // Additional security checks
        this.performSecurityChecks(input, type);

        return input;
    }

    /**
     * Perform additional security checks
     */
    performSecurityChecks(input, type) {
        // Check for SQL injection patterns
        for (const pattern of this.sanitizationRules.sql.dangerousPatterns) {
            if (pattern.test(input)) {
                throw new Error('Input contains SQL injection patterns');
            }
        }

        // Check for XSS patterns
        for (const pattern of this.sanitizationRules.xss.dangerousPatterns) {
            if (pattern.test(input)) {
                throw new Error('Input contains XSS patterns');
            }
        }

        // Check for command injection
        const commandInjectionPatterns = [
            /[;&|`$]/,
            /\.\./,
            /eval\s*\(/i,
            /exec\s*\(/i,
            /system\s*\(/i,
            /child_process/i
        ];

        for (const pattern of commandInjectionPatterns) {
            if (pattern.test(input)) {
                throw new Error('Input contains command injection patterns');
            }
        }
    }

    /**
     * Sanitize input based on type
     */
    sanitize(input, type, options = {}) {
        let sanitized = input;

        // Basic sanitization
        sanitized = sanitized.trim();

        // Type-specific sanitization
        switch (type) {
            case 'html':
                sanitized = this.sanitizeHTML(sanitized, options);
                break;
            case 'filename':
                sanitized = this.sanitizeFilename(sanitized);
                break;
            case 'filePath':
                sanitized = this.sanitizeFilePath(sanitized);
                break;
            case 'mathExpression':
                sanitized = this.sanitizeMathExpression(sanitized);
                break;
            case 'commandArgs':
                sanitized = this.sanitizeCommandArgs(sanitized);
                break;
        }

        return sanitized;
    }

    /**
     * Sanitize HTML content
     */
    sanitizeHTML(input, options = {}) {
        const rules = this.sanitizationRules.html;
        let sanitized = input;

        // Remove dangerous tags
        const dangerousTags = /<(?!\/?(?:b|i|em|strong|p|br)\b)[^>]*>/gi;
        sanitized = sanitized.replace(dangerousTags, '');

        // Remove dangerous attributes
        const dangerousAttrs = /on\w+\s*=\s*["'][^"']*["']/gi;
        sanitized = sanitized.replace(dangerousAttrs, '');

        return sanitized;
    }

    /**
     * Sanitize filename
     */
    sanitizeFilename(input) {
        let sanitized = input;

        // Remove dangerous characters
        sanitized = sanitized.replace(/[<>:"|?*]/g, '_');

        // Remove reserved names
        const reservedNames = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i;
        if (reservedNames.test(sanitized)) {
            sanitized = '_' + sanitized;
        }

        // Limit length
        if (sanitized.length > 255) {
            const ext = sanitized.split('.').pop();
            const name = sanitized.substring(0, 255 - ext.length - 1);
            sanitized = name + '.' + ext;
        }

        return sanitized;
    }

    /**
     * Sanitize file path
     */
    sanitizeFilePath(input) {
        let sanitized = input;

        // Normalize path separators
        sanitized = sanitized.replace(/[\\/]+/g, '/');

        // Remove directory traversal
        sanitized = sanitized.replace(/\.\./g, '');

        // Remove leading slashes if not allowed
        if (!process.env.ALLOW_ABSOLUTE_PATHS && sanitized.startsWith('/')) {
            sanitized = sanitized.substring(1);
        }

        return sanitized;
    }

    /**
     * Sanitize math expression
     */
    sanitizeMathExpression(input) {
        let sanitized = input;

        // Remove all whitespace
        sanitized = sanitized.replace(/\s/g, '');

        // Remove any non-math characters
        sanitized = sanitized.replace(/[^0-9+\-*/().,]/g, '');

        return sanitized;
    }

    /**
     * Sanitize command arguments
     */
    sanitizeCommandArgs(input) {
        let sanitized = input;

        // Remove dangerous characters
        sanitized = sanitized.replace(/[;&|`$]/g, '');

        // Remove directory traversal
        sanitized = sanitized.replace(/\.\./g, '');

        return sanitized;
    }

    /**
     * Validate and sanitize input in one step
     */
    validateAndSanitize(input, type, options = {}) {
        // First sanitize
        const sanitized = this.sanitize(input, type, options);
        
        // Then validate
        return this.validate(sanitized, type, options);
    }

    /**
     * Create validation middleware for functions
     */
    createValidationMiddleware(validationRules) {
        return (fn) => {
            return (...args) => {
                // Validate arguments based on rules
                for (let i = 0; i < validationRules.length; i++) {
                    const rule = validationRules[i];
                    if (rule && args[i] !== undefined) {
                        this.validate(args[i], rule.type, rule.options);
                    }
                }
                
                return fn(...args);
            };
        };
    }

    /**
     * Get validation statistics
     */
    getValidationStats() {
        return {
            supportedTypes: Object.keys(this.validationRules),
            sanitizationRules: Object.keys(this.sanitizationRules),
            totalRules: Object.keys(this.validationRules).length
        };
    }
}

module.exports = InputValidator;