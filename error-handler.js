/**
 * Centralized Error Handling System for RawrZ Platform
 * Provides secure error handling, logging, and recovery mechanisms
 */

const SecurityUtils = require('./security-utils');

class ErrorHandler {
    constructor() {
        this.security = new SecurityUtils();
        this.errorCounts = new Map();
        this.maxErrorsPerMinute = 10;
        this.errorWindow = 60000; // 1 minute
    }

    /**
     * Handle errors with security considerations
     */
    handleError(error, context = {}, options = {}) {
        // Rate limiting for error logging
        if (!this.checkErrorRate()) {
            this.security.logger.warn('Error rate limit exceeded, suppressing additional errors');
            return;
        }

        // Sanitize error information
        const sanitizedError = this.sanitizeError(error, context);
        
        // Log error securely
        this.logError(sanitizedError, context, options);
        
        // Return safe error response
        return this.createSafeErrorResponse(sanitizedError, options);
    }

    /**
     * Sanitize error information to prevent information disclosure
     */
    sanitizeError(error, context) {
        const sanitized = {
            message: this.security.sanitizeErrorMessage(
                error.message || 'An error occurred',
                error
            ),
            code: error.code || 'UNKNOWN_ERROR',
            timestamp: new Date().toISOString(),
            context: this.sanitizeContext(context)
        };

        // Only include stack trace in debug mode
        if (process.env.DEBUG_ERRORS === 'true') {
            sanitized.stack = error.stack;
        }

        return sanitized;
    }

    /**
     * Sanitize context information
     */
    sanitizeContext(context) {
        const sanitized = {};
        
        // Only include safe context information
        const safeKeys = ['operation', 'module', 'function', 'userId', 'requestId'];
        
        for (const key of safeKeys) {
            if (context[key]) {
                sanitized[key] = context[key];
            }
        }

        return sanitized;
    }

    /**
     * Log error securely
     */
    logError(sanitizedError, context, options) {
        const logLevel = this.determineLogLevel(sanitizedError, options);
        
        switch (logLevel) {
            case 'error':
                this.security.logger.error(
                    `${sanitizedError.message} [${sanitizedError.code}]`,
                    sanitizedError
                );
                break;
            case 'warn':
                this.security.logger.warn(
                    `${sanitizedError.message} [${sanitizedError.code}]`
                );
                break;
            case 'info':
                this.security.logger.info(
                    `${sanitizedError.message} [${sanitizedError.code}]`
                );
                break;
        }
    }

    /**
     * Determine appropriate log level based on error severity
     */
    determineLogLevel(error, options) {
        const criticalCodes = ['CRYPTO_ERROR', 'SECURITY_ERROR', 'AUTH_ERROR'];
        const warningCodes = ['VALIDATION_ERROR', 'RATE_LIMIT_ERROR'];
        
        if (criticalCodes.includes(error.code)) {
            return 'error';
        } else if (warningCodes.includes(error.code)) {
            return 'warn';
        } else if (options.silent) {
            return 'info';
        } else {
            return 'error';
        }
    }

    /**
     * Create safe error response for API consumers
     */
    createSafeErrorResponse(sanitizedError, options) {
        const response = {
            success: false,
            error: {
                message: sanitizedError.message,
                code: sanitizedError.code,
                timestamp: sanitizedError.timestamp
            }
        };

        // Include request ID if available
        if (sanitizedError.context.requestId) {
            response.error.requestId = sanitizedError.context.requestId;
        }

        // Include additional info only in debug mode
        if (process.env.DEBUG_ERRORS === 'true') {
            response.error.details = sanitizedError.context;
        }

        return response;
    }

    /**
     * Check error rate to prevent log flooding
     */
    checkErrorRate() {
        const now = Date.now();
        const windowStart = now - this.errorWindow;
        
        // Clean old entries
        for (const [timestamp] of this.errorCounts.entries()) {
            if (timestamp < windowStart) {
                this.errorCounts.delete(timestamp);
            }
        }
        
        // Count current errors
        const currentErrors = Array.from(this.errorCounts.keys())
            .filter(timestamp => timestamp > windowStart).length;
        
        if (currentErrors >= this.maxErrorsPerMinute) {
            return false;
        }
        
        // Add current error
        this.errorCounts.set(now, true);
        return true;
    }

    /**
     * Wrap async functions with error handling
     */
    wrapAsync(fn, context = {}) {
        return async (...args) => {
            try {
                return await fn(...args);
            } catch (error) {
                return this.handleError(error, context);
            }
        };
    }

    /**
     * Wrap sync functions with error handling
     */
    wrapSync(fn, context = {}) {
        return (...args) => {
            try {
                return fn(...args);
            } catch (error) {
                return this.handleError(error, context);
            }
        };
    }

    /**
     * Create error for specific scenarios
     */
    createError(code, message, context = {}) {
        const error = new Error(message);
        error.code = code;
        error.context = context;
        return error;
    }

    /**
     * Validate error handling configuration
     */
    validateConfiguration() {
        const issues = [];
        
        if (this.maxErrorsPerMinute < 1) {
            issues.push('maxErrorsPerMinute must be at least 1');
        }
        
        if (this.errorWindow < 1000) {
            issues.push('errorWindow must be at least 1000ms');
        }
        
        if (issues.length > 0) {
            throw new Error(`Invalid error handler configuration: ${issues.join(', ')}`);
        }
    }

    /**
     * Get error statistics
     */
    getErrorStats() {
        const now = Date.now();
        const windowStart = now - this.errorWindow;
        
        const recentErrors = Array.from(this.errorCounts.keys())
            .filter(timestamp => timestamp > windowStart);
        
        return {
            errorsInLastMinute: recentErrors.length,
            maxErrorsPerMinute: this.maxErrorsPerMinute,
            errorWindowMs: this.errorWindow
        };
    }

    /**
     * Reset error counters
     */
    resetErrorCounters() {
        this.errorCounts.clear();
        this.security.logger.info('Error counters reset');
    }
}

module.exports = ErrorHandler;