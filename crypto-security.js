/**
 * Enhanced Cryptographic Security Module for RawrZ Platform
 * Provides secure cryptographic operations with proper authentication and validation
 */

const crypto = require('crypto');
const SecurityUtils = require('./security-utils');

class CryptoSecurity {
    constructor() {
        this.security = new SecurityUtils();
        this.supportedAlgorithms = this.initializeSupportedAlgorithms();
        this.keyDerivationConfig = this.initializeKeyDerivationConfig();
    }

    /**
     * Initialize supported cryptographic algorithms
     */
    initializeSupportedAlgorithms() {
        return {
            // Symmetric encryption algorithms (secure)
            symmetric: {
                'aes-128-gcm': { keySize: 16, ivSize: 12, secure: true },
                'aes-192-gcm': { keySize: 24, ivSize: 12, secure: true },
                'aes-256-gcm': { keySize: 32, ivSize: 12, secure: true },
                'aes-128-cbc': { keySize: 16, ivSize: 16, secure: false },
                'aes-192-cbc': { keySize: 24, ivSize: 16, secure: false },
                'aes-256-cbc': { keySize: 32, ivSize: 16, secure: false },
                'chacha20-poly1305': { keySize: 32, ivSize: 12, secure: true },
                'camellia-128-gcm': { keySize: 16, ivSize: 12, secure: true },
                'camellia-192-gcm': { keySize: 24, ivSize: 12, secure: true },
                'camellia-256-gcm': { keySize: 32, ivSize: 12, secure: true }
            },
            
            // Hash algorithms (secure)
            hash: {
                'sha256': { secure: true, outputSize: 32 },
                'sha384': { secure: true, outputSize: 48 },
                'sha512': { secure: true, outputSize: 64 },
                'blake2b256': { secure: true, outputSize: 32 },
                'blake2b512': { secure: true, outputSize: 64 }
            },
            
            // Key derivation functions
            kdf: {
                'pbkdf2': { secure: true, minIterations: 100000 },
                'scrypt': { secure: true, minIterations: 16384 },
                'argon2id': { secure: true, minIterations: 3 }
            }
        };
    }

    /**
     * Initialize key derivation configuration
     */
    initializeKeyDerivationConfig() {
        return {
            pbkdf2: {
                iterations: 100000,
                digest: 'sha256'
            },
            scrypt: {
                N: 16384,
                r: 8,
                p: 1,
                maxmem: 32 * 1024 * 1024 // 32MB
            },
            argon2id: {
                memoryCost: 65536,
                timeCost: 3,
                parallelism: 4
            }
        };
    }

    /**
     * Generate cryptographically secure random bytes
     */
    generateSecureRandom(length) {
        if (length < 1 || length > 1024) {
            throw new Error('Invalid random length: must be between 1 and 1024 bytes');
        }
        
        return crypto.randomBytes(length);
    }

    /**
     * Generate secure key and IV for algorithm
     */
    generateKeyAndIV(algorithm) {
        const algo = this.supportedAlgorithms.symmetric[algorithm];
        if (!algo) {
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        }

        return {
            key: this.generateSecureRandom(algo.keySize),
            iv: this.generateSecureRandom(algo.ivSize)
        };
    }

    /**
     * Derive key from password using secure KDF
     */
    deriveKeyFromPassword(password, salt, algorithm = 'pbkdf2', options = {}) {
        // Validate inputs
        if (!password || typeof password !== 'string') {
            throw new Error('Password must be a non-empty string');
        }

        if (!salt || !Buffer.isBuffer(salt)) {
            throw new Error('Salt must be a Buffer');
        }

        if (salt.length < 16) {
            throw new Error('Salt must be at least 16 bytes');
        }

        const kdfConfig = this.keyDerivationConfig[algorithm];
        if (!kdfConfig) {
            throw new Error(`Unsupported KDF algorithm: ${algorithm}`);
        }

        const keyLength = options.keyLength || 32;
        const iterations = options.iterations || kdfConfig.iterations;

        // Validate iterations
        const minIterations = this.supportedAlgorithms.kdf[algorithm].minIterations;
        if (iterations < minIterations) {
            throw new Error(`Iterations must be at least ${minIterations} for ${algorithm}`);
        }

        try {
            switch (algorithm) {
                case 'pbkdf2':
                    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, kdfConfig.digest);
                
                case 'scrypt':
                    return crypto.scryptSync(password, salt, keyLength, {
                        N: kdfConfig.N,
                        r: kdfConfig.r,
                        p: kdfConfig.p,
                        maxmem: kdfConfig.maxmem
                    });
                
                default:
                    throw new Error(`KDF algorithm not implemented: ${algorithm}`);
            }
        } catch (error) {
            throw new Error(`Key derivation failed: ${error.message}`);
        }
    }

    /**
     * Encrypt data with authentication
     */
    async encrypt(data, algorithm = 'aes-256-gcm', options = {}) {
        // Validate inputs
        if (!data) {
            throw new Error('Data is required for encryption');
        }

        if (!Buffer.isBuffer(data)) {
            data = Buffer.from(data, 'utf8');
        }

        // Validate algorithm
        const algo = this.supportedAlgorithms.symmetric[algorithm];
        if (!algo) {
            throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
        }

        // Warn about insecure algorithms
        if (!algo.secure) {
            this.security.logger.warn(`Using potentially insecure algorithm: ${algorithm}`);
        }

        // Generate or use provided key/IV
        const key = options.key || this.generateSecureRandom(algo.keySize);
        const iv = options.iv || this.generateSecureRandom(algo.ivSize);

        // Validate key and IV sizes
        if (key.length !== algo.keySize) {
            throw new Error(`Invalid key size: expected ${algo.keySize}, got ${key.length}`);
        }

        if (iv.length !== algo.ivSize) {
            throw new Error(`Invalid IV size: expected ${algo.ivSize}, got ${iv.length}`);
        }

        try {
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            
            // Set additional authenticated data if provided
            if (options.aad) {
                cipher.setAAD(Buffer.from(options.aad));
            }

            let encrypted = cipher.update(data);
            encrypted = Buffer.concat([encrypted, cipher.final()]);

            const result = {
                encrypted,
                key: key.toString('hex'),
                iv: iv.toString('hex'),
                algorithm
            };

            // Add authentication tag for authenticated algorithms
            if (algorithm.includes('gcm') || algorithm.includes('poly1305')) {
                result.authTag = cipher.getAuthTag().toString('hex');
            }

            return result;
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt data with authentication verification
     */
    async decrypt(encryptedData, key, iv, algorithm = 'aes-256-gcm', options = {}) {
        // Validate inputs
        if (!encryptedData || !Buffer.isBuffer(encryptedData)) {
            throw new Error('Encrypted data must be a Buffer');
        }

        if (!key || !Buffer.isBuffer(key)) {
            key = Buffer.from(key, 'hex');
        }

        if (!iv || !Buffer.isBuffer(iv)) {
            iv = Buffer.from(iv, 'hex');
        }

        // Validate algorithm
        const algo = this.supportedAlgorithms.symmetric[algorithm];
        if (!algo) {
            throw new Error(`Unsupported decryption algorithm: ${algorithm}`);
        }

        // Validate key and IV sizes
        if (key.length !== algo.keySize) {
            throw new Error(`Invalid key size: expected ${algo.keySize}, got ${key.length}`);
        }

        if (iv.length !== algo.ivSize) {
            throw new Error(`Invalid IV size: expected ${algo.ivSize}, got ${iv.length}`);
        }

        try {
            const decipher = crypto.createDecipheriv(algorithm, key, iv);

            // Set additional authenticated data if provided
            if (options.aad) {
                decipher.setAAD(Buffer.from(options.aad));
            }

            // Set authentication tag for authenticated algorithms
            if (options.authTag) {
                decipher.setAuthTag(Buffer.from(options.authTag, 'hex'));
            }

            let decrypted = decipher.update(encryptedData);
            decrypted = Buffer.concat([decrypted, decipher.final()]);

            return decrypted;
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    /**
     * Generate secure hash
     */
    generateHash(data, algorithm = 'sha256', options = {}) {
        // Validate inputs
        if (!data) {
            throw new Error('Data is required for hashing');
        }

        if (!Buffer.isBuffer(data)) {
            data = Buffer.from(data, 'utf8');
        }

        // Validate algorithm
        const algo = this.supportedAlgorithms.hash[algorithm];
        if (!algo) {
            throw new Error(`Unsupported hash algorithm: ${algorithm}`);
        }

        try {
            const hash = crypto.createHash(algorithm);
            
            // Add salt if provided
            if (options.salt) {
                hash.update(Buffer.from(options.salt));
            }
            
            hash.update(data);
            return hash.digest('hex');
        } catch (error) {
            throw new Error(`Hashing failed: ${error.message}`);
        }
    }

    /**
     * Generate HMAC
     */
    generateHMAC(data, key, algorithm = 'sha256') {
        // Validate inputs
        if (!data) {
            throw new Error('Data is required for HMAC');
        }

        if (!key) {
            throw new Error('Key is required for HMAC');
        }

        if (!Buffer.isBuffer(data)) {
            data = Buffer.from(data, 'utf8');
        }

        if (!Buffer.isBuffer(key)) {
            key = Buffer.from(key, 'hex');
        }

        try {
            const hmac = crypto.createHmac(algorithm, key);
            hmac.update(data);
            return hmac.digest('hex');
        } catch (error) {
            throw new Error(`HMAC generation failed: ${error.message}`);
        }
    }

    /**
     * Verify HMAC
     */
    verifyHMAC(data, key, signature, algorithm = 'sha256') {
        const expectedSignature = this.generateHMAC(data, key, algorithm);
        return crypto.timingSafeEqual(
            Buffer.from(signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
    }

    /**
     * Generate secure random password
     */
    generateSecurePassword(length = 16, options = {}) {
        const {
            includeUppercase = true,
            includeLowercase = true,
            includeNumbers = true,
            includeSymbols = true,
            excludeSimilar = true
        } = options;

        let charset = '';
        
        if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
        if (includeNumbers) charset += '0123456789';
        if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        if (excludeSimilar) {
            charset = charset.replace(/[0O1lI]/g, '');
        }

        if (charset.length === 0) {
            throw new Error('At least one character type must be included');
        }

        let password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = crypto.randomInt(0, charset.length);
            password += charset[randomIndex];
        }

        return password;
    }

    /**
     * Validate cryptographic configuration
     */
    validateCryptoConfig(config) {
        const issues = [];

        // Check algorithm security
        if (config.algorithm && this.supportedAlgorithms.symmetric[config.algorithm]) {
            const algo = this.supportedAlgorithms.symmetric[config.algorithm];
            if (!algo.secure) {
                issues.push(`Algorithm ${config.algorithm} is not considered secure`);
            }
        }

        // Check key derivation
        if (config.kdf && this.supportedAlgorithms.kdf[config.kdf]) {
            const kdf = this.supportedAlgorithms.kdf[config.kdf];
            if (config.iterations && config.iterations < kdf.minIterations) {
                issues.push(`KDF iterations too low for ${config.kdf}: ${config.iterations} < ${kdf.minIterations}`);
            }
        }

        // Check key size
        if (config.keySize && config.keySize < 16) {
            issues.push('Key size too small: minimum 16 bytes recommended');
        }

        if (issues.length > 0) {
            throw new Error(`Cryptographic configuration issues: ${issues.join(', ')}`);
        }
    }

    /**
     * Get security recommendations
     */
    getSecurityRecommendations() {
        return {
            algorithms: {
                recommended: ['aes-256-gcm', 'chacha20-poly1305'],
                avoid: ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc'],
                reason: 'Use authenticated encryption (GCM/Poly1305) instead of CBC mode'
            },
            keyDerivation: {
                recommended: 'pbkdf2 with 100,000+ iterations or scrypt',
                avoid: 'Simple hash functions for key derivation',
                reason: 'Use proper KDF to prevent rainbow table attacks'
            },
            randomGeneration: {
                recommended: 'crypto.randomBytes() or crypto.randomInt()',
                avoid: 'Math.random() or other non-cryptographic PRNGs',
                reason: 'Use cryptographically secure random number generators'
            }
        };
    }
}

module.exports = CryptoSecurity;