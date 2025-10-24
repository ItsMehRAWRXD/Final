/**
 * Enhanced Test Suite for RawrZ Platform Security
 * Comprehensive security testing with proper error handling
 */

const assert = require('assert');

class EnhancedTestSuite {
    constructor() {
        this.tests = [];
        this.passed = 0;
        this.failed = 0;
    }

    addTest(name, testFunction) {
        this.tests.push({ name, testFunction });
    }

    async runTests() {
        console.log('=================================================');
        console.log('RawrZ Security Platform - Enhanced Test Suite');
        console.log('=================================================');
        console.log(`Running ${this.tests.length} tests...\n`);

        for (const test of this.tests) {
            try {
                await test.testFunction();
                console.log(`[PASS] ${test.name}`);
                this.passed++;
            } catch (error) {
                console.log(`[FAIL] ${test.name}: ${error.message}`);
                this.failed++;
            }
        }

        console.log('\n=================================================');
        console.log('Test Summary');
        console.log('=================================================');
        console.log(`Total Tests: ${this.tests.length}`);
        console.log(`Passed: ${this.passed}`);
        console.log(`Failed: ${this.failed}`);
        console.log(`Success Rate: ${((this.passed / this.tests.length) * 100).toFixed(2)}%`);
        console.log('=================================================');
    }

    // Security Tests
    async testCryptoSecurity() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test secure math evaluation
        assert.strictEqual(rawrz.safeMathEval('2 + 2'), 4);
        assert.strictEqual(rawrz.safeMathEval('10 * 5'), 50);
        
        // Test invalid expressions
        assert.throws(() => rawrz.safeMathEval('eval("malicious code")'), Error);
        assert.throws(() => rawrz.safeMathEval('process.exit()'), Error);
        assert.throws(() => rawrz.safeMathEval('require("fs")'), Error);
        assert.throws(() => rawrz.safeMathEval('console.log("test")'), Error);
    }

    async testInputValidation() {
        const InputValidator = require('./input-validator.js');
        const validator = new InputValidator();

        // Test math expression validation
        assert.strictEqual(validator.validate('2 + 2', 'mathExpression'), '2 + 2');
        assert.throws(() => validator.validate('eval("test")', 'mathExpression'), Error);
        assert.throws(() => validator.validate('process.exit()', 'mathExpression'), Error);

        // Test filename validation
        assert.strictEqual(validator.validate('test.txt', 'filename'), 'test.txt');
        assert.throws(() => validator.validate('test<>.txt', 'filename'), Error);
        assert.throws(() => validator.validate('CON.txt', 'filename'), Error);

        // Test URL validation
        assert.strictEqual(validator.validate('https://example.com', 'url'), 'https://example.com');
        assert.throws(() => validator.validate('javascript:alert(1)', 'url'), Error);
        assert.throws(() => validator.validate('data:text/html,<script>', 'url'), Error);
    }

    async testErrorHandling() {
        const ErrorHandler = require('./error-handler.js');
        const errorHandler = new ErrorHandler();

        // Test error sanitization
        const error = new Error('File not found: /sensitive/path/file.txt');
        error.code = 'ENOENT';
        
        const result = errorHandler.handleError(error, { operation: 'file_read' });
        assert.strictEqual(result.success, false);
        assert.strictEqual(result.error.message, 'File or directory not found');
        assert.strictEqual(result.error.code, 'ENOENT');
    }

    async testCryptoSecurityModule() {
        const CryptoSecurity = require('./crypto-security.js');
        const crypto = new CryptoSecurity();

        // Test secure random generation
        const random1 = crypto.generateSecureRandom(32);
        const random2 = crypto.generateSecureRandom(32);
        assert.strictEqual(random1.length, 32);
        assert.notStrictEqual(random1, random2);

        // Test encryption/decryption
        const data = Buffer.from('test data');
        const encrypted = await crypto.encrypt(data, 'aes-256-gcm');
        const decrypted = await crypto.decrypt(
            encrypted.encrypted,
            Buffer.from(encrypted.key, 'hex'),
            Buffer.from(encrypted.iv, 'hex'),
            encrypted.algorithm,
            { authTag: encrypted.authTag }
        );
        assert.strictEqual(decrypted.toString(), data.toString());

        // Test hash generation
        const hash = crypto.generateHash('test data', 'sha256');
        assert.strictEqual(hash.length, 64); // SHA256 hex length

        // Test HMAC
        const key = crypto.generateSecureRandom(32);
        const hmac = crypto.generateHMAC('test data', key);
        assert.strictEqual(crypto.verifyHMAC('test data', key, hmac), true);
        assert.strictEqual(crypto.verifyHMAC('wrong data', key, hmac), false);
    }

    async testSecurityUtils() {
        const SecurityUtils = require('./security-utils.js');
        const security = new SecurityUtils();

        // Test input validation
        assert.strictEqual(security.validateInput('test', 'alphanumeric'), 'test');
        assert.throws(() => security.validateInput('test<script>', 'alphanumeric'), Error);

        // Test secure random generation
        const random = security.generateSecureRandom(16);
        assert.strictEqual(random.length, 32); // hex string length

        // Test file path validation
        assert.strictEqual(security.validateFilePath('test/file.txt'), 'test/file.txt');
        assert.throws(() => security.validateFilePath('../../../etc/passwd'), Error);

        // Test rate limiting
        const rateLimiter = security.createRateLimiter(2, 1000);
        rateLimiter('test-user');
        rateLimiter('test-user');
        assert.throws(() => rateLimiter('test-user'), Error);
    }

    async testFileOperations() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test path traversal prevention
        assert.throws(() => rawrz.readAbsoluteFile('../../../etc/passwd'), Error);
        
        // Test file operations with valid paths
        const result = await rawrz.listFiles('.');
        assert.strictEqual(result.success, true);
    }

    async testNetworkOperations() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test ping with valid host
        const pingResult = await rawrz.ping('8.8.8.8');
        assert.strictEqual(pingResult.success, true);
    }

    async testSystemOperations() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test system info
        const sysInfo = await rawrz.getSystemInfo();
        assert.strictEqual(sysInfo.success, true);
        assert(sysInfo.info.platform);
    }

    async testUtilityFunctions() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test base64 encoding/decoding
        const testData = 'Hello, World!';
        const encoded = await rawrz.base64Encode(testData);
        const decoded = await rawrz.base64Decode(encoded.result);
        assert.strictEqual(decoded.result, testData);
    }

    async testMemoryLimits() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test memory limit enforcement
        const largeData = 'x'.repeat(1000000); // 1MB string
        const result = await rawrz.processLargeData(largeData);
        assert.strictEqual(result.success, false);
        assert(result.error.includes('Memory limit exceeded'));
    }

    async testSecurityMonitor() {
        const SecurityMonitor = require('./security-monitor.js');
        const monitor = new SecurityMonitor();

        // Test security alert generation
        monitor.logSecurityEvent('HIGH', 'Failed login attempt', {
            ip: '192.168.1.100',
            user: 'admin',
            timestamp: new Date()
        });

        // Test rate limiting
        for (let i = 0; i < 5; i++) {
            monitor.checkRateLimit('test-client');
        }
        assert.throws(() => monitor.checkRateLimit('test-client'), Error);
    }

    async testSystemHealth() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test system health check
        const health = await rawrz.checkSystemHealth();
        assert.strictEqual(health.success, true);
        assert(health.health.memory);
        assert(health.health.cpu);
    }
}

// Create and run test suite
async function runTests() {
    const testSuite = new EnhancedTestSuite();

    // Add all tests
    testSuite.addTest('Crypto Security', testSuite.testCryptoSecurity);
    testSuite.addTest('Input Validation', testSuite.testInputValidation);
    testSuite.addTest('Error Handling', testSuite.testErrorHandling);
    testSuite.addTest('Crypto Security Module', testSuite.testCryptoSecurityModule);
    testSuite.addTest('Security Utils', testSuite.testSecurityUtils);
    testSuite.addTest('File Operations', testSuite.testFileOperations);
    testSuite.addTest('Network Operations', testSuite.testNetworkOperations);
    testSuite.addTest('System Operations', testSuite.testSystemOperations);
    testSuite.addTest('Utility Functions', testSuite.testUtilityFunctions);
    testSuite.addTest('Memory Limits', testSuite.testMemoryLimits);
    testSuite.addTest('Security Monitor', testSuite.testSecurityMonitor);
    testSuite.addTest('System Health', testSuite.testSystemHealth);

    await testSuite.runTests();
}

// Run tests if this file is executed directly
if (require.main === module) {
    runTests().catch(console.error);
}

module.exports = EnhancedTestSuite;