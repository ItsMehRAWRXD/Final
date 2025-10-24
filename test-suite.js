// RawrZ Security Platform - Comprehensive Test Suite
const assert = require('assert');
const fs = require('fs').promises;
const path = require('path');

class TestSuite {
    constructor() {
        this.tests = [];
        this.passed = 0;
        this.failed = 0;
        this.results = [];
    }

    // Add test
    addTest(name, testFunction) {
        this.tests.push({ name, testFunction });
    }

    // Run all tests
    async runAllTests() {
        console.log('=================================================');
        console.log('RawrZ Security Platform - Test Suite');
        console.log('=================================================');
        console.log(`Running ${this.tests.length} tests...\n`);

        for (const test of this.tests) {
            try {
                await test.testFunction();
                this.passed++;
                this.results.push({ name: test.name, status: 'PASSED' });
                console.log(`[PASS] ${test.name}`);
            } catch (error) {
                this.failed++;
                this.results.push({ name: test.name, status: 'FAILED', error: error.message });
                console.log(`[FAIL] ${test.name}: ${error.message}`);
            }
        }

        this.printSummary();
        return this.results;
    }

    // Print test summary
    printSummary() {
        console.log('\n=================================================');
        console.log('Test Summary');
        console.log('=================================================');
        console.log(`Total Tests: ${this.tests.length}`);
        console.log(`Passed: ${this.passed}`);
        console.log(`Failed: ${this.failed}`);
        console.log(`Success Rate: ${((this.passed / this.tests.length) * 100).toFixed(2)}%`);
        console.log('=================================================');
    }

    // Security tests
    async testInputValidation() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test valid inputs
        assert.doesNotThrow(() => rawrz.validateInput('test', 'string'));
        assert.doesNotThrow(() => rawrz.validateInput(123, 'number'));
        
        // Test string length validation
        assert.doesNotThrow(() => rawrz.validateInput('short', 'string', { maxLength: 100 }));
        assert.throws(() => rawrz.validateInput('a'.repeat(1001), 'string', { maxLength: 1000 }), Error);
        
        // Test number range validation
        assert.doesNotThrow(() => rawrz.validateInput(50, 'number', { min: 0, max: 100 }));
        assert.throws(() => rawrz.validateInput(150, 'number', { max: 100 }), Error);
        assert.throws(() => rawrz.validateInput(-10, 'number', { min: 0 }), Error);
        
        // Test pattern validation
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        assert.doesNotThrow(() => rawrz.validateInput('test@example.com', 'string', { pattern: emailPattern }));
        assert.throws(() => rawrz.validateInput('invalid-email', 'string', { pattern: emailPattern }), Error);
    }

    async testSanitization() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test filename sanitization - removes dangerous characters
        const sanitizedFilename = rawrz.sanitizeInput('test<>:"|?*file.txt', 'filename');
        assert(!sanitizedFilename.includes('<'), 'Should remove <');
        assert(!sanitizedFilename.includes('>'), 'Should remove >');
        assert(!sanitizedFilename.includes(':'), 'Should remove :');
        assert(!sanitizedFilename.includes('"'), 'Should remove "');

        // Test path traversal prevention
        assert.throws(() => rawrz.sanitizeInput('../../../etc/passwd', 'path'), Error);
        assert.throws(() => rawrz.sanitizeInput('..\\..\\windows\\system32', 'path'), Error);

        // Test HTML sanitization
        const htmlInput = '<script>alert("xss")</script>';
        const sanitizedHtml = rawrz.sanitizeInput(htmlInput, 'html');
        assert(!sanitizedHtml.includes('<script>'), 'Should encode HTML');
        assert(sanitizedHtml.includes('&lt;'), 'Should use HTML entities');

        // Test command sanitization
        const cmdInput = 'test; rm -rf /';
        const sanitizedCmd = rawrz.sanitizeInput(cmdInput, 'command');
        assert(!sanitizedCmd.includes(';'), 'Should remove command separators');
        
        // Test null byte removal
        const nullByteInput = 'test\x00file.txt';
        const sanitizedNull = rawrz.sanitizeInput(nullByteInput, 'general');
        assert(!sanitizedNull.includes('\x00'), 'Should remove null bytes');
    }

    async testRateLimiting() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test rate limiting
        for (let i = 0; i < 5; i++) {
            assert.doesNotThrow(() => rawrz.checkRateLimit('test-client'));
        }

        // Test rate limit exceeded
        for (let i = 0; i < 100; i++) {
            rawrz.checkRateLimit('test-client');
        }
        assert.throws(() => rawrz.checkRateLimit('test-client'), Error);
    }

    async testCryptoSecurity() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test secure math evaluation - valid expressions
        assert.strictEqual(rawrz.safeMathEval('2 + 2'), 4, 'Simple addition');
        assert.strictEqual(rawrz.safeMathEval('10 * 5'), 50, 'Multiplication');
        assert.strictEqual(rawrz.safeMathEval('(2 + 3) * 4'), 20, 'Order of operations');
        assert.strictEqual(rawrz.safeMathEval('100 / 4'), 25, 'Division');
        assert.strictEqual(rawrz.safeMathEval('10 - 3'), 7, 'Subtraction');
        
        // Test invalid expressions - code injection attempts
        assert.throws(() => rawrz.safeMathEval('eval("malicious code")'), Error, 'Should block eval');
        assert.throws(() => rawrz.safeMathEval('process.exit()'), Error, 'Should block process');
        assert.throws(() => rawrz.safeMathEval('require("fs")'), Error, 'Should block require');
        assert.throws(() => rawrz.safeMathEval('__proto__'), Error, 'Should block proto');
        assert.throws(() => rawrz.safeMathEval('constructor'), Error, 'Should block constructor');
        assert.throws(() => rawrz.safeMathEval('function() {}'), Error, 'Should block function keyword');
        
        // Test invalid syntax
        assert.throws(() => rawrz.safeMathEval('2 +'), Error, 'Should reject incomplete expression');
        assert.throws(() => rawrz.safeMathEval('(2 + 3'), Error, 'Should reject unbalanced parentheses');
        assert.throws(() => rawrz.safeMathEval('2 + 3)'), Error, 'Should reject unbalanced parentheses');
        
        // Test invalid characters
        assert.throws(() => rawrz.safeMathEval('2 + abc'), Error, 'Should reject letters');
        assert.throws(() => rawrz.safeMathEval('2; alert(1)'), Error, 'Should reject semicolons');
        
        // Test length limit
        const longExpr = '1 + '.repeat(1000) + '1';
        assert.throws(() => rawrz.safeMathEval(longExpr), Error, 'Should reject too long expressions');
    }

    async testFileOperations() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test path validation - should reject directory traversal
        assert.throws(() => rawrz.validatePath('../../../etc/passwd'), Error, 'Should block path traversal');
        assert.throws(() => rawrz.validatePath('..\\..\\windows\\system32'), Error, 'Should block Windows path traversal');
        
        // Test file size validation
        assert.doesNotThrow(() => rawrz.validateFileSize(1024 * 1024, 10 * 1024 * 1024), 'Should accept 1MB file');
        assert.throws(() => rawrz.validateFileSize(101 * 1024 * 1024, 100 * 1024 * 1024), Error, 'Should reject >100MB file');
        
        // Test sanitized filename patterns
        const dangerousName = '../../../etc/passwd';
        const sanitized = rawrz.sanitizeInput(dangerousName, 'filename');
        assert(!sanitized.includes('..'), 'Sanitized filename should not contain ..');
        assert(!sanitized.includes('/'), 'Sanitized filename should not contain /');
    }

    async testErrorHandling() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test error sanitization
        const testError = new Error('File not found at C:\\Users\\admin\\secret\\file.txt');
        const sanitized = rawrz.sanitizeError(testError, 'file-operation');
        
        // Should not expose full paths
        assert(!sanitized.message.includes('C:\\Users'), 'Should redact Windows paths');
        assert(!sanitized.message.includes('admin'), 'Should redact sensitive info');
        
        // Test error with IP address
        const ipError = new Error('Connection failed to 192.168.1.100');
        const sanitizedIp = rawrz.sanitizeError(ipError, 'network');
        assert(!sanitizedIp.message.includes('192.168.1.100'), 'Should redact IP addresses');
        assert(sanitizedIp.message.includes('[ip]'), 'Should replace with placeholder');
        
        // Test secure logging
        const logResult = rawrz.logSecureError(new Error('Test error'), 'test-context');
        assert(logResult.timestamp, 'Should include timestamp');
        assert(logResult.context === 'test-context', 'Should include context');
        assert(logResult.message, 'Should include sanitized message');
    }

    async testMemoryLimits() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test file size limits
        const maxSize = 100 * 1024 * 1024; // 100MB
        const largeSize = 101 * 1024 * 1024; // 101MB
        
        assert.doesNotThrow(() => rawrz.validateFileSize(maxSize - 1, maxSize), 'Should accept file under limit');
        assert.throws(() => rawrz.validateFileSize(largeSize, maxSize), Error, 'Should reject file over limit');
        
        // Test empty/invalid input validation
        assert.throws(() => rawrz.validateInput('', 'string', { minLength: 1 }), Error, 'Should reject empty string with minLength');
    }

    async testSecurityMonitor() {
        const SecurityMonitor = require('./security-monitor.js');

        // Test security event logging
        const event = await SecurityMonitor.logSecurityEvent({
            type: 'authentication',
            severity: 'high',
            message: 'Failed login attempt',
            source: 'login-system'
        });

        assert(event.id);
        assert(event.timestamp);
        assert.strictEqual(event.severity, 'high');

        // Test audit event logging
        const auditEvent = await SecurityMonitor.logAuditEvent({
            action: 'file-access',
            resource: 'sensitive-file.txt',
            user: 'test-user',
            result: 'success'
        });

        assert(auditEvent.id);
        assert.strictEqual(auditEvent.action, 'file-access');
    }

    async testSystemHealth() {
        const SecurityMonitor = require('./security-monitor.js');
        const health = SecurityMonitor.getSystemHealth();

        assert(health.memory);
        assert(health.uptime >= 0);
        assert(health.health >= 0 && health.health <= 100);
    }
}

// Create and run test suite
async function runTests() {
    const testSuite = new TestSuite();

    // Add all tests
    testSuite.addTest('Input Validation', testSuite.testInputValidation);
    testSuite.addTest('Input Sanitization', testSuite.testSanitization);
    testSuite.addTest('Rate Limiting', testSuite.testRateLimiting);
    testSuite.addTest('Crypto Security', testSuite.testCryptoSecurity);
    testSuite.addTest('File Operations', testSuite.testFileOperations);
    testSuite.addTest('Error Handling', testSuite.testErrorHandling);
    testSuite.addTest('Memory Limits', testSuite.testMemoryLimits);
    testSuite.addTest('Security Monitor', testSuite.testSecurityMonitor);
    testSuite.addTest('System Health', testSuite.testSystemHealth);

    // Run tests
    await testSuite.runAllTests();
}

// Run if called directly
if (require.main === module) {
    runTests().catch(console.error);
}

module.exports = TestSuite;
