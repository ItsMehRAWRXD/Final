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
        assert.doesNotThrow(() => rawrz.validateInput('aes256', 'algorithm'));

        // Test invalid inputs
        assert.throws(() => rawrz.validateInput(null, 'string'), Error);
        assert.throws(() => rawrz.validateInput('invalid', 'algorithm'), Error);
        assert.throws(() => rawrz.validateInput('a' * 10001, 'string', { maxLength: 10000 }), Error);
    }

    async testSanitization() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test filename sanitization
        const sanitized = rawrz.sanitizeInput('test<>:"/\\|?*file.txt', 'filename');
        assert(!sanitized.includes('<'));
        assert(!sanitized.includes('>'));
        assert(!sanitized.includes(':'));

        // Test path sanitization
        const sanitizedPath = rawrz.sanitizeInput('../../../etc/passwd', 'path');
        assert(!sanitizedPath.includes('..'));
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

        // Test secure math evaluation
        assert.strictEqual(rawrz.safeMathEval('2 + 2'), 4);
        assert.strictEqual(rawrz.safeMathEval('10 * 5'), 50);
        
        // Test invalid expressions
        assert.throws(() => rawrz.safeMathEval('eval("malicious code")'), Error);
        assert.throws(() => rawrz.safeMathEval('process.exit()'), Error);
    }

    async testFileOperations() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test path traversal prevention
        assert.throws(() => rawrz.readAbsoluteFile('../../../etc/passwd'), Error);
        assert.throws(() => rawrz.readAbsoluteFile('~/sensitive-file'), Error);
    }

    async testErrorHandling() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test that errors don't expose sensitive information
        try {
            await rawrz.encrypt('invalid-algorithm', 'test-data');
        } catch (error) {
            assert(!error.message.includes('internal'));
            assert(!error.message.includes('stack'));
        }
    }

    async testMemoryLimits() {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test large data handling
        const largeData = 'x'.repeat(101 * 1024 * 1024); // 101MB
        assert.throws(() => rawrz.performEncryption(largeData, 'aes256'), Error);
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
