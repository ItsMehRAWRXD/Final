/**
 * Simple Security Test for RawrZ Platform
 * Tests the key security enhancements
 */

const assert = require('assert');

async function runSecurityTests() {
    console.log('=================================================');
    console.log('RawrZ Security Platform - Security Tests');
    console.log('=================================================\n');

    let passed = 0;
    let failed = 0;

    // Test 1: Safe Math Evaluation
    try {
        const RawrZStandalone = require('./rawrz-standalone.js');
        const rawrz = new RawrZStandalone();

        // Test valid math expressions
        assert.strictEqual(rawrz.safeMathEval('2 + 2'), 4);
        assert.strictEqual(rawrz.safeMathEval('10 * 5'), 50);
        
        // Test dangerous expressions (should throw errors)
        assert.throws(() => rawrz.safeMathEval('eval("malicious code")'), Error);
        assert.throws(() => rawrz.safeMathEval('process.exit()'), Error);
        assert.throws(() => rawrz.safeMathEval('require("fs")'), Error);
        
        console.log('[PASS] Safe Math Evaluation');
        passed++;
    } catch (error) {
        console.log(`[FAIL] Safe Math Evaluation: ${error.message}`);
        failed++;
    }

    // Test 2: Input Validation
    try {
        const InputValidator = require('./input-validator.js');
        const validator = new InputValidator();

        // Test math expression validation
        assert.strictEqual(validator.validate('2 + 2', 'mathExpression'), '2 + 2');
        assert.throws(() => validator.validate('eval("test")', 'mathExpression'), Error);
        assert.throws(() => validator.validate('process.exit()', 'mathExpression'), Error);

        // Test filename validation
        assert.strictEqual(validator.validate('test.txt', 'filename'), 'test.txt');
        assert.throws(() => validator.validate('test<>.txt', 'filename'), Error);

        console.log('[PASS] Input Validation');
        passed++;
    } catch (error) {
        console.log(`[FAIL] Input Validation: ${error.message}`);
        failed++;
    }

    // Test 3: Error Handling
    try {
        const ErrorHandler = require('./error-handler.js');
        const errorHandler = new ErrorHandler();

        // Test error sanitization
        const error = new Error('File not found: /sensitive/path/file.txt');
        error.code = 'ENOENT';
        
        const result = errorHandler.handleError(error, { operation: 'file_read' });
        assert.strictEqual(result.success, false);
        assert.strictEqual(result.error.message, 'File or directory not found');
        assert.strictEqual(result.error.code, 'ENOENT');

        console.log('[PASS] Error Handling');
        passed++;
    } catch (error) {
        console.log(`[FAIL] Error Handling: ${error.message}`);
        failed++;
    }

    // Test 4: Crypto Security
    try {
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

        console.log('[PASS] Crypto Security');
        passed++;
    } catch (error) {
        console.log(`[FAIL] Crypto Security: ${error.message}`);
        failed++;
    }

    // Test 5: Security Utils
    try {
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

        console.log('[PASS] Security Utils');
        passed++;
    } catch (error) {
        console.log(`[FAIL] Security Utils: ${error.message}`);
        failed++;
    }

    console.log('\n=================================================');
    console.log('Security Test Summary');
    console.log('=================================================');
    console.log(`Total Tests: ${passed + failed}`);
    console.log(`Passed: ${passed}`);
    console.log(`Failed: ${failed}`);
    console.log(`Success Rate: ${((passed / (passed + failed)) * 100).toFixed(2)}%`);
    console.log('=================================================');

    if (failed === 0) {
        console.log('\n✅ All security tests passed! The platform is secure.');
    } else {
        console.log('\n❌ Some security tests failed. Please review the issues.');
    }
}

// Run tests
runSecurityTests().catch(console.error);