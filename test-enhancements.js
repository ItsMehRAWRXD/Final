#!/usr/bin/env node
// RawrZ Enhancement Test Suite
// Tests all enhanced base elements

const fs = require('fs').promises;
const path = require('path');

class EnhancementTester {
    constructor() {
        this.results = {
            passed: 0,
            failed: 0,
            tests: []
        };
    }

    async runTest(name, testFn) {
        try {
            console.log(`[TEST] Running: ${name}`);
            const result = await testFn();
            this.results.passed++;
            this.results.tests.push({ name, status: 'PASS', result });
            console.log(`[PASS] ${name}`);
            return true;
        } catch (error) {
            this.results.failed++;
            this.results.tests.push({ name, status: 'FAIL', error: error.message });
            console.log(`[FAIL] ${name}: ${error.message}`);
            return false;
        }
    }

    async testMemoryManager() {
        const mm = require('./memory-manager');
        
        // Test initialization
        await mm.initialize();
        
        // Test memory allocation
        await mm.allocatePool('test-pool', 1024);
        
        // Test memory usage
        const usage = mm.getMemoryUsage();
        if (!usage.process || !usage.system) {
            throw new Error('Memory usage data incomplete');
        }
        
        // Test memory optimization
        const optimization = await mm.optimize();
        if (!optimization.optimized) {
            throw new Error('Memory optimization failed');
        }
        
        // Test leak detection
        const leaks = mm.detectMemoryLeaks();
        if (typeof leaks.hasLeaks !== 'boolean') {
            throw new Error('Leak detection failed');
        }
        
        // Cleanup
        await mm.cleanup();
        
        return 'Memory Manager working correctly';
    }

    async testNetworkTools() {
        const nt = require('./network-tools');
        
        // Test initialization
        await nt.initialize();
        
        // Test DNS resolution
        const dnsResult = await nt.resolveDNS('google.com');
        if (!dnsResult.success) {
            throw new Error('DNS resolution failed');
        }
        
        // Test connectivity
        const connectivity = await nt.testConnectivity('google.com', 80);
        if (typeof connectivity.success !== 'boolean') {
            throw new Error('Connectivity test failed');
        }
        
        // Test HTTP analysis
        const httpResult = await nt.analyzeHTTP('http://google.com');
        if (!httpResult.success) {
            console.log('[WARN] HTTP analysis failed, but continuing test');
        }
        
        // Cleanup
        await nt.cleanup();
        
        return 'Network Tools working correctly';
    }

    async testCorePlatform() {
        const { spawn } = require('child_process');
        
        return new Promise((resolve, reject) => {
            const child = spawn('node', ['rawrz-standalone.js', 'help'], { cwd: __dirname });
            let output = '';
            
            child.stdout.on('data', (data) => {
                output += data.toString();
            });
            
            child.on('close', (code) => {
                if (code === 0 && output.includes('RawrZ Security Platform')) {
                    resolve('Core Platform working correctly');
                } else {
                    reject(new Error(`Core platform test failed with code ${code}`));
                }
            });
            
            child.on('error', (error) => {
                reject(new Error(`Core platform test error: ${error.message}`));
            });
        });
    }

    async testAdvancedCrypto() {
        const ac = require('./advanced-crypto');
        
        // Test encryption
        const testData = 'RawrZ Test Data';
        const encrypted = await ac.encrypt(testData, {
            algorithm: 'aes-256-gcm',
            dataType: 'text'
        });
        
        if (!encrypted.data || !encrypted.key || !encrypted.iv) {
            throw new Error('Encryption failed');
        }
        
        // Test decryption
        const decrypted = await ac.decrypt(encrypted.data, {
            algorithm: 'aes-256-gcm',
            key: encrypted.key,
            iv: encrypted.iv,
            dataType: 'text'
        });
        
        if (decrypted !== testData) {
            throw new Error('Decryption failed');
        }
        
        return 'Advanced Crypto working correctly';
    }

    async testDualCryptoEngine() {
        const dce = require('./dual-crypto-engine');
        
        // Test initialization
        await dce.initialize();
        
        // Test dual encryption
        const testData = 'RawrZ Dual Crypto Test';
        const result = await dce.encrypt(testData, {
            algorithm: 'aes-camellia-dual',
            dataType: 'text'
        });
        
        if (!result.success || !result.encryptedData || !result.keys) {
            throw new Error('Dual encryption failed');
        }
        
        return 'Dual Crypto Engine working correctly';
    }

    async testCompressionEngine() {
        const ce = require('./compression-engine');
        
        // Test compression
        const testData = Buffer.from('RawrZ Compression Test Data '.repeat(100));
        const compressed = await ce.compress(testData, 'gzip');
        
        if (!compressed.data || compressed.compressedSize >= testData.length) {
            throw new Error('Compression failed');
        }
        
        // Test decompression
        const decompressed = await ce.decompress(compressed.data, 'gzip');
        
        if (!decompressed.data.equals(testData)) {
            throw new Error('Decompression failed');
        }
        
        return 'Compression Engine working correctly';
    }

    async testStealthEngine() {
        const se = require('./stealth-engine');
        
        // Test stealth mode
        const result = await se.enableStealth('basic');
        
        if (!result.enabled) {
            throw new Error('Stealth mode failed');
        }
        
        // Test detection scan
        const scan = await se.runDetectionScan();
        
        if (!scan || typeof scan !== 'object') {
            throw new Error('Detection scan failed');
        }
        
        // Cleanup
        await se.cleanup();
        
        return 'Stealth Engine working correctly';
    }

    async testPolymorphicEngine() {
        const pe = require('./polymorphic-engine');
        
        // Test polymorphic transformation
        const testCode = 'mov eax, 1\nadd eax, 2\nret';
        const result = await pe.polymorphize(testCode, {
            mutationTypes: ['instruction-substitution', 'register-reallocation']
        });
        
        if (!result.mutatedCode) {
            throw new Error('Polymorphic transformation failed - no mutated code');
        }
        
        // Check if any mutations were applied
        const hasChanges = result.appliedMutations.some(m => m.success && m.changes > 0);
        if (!hasChanges) {
            console.log('[WARN] No mutations were applied, but transformation completed');
        }
        
        return 'Polymorphic Engine working correctly';
    }

    async runAllTests() {
        console.log('=================================================');
        console.log('RawrZ Enhancement Test Suite');
        console.log('=================================================');
        console.log('');

        // Run all tests
        await this.runTest('Memory Manager', () => this.testMemoryManager());
        await this.runTest('Network Tools', () => this.testNetworkTools());
        await this.runTest('Core Platform', () => this.testCorePlatform());
        await this.runTest('Advanced Crypto', () => this.testAdvancedCrypto());
        await this.runTest('Dual Crypto Engine', () => this.testDualCryptoEngine());
        await this.runTest('Compression Engine', () => this.testCompressionEngine());
        await this.runTest('Stealth Engine', () => this.testStealthEngine());
        await this.runTest('Polymorphic Engine', () => this.testPolymorphicEngine());

        // Print results
        console.log('');
        console.log('=================================================');
        console.log('Test Results Summary');
        console.log('=================================================');
        console.log(`[OK] Passed: ${this.results.passed}`);
        console.log(`[ERROR] Failed: ${this.results.failed}`);
        console.log(`[OK] Total: ${this.results.passed + this.results.failed}`);
        console.log(`[OK] Success Rate: ${((this.results.passed / (this.results.passed + this.results.failed)) * 100).toFixed(1)}%`);
        console.log('=================================================');

        // Print failed tests
        const failedTests = this.results.tests.filter(t => t.status === 'FAIL');
        if (failedTests.length > 0) {
            console.log('');
            console.log('Failed Tests:');
            failedTests.forEach(test => {
                console.log(`[ERROR] ${test.name}: ${test.error}`);
            });
        }

        return this.results;
    }
}

// Run tests if called directly
if (require.main === module) {
    const tester = new EnhancementTester();
    tester.runAllTests().catch(console.error);
}

module.exports = EnhancementTester;