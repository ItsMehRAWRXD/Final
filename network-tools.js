// RawrZ Network Tools - Network analysis and security tools
const net = require('net');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const { URL } = require('url');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

class NetworkTools {
    constructor() {
        this.protocols = ['tcp', 'udp', 'http', 'https', 'dns', 'ftp', 'smtp', 'pop3', 'imap'];
        this.commonPorts = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            3389: 'RDP',
            5432: 'PostgreSQL',
            3306: 'MySQL',
            1433: 'MSSQL',
            6379: 'Redis',
            27017: 'MongoDB'
        };
        
        this.scanResults = new Map();
        this.initialized = false;
    }

    async initialize(config = {}) {
        try {
            this.config = {
                timeout: config.timeout || 5000,
                maxConcurrent: config.maxConcurrent || 100,
                retries: config.retries || 3,
                userAgent: config.userAgent || 'RawrZ-NetworkTools/1.0',
                ...config
            };
            
            this.initialized = true;
            console.log('[OK] Network Tools initialized');
            return { success: true, config: this.config };
        } catch (error) {
            console.error('[ERROR] Network Tools initialization failed:', error.message);
            throw error;
        }
    }

    // Port scanning
    async scanPorts(target, ports = null, options = {}) {
        try {
            const startTime = Date.now();
            const portsToScan = ports || Object.keys(this.commonPorts).map(Number);
            const results = {
                target,
                openPorts: [],
                closedPorts: [],
                filteredPorts: [],
                errors: []
            };

            console.log(`[OK] Scanning ${target} ports ${Math.min(...portsToScan)}-${Math.max(...portsToScan)}...`);

            // Scan ports in batches
            const batchSize = this.config.maxConcurrent;
            for (let i = 0; i < portsToScan.length; i += batchSize) {
                const batch = portsToScan.slice(i, i + batchSize);
                const batchPromises = batch.map(port => this.scanPort(target, port, options));
                const batchResults = await Promise.allSettled(batchPromises);
                
                batchResults.forEach((result, index) => {
                    const port = batch[index];
                    if (result.status === 'fulfilled') {
                        if (result.value.open) {
                            results.openPorts.push({
                                port,
                                service: this.commonPorts[port] || 'Unknown',
                                banner: result.value.banner,
                                responseTime: result.value.responseTime
                            });
                        } else {
                            results.closedPorts.push(port);
                        }
                    } else {
                        results.errors.push({
                            port,
                            error: result.reason.message
                        });
                    }
                });
            }

            const duration = Date.now() - startTime;
            console.log(`[OK] Port scan completed: ${results.openPorts.length} open ports found in ${duration}ms`);
            
            return {
                success: true,
                ...results,
                duration,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            console.error('[ERROR] Port scanning failed:', error.message);
            return { success: false, error: error.message };
        }
    }

    // Scan individual port
    async scanPort(target, port, options = {}) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            const timeout = options.timeout || this.config.timeout;
            const startTime = Date.now();
            
            socket.setTimeout(timeout);
            
            socket.on('connect', () => {
                const responseTime = Date.now() - startTime;
                socket.destroy();
                resolve({
                    open: true,
                    port,
                    responseTime,
                    banner: null
                });
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve({ open: false, port, reason: 'timeout' });
            });
            
            socket.on('error', (err) => {
                socket.destroy();
                resolve({ open: false, port, reason: err.code });
            });
            
            socket.connect(port, target);
        });
    }

    // DNS resolution
    async resolveDNS(hostname, recordType = 'A') {
        try {
            console.log(`[OK] Resolving DNS ${recordType} record for ${hostname}...`);
            
            const results = await dns.resolve(hostname, recordType);
            const addresses = Array.isArray(results) ? results : [results];
            
            console.log(`[OK] DNS resolution successful: ${addresses.length} ${recordType} records found`);
            
            return {
                success: true,
                hostname,
                recordType,
                addresses,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            console.error(`[ERROR] DNS resolution failed for ${hostname}:`, error.message);
            return { success: false, hostname, recordType, error: error.message };
        }
    }

    // HTTP/HTTPS analysis
    async analyzeHTTP(url, options = {}) {
        try {
            const parsedUrl = new URL(url);
            const isHttps = parsedUrl.protocol === 'https:';
            const client = isHttps ? https : http;
            
            console.log(`[OK] Analyzing HTTP${isHttps ? 'S' : ''} resource: ${url}`);
            
            const requestOptions = {
                hostname: parsedUrl.hostname,
                port: parsedUrl.port || (isHttps ? 443 : 80),
                path: parsedUrl.pathname + parsedUrl.search,
                method: options.method || 'GET',
                headers: {
                    'User-Agent': this.config.userAgent,
                    ...options.headers
                },
                timeout: options.timeout || this.config.timeout
            };
            
            return new Promise((resolve) => {
                const startTime = Date.now();
                const req = client.request(requestOptions, (res) => {
                    const responseTime = Date.now() - startTime;
                    let data = '';
                    
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        resolve({
                            success: true,
                            url,
                            statusCode: res.statusCode,
                            headers: res.headers,
                            responseTime,
                            contentLength: data.length,
                            security: this.analyzeSecurityHeaders(res.headers),
                            timestamp: new Date().toISOString()
                        });
                    });
                });
                
                req.on('error', (error) => {
                    resolve({
                        success: false,
                        url,
                        error: error.message,
                        timestamp: new Date().toISOString()
                    });
                });
                
                req.on('timeout', () => {
                    req.destroy();
                    resolve({
                        success: false,
                        url,
                        error: 'Request timeout',
                        timestamp: new Date().toISOString()
                    });
                });
                
                req.end();
            });
        } catch (error) {
            console.error(`[ERROR] HTTP analysis failed for ${url}:`, error.message);
            return { success: false, url, error: error.message };
        }
    }

    // Analyze security headers
    analyzeSecurityHeaders(headers) {
        const securityHeaders = {
            'Strict-Transport-Security': headers['strict-transport-security'],
            'X-Content-Type-Options': headers['x-content-type-options'],
            'X-Frame-Options': headers['x-frame-options'],
            'X-XSS-Protection': headers['x-xss-protection'],
            'Content-Security-Policy': headers['content-security-policy'],
            'Referrer-Policy': headers['referrer-policy']
        };
        
        const present = Object.values(securityHeaders).filter(Boolean).length;
        const total = Object.keys(securityHeaders).length;
        
        return {
            score: Math.round((present / total) * 100),
            headers: securityHeaders,
            recommendations: this.getSecurityRecommendations(securityHeaders)
        };
    }

    // Get security recommendations
    getSecurityRecommendations(headers) {
        const recommendations = [];
        
        if (!headers['Strict-Transport-Security']) {
            recommendations.push('Add Strict-Transport-Security header for HTTPS');
        }
        if (!headers['X-Content-Type-Options']) {
            recommendations.push('Add X-Content-Type-Options: nosniff header');
        }
        if (!headers['X-Frame-Options']) {
            recommendations.push('Add X-Frame-Options header to prevent clickjacking');
        }
        if (!headers['Content-Security-Policy']) {
            recommendations.push('Add Content-Security-Policy header');
        }
        
        return recommendations;
    }

    // Network connectivity test
    async testConnectivity(target, port = null) {
        try {
            console.log(`[OK] Testing connectivity to ${target}${port ? `:${port}` : ''}...`);
            
            if (port) {
                const result = await this.scanPort(target, port);
                return {
                    success: result.open,
                    target,
                    port,
                    responseTime: result.responseTime,
                    timestamp: new Date().toISOString()
                };
            } else {
                // Test common ports
                const commonPorts = [80, 443, 22, 21, 25];
                const results = [];
                
                for (const testPort of commonPorts) {
                    const result = await this.scanPort(target, testPort);
                    results.push({
                        port: testPort,
                        open: result.open,
                        responseTime: result.responseTime
                    });
                }
                
                const openPorts = results.filter(r => r.open).length;
                
                return {
                    success: openPorts > 0,
                    target,
                    results,
                    openPorts,
                    timestamp: new Date().toISOString()
                };
            }
        } catch (error) {
            console.error(`[ERROR] Connectivity test failed for ${target}:`, error.message);
            return { success: false, target, error: error.message };
        }
    }

    // Traceroute
    async traceroute(target, maxHops = 30) {
        try {
            console.log(`[OK] Tracing route to ${target}...`);
            
            const { stdout } = await execAsync(`traceroute -m ${maxHops} ${target}`);
            
            return {
                success: true,
                target,
                hops: this.parseTracerouteOutput(stdout),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            console.error(`[ERROR] Traceroute failed for ${target}:`, error.message);
            return { success: false, target, error: error.message };
        }
    }

    // Parse traceroute output
    parseTracerouteOutput(output) {
        const lines = output.split('\n');
        const hops = [];
        
        for (const line of lines) {
            const match = line.match(/^\s*(\d+)\s+(.+?)\s+\((.+?)\)\s+(.+)/);
            if (match) {
                hops.push({
                    hop: parseInt(match[1]),
                    hostname: match[2],
                    ip: match[3],
                    times: match[4].split(/\s+/).map(t => t.replace('ms', '')).filter(t => t !== '*')
                });
            }
        }
        
        return hops;
    }

    // Comprehensive network analysis
    async analyze(target, options = {}) {
        try {
            console.log(`[OK] Starting comprehensive network analysis for ${target}...`);
            
            const results = {
                target,
                timestamp: new Date().toISOString(),
                dns: null,
                ports: null,
                http: null,
                connectivity: null,
                traceroute: null
            };
            
            // DNS resolution
            if (options.dns !== false) {
                results.dns = await this.resolveDNS(target);
            }
            
            // Port scanning
            if (options.ports !== false) {
                results.ports = await this.scanPorts(target, options.portRange);
            }
            
            // HTTP analysis
            if (options.http !== false) {
                const protocol = options.https ? 'https' : 'http';
                results.http = await this.analyzeHTTP(`${protocol}://${target}`);
            }
            
            // Connectivity test
            if (options.connectivity !== false) {
                results.connectivity = await this.testConnectivity(target);
            }
            
            // Traceroute
            if (options.traceroute !== false) {
                results.traceroute = await this.traceroute(target);
            }
            
            console.log(`[OK] Network analysis completed for ${target}`);
            return { success: true, ...results };
        } catch (error) {
            console.error(`[ERROR] Network analysis failed for ${target}:`, error.message);
            return { success: false, target, error: error.message };
        }
    }

    // Get network statistics
    getStats() {
        return {
            initialized: this.initialized,
            protocols: this.protocols,
            commonPorts: Object.keys(this.commonPorts).length,
            scanResults: this.scanResults.size,
            config: this.config
        };
    }

    // Cleanup
    async cleanup() {
        try {
            this.scanResults.clear();
            console.log('[OK] Network Tools cleanup completed');
            return { success: true };
        } catch (error) {
            console.error('[ERROR] Network Tools cleanup failed:', error.message);
            return { success: false, error: error.message };
        }
    }
}

module.exports = new NetworkTools();
