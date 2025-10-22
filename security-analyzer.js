// RawrZ Security Analyzer - Advanced security analysis and threat detection
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const { logger } = require('./utils/logger');

class SecurityAnalyzer {
    constructor() {
        this.threats = {
            malware: {
                signatures: new Map(),
                heuristics: [],
                patterns: []
            },
            vulnerabilities: {
                cve: new Map(),
                exploits: [],
                patches: []
            },
            anomalies: {
                behavior: [],
                network: [],
                file: []
            }
        };
        
        this.scanResults = new Map();
        this.riskLevels = {
            LOW: 1,
            MEDIUM: 2,
            HIGH: 3,
            CRITICAL: 4
        };
        
        this.initialized = false;
    }

    async initialize(options = {}) {
        try {
            this.config = {
                scanDepth: options.scanDepth || 'deep',
                includeHeuristics: options.includeHeuristics !== false,
                includeBehavioral: options.includeBehavioral !== false,
                includeNetwork: options.includeNetwork !== false,
                realTimeMonitoring: options.realTimeMonitoring || false,
                ...options
            };

            // Load threat signatures
            await this.loadThreatSignatures();
            
            // Initialize heuristics
            this.initializeHeuristics();
            
            this.initialized = true;
            logger.info('Security Analyzer initialized', { 
                scanDepth: this.config.scanDepth,
                signatures: this.threats.malware.signatures.size
            });
            
            return { success: true, config: this.config };
        } catch (error) {
            logger.error('Security Analyzer initialization failed', { error: error.message });
            throw error;
        }
    }

    async loadThreatSignatures() {
        try {
            // Load common malware signatures
            const commonSignatures = [
                { name: 'Trojan.Generic', pattern: /trojan/i, risk: 'HIGH' },
                { name: 'Virus.Win32', pattern: /virus/i, risk: 'HIGH' },
                { name: 'Ransomware', pattern: /ransom/i, risk: 'CRITICAL' },
                { name: 'Keylogger', pattern: /keylog/i, risk: 'HIGH' },
                { name: 'Backdoor', pattern: /backdoor/i, risk: 'HIGH' },
                { name: 'Rootkit', pattern: /rootkit/i, risk: 'CRITICAL' },
                { name: 'Spyware', pattern: /spy/i, risk: 'MEDIUM' },
                { name: 'Adware', pattern: /adware/i, risk: 'LOW' }
            ];

            commonSignatures.forEach(sig => {
                this.threats.malware.signatures.set(sig.name, {
                    pattern: sig.pattern,
                    risk: sig.risk,
                    description: `Detected ${sig.name} signature`,
                    lastUpdated: new Date().toISOString()
                });
            });

            logger.info('Threat signatures loaded', { count: commonSignatures.length });
        } catch (error) {
            logger.error('Failed to load threat signatures', { error: error.message });
        }
    }

    initializeHeuristics() {
        this.threats.malware.heuristics = [
            {
                name: 'Suspicious File Extension',
                check: (filePath) => {
                    const suspiciousExts = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js'];
                    const ext = path.extname(filePath).toLowerCase();
                    return suspiciousExts.includes(ext);
                },
                risk: 'MEDIUM',
                description: 'File has suspicious extension'
            },
            {
                name: 'Large File Size',
                check: async (filePath) => {
                    try {
                        const stats = await fs.stat(filePath);
                        return stats.size > 100 * 1024 * 1024; // 100MB
                    } catch {
                        return false;
                    }
                },
                risk: 'LOW',
                description: 'File is unusually large'
            },
            {
                name: 'Hidden File',
                check: async (filePath) => {
                    try {
                        const stats = await fs.stat(filePath);
                        return stats.mode & 0o200000; // Hidden bit
                    } catch {
                        return false;
                    }
                },
                risk: 'MEDIUM',
                description: 'File is hidden'
            },
            {
                name: 'System Directory',
                check: (filePath) => {
                    const systemDirs = ['/system', '/windows/system32', '/usr/bin', '/bin'];
                    return systemDirs.some(dir => filePath.includes(dir));
                },
                risk: 'HIGH',
                description: 'File in system directory'
            }
        ];

        logger.info('Heuristics initialized', { count: this.threats.malware.heuristics.length });
    }

    async scanFile(filePath, options = {}) {
        try {
            const startTime = Date.now();
            const results = {
                filePath,
                timestamp: new Date().toISOString(),
                threats: [],
                riskScore: 0,
                status: 'clean',
                scanDuration: 0,
                fileInfo: {}
            };

            // Get file info
            try {
                const stats = await fs.stat(filePath);
                results.fileInfo = {
                    size: stats.size,
                    created: stats.birthtime,
                    modified: stats.mtime,
                    permissions: stats.mode.toString(8),
                    isFile: stats.isFile(),
                    isDirectory: stats.isDirectory()
                };
            } catch (error) {
                results.fileInfo.error = error.message;
            }

            // Read file content for analysis
            let content = '';
            try {
                content = await fs.readFile(filePath, 'utf8');
            } catch (error) {
                // File might be binary, try as buffer
                try {
                    const buffer = await fs.readFile(filePath);
                    content = buffer.toString('hex');
                } catch {
                    results.fileInfo.readError = 'Could not read file content';
                }
            }

            // Signature-based detection
            for (const [name, signature] of this.threats.malware.signatures) {
                if (signature.pattern.test(content)) {
                    results.threats.push({
                        type: 'signature',
                        name,
                        description: signature.description,
                        risk: signature.risk,
                        confidence: 0.9
                    });
                    results.riskScore += this.riskLevels[signature.risk];
                }
            }

            // Heuristic analysis
            if (this.config.includeHeuristics) {
                for (const heuristic of this.threats.malware.heuristics) {
                    try {
                        const detected = await heuristic.check(filePath);
                        if (detected) {
                            results.threats.push({
                                type: 'heuristic',
                                name: heuristic.name,
                                description: heuristic.description,
                                risk: heuristic.risk,
                                confidence: 0.7
                            });
                            results.riskScore += this.riskLevels[heuristic.risk];
                        }
                    } catch (error) {
                        logger.warn('Heuristic check failed', { heuristic: heuristic.name, error: error.message });
                    }
                }
            }

            // Behavioral analysis
            if (this.config.includeBehavioral) {
                const behavioralThreats = await this.analyzeBehavior(filePath, content);
                results.threats.push(...behavioralThreats);
                results.riskScore += behavioralThreats.reduce((sum, threat) => sum + this.riskLevels[threat.risk], 0);
            }

            // Determine overall status
            if (results.riskScore >= this.riskLevels.CRITICAL * 2) {
                results.status = 'critical';
            } else if (results.riskScore >= this.riskLevels.HIGH) {
                results.status = 'high_risk';
            } else if (results.riskScore >= this.riskLevels.MEDIUM) {
                results.status = 'medium_risk';
            } else if (results.riskScore > 0) {
                results.status = 'low_risk';
            } else {
                results.status = 'clean';
            }

            results.scanDuration = Date.now() - startTime;
            this.scanResults.set(filePath, results);

            logger.info('File scan completed', { 
                filePath, 
                status: results.status, 
                threats: results.threats.length,
                duration: results.scanDuration 
            });

            return results;
        } catch (error) {
            logger.error('File scan failed', { filePath, error: error.message });
            return {
                filePath,
                timestamp: new Date().toISOString(),
                threats: [],
                riskScore: 0,
                status: 'error',
                error: error.message,
                scanDuration: 0
            };
        }
    }

    async analyzeBehavior(filePath, content) {
        const threats = [];

        // Check for suspicious patterns
        const suspiciousPatterns = [
            { pattern: /eval\s*\(/i, name: 'Code Injection', risk: 'HIGH' },
            { pattern: /exec\s*\(/i, name: 'Command Execution', risk: 'HIGH' },
            { pattern: /system\s*\(/i, name: 'System Call', risk: 'MEDIUM' },
            { pattern: /shell_exec/i, name: 'Shell Execution', risk: 'HIGH' },
            { pattern: /base64_decode/i, name: 'Obfuscated Code', risk: 'MEDIUM' },
            { pattern: /str_rot13/i, name: 'Code Obfuscation', risk: 'LOW' },
            { pattern: /gzinflate/i, name: 'Compressed Code', risk: 'MEDIUM' },
            { pattern: /preg_replace.*\/e/i, name: 'Code Injection', risk: 'CRITICAL' }
        ];

        for (const { pattern, name, risk } of suspiciousPatterns) {
            if (pattern.test(content)) {
                threats.push({
                    type: 'behavioral',
                    name,
                    description: `Suspicious pattern detected: ${name}`,
                    risk,
                    confidence: 0.8
                });
            }
        }

        // Check for network-related suspicious activity
        const networkPatterns = [
            { pattern: /curl_exec/i, name: 'HTTP Request', risk: 'MEDIUM' },
            { pattern: /file_get_contents.*http/i, name: 'Remote File Access', risk: 'MEDIUM' },
            { pattern: /fsockopen/i, name: 'Socket Connection', risk: 'MEDIUM' },
            { pattern: /socket_create/i, name: 'Socket Creation', risk: 'MEDIUM' }
        ];

        for (const { pattern, name, risk } of networkPatterns) {
            if (pattern.test(content)) {
                threats.push({
                    type: 'behavioral',
                    name,
                    description: `Network activity detected: ${name}`,
                    risk,
                    confidence: 0.6
                });
            }
        }

        return threats;
    }

    async scanDirectory(dirPath, options = {}) {
        try {
            const results = {
                directory: dirPath,
                timestamp: new Date().toISOString(),
                files: [],
                summary: {
                    total: 0,
                    clean: 0,
                    low_risk: 0,
                    medium_risk: 0,
                    high_risk: 0,
                    critical: 0,
                    errors: 0
                },
                scanDuration: 0
            };

            const startTime = Date.now();
            const files = await this.getFilesRecursive(dirPath, options.maxDepth || 10);
            
            logger.info('Starting directory scan', { directory: dirPath, fileCount: files.length });

            // Scan files in parallel (with concurrency limit)
            const concurrency = options.concurrency || 5;
            const chunks = this.chunkArray(files, concurrency);
            
            for (const chunk of chunks) {
                const promises = chunk.map(file => this.scanFile(file, options));
                const chunkResults = await Promise.allSettled(promises);
                
                chunkResults.forEach((result, index) => {
                    if (result.status === 'fulfilled') {
                        results.files.push(result.value);
                        results.summary[result.value.status]++;
                    } else {
                        results.files.push({
                            filePath: chunk[index],
                            status: 'error',
                            error: result.reason.message,
                            timestamp: new Date().toISOString()
                        });
                        results.summary.errors++;
                    }
                });
            }

            results.summary.total = files.length;
            results.scanDuration = Date.now() - startTime;

            logger.info('Directory scan completed', { 
                directory: dirPath, 
                total: results.summary.total,
                duration: results.scanDuration,
                summary: results.summary
            });

            return results;
        } catch (error) {
            logger.error('Directory scan failed', { directory: dirPath, error: error.message });
            return {
                directory: dirPath,
                timestamp: new Date().toISOString(),
                files: [],
                summary: { total: 0, errors: 1 },
                error: error.message,
                scanDuration: 0
            };
        }
    }

    async getFilesRecursive(dirPath, maxDepth = 10, currentDepth = 0) {
        if (currentDepth >= maxDepth) return [];

        try {
            const files = [];
            const entries = await fs.readdir(dirPath, { withFileTypes: true });

            for (const entry of entries) {
                const fullPath = path.join(dirPath, entry.name);
                
                if (entry.isDirectory()) {
                    const subFiles = await this.getFilesRecursive(fullPath, maxDepth, currentDepth + 1);
                    files.push(...subFiles);
                } else if (entry.isFile()) {
                    files.push(fullPath);
                }
            }

            return files;
        } catch (error) {
            logger.warn('Failed to read directory', { dirPath, error: error.message });
            return [];
        }
    }

    chunkArray(array, size) {
        const chunks = [];
        for (let i = 0; i < array.length; i += size) {
            chunks.push(array.slice(i, i + size));
        }
        return chunks;
    }

    async analyzeNetworkTraffic(trafficData) {
        try {
            const threats = [];

            // Analyze for suspicious network patterns
            const suspiciousPatterns = [
                { pattern: /botnet/i, name: 'Botnet Communication', risk: 'CRITICAL' },
                { pattern: /c2/i, name: 'Command & Control', risk: 'CRITICAL' },
                { pattern: /exfiltration/i, name: 'Data Exfiltration', risk: 'HIGH' },
                { pattern: /lateral/i, name: 'Lateral Movement', risk: 'HIGH' },
                { pattern: /persistence/i, name: 'Persistence Mechanism', risk: 'MEDIUM' }
            ];

            for (const { pattern, name, risk } of suspiciousPatterns) {
                if (pattern.test(JSON.stringify(trafficData))) {
                    threats.push({
                        type: 'network',
                        name,
                        description: `Suspicious network activity: ${name}`,
                        risk,
                        confidence: 0.8
                    });
                }
            }

            return threats;
        } catch (error) {
            logger.error('Network analysis failed', { error: error.message });
            return [];
        }
    }

    getThreatSummary() {
        const summary = {
            totalScans: this.scanResults.size,
            clean: 0,
            low_risk: 0,
            medium_risk: 0,
            high_risk: 0,
            critical: 0,
            errors: 0,
            threatTypes: new Map(),
            topThreats: []
        };

        for (const result of this.scanResults.values()) {
            summary[result.status]++;
            
            result.threats.forEach(threat => {
                const count = summary.threatTypes.get(threat.name) || 0;
                summary.threatTypes.set(threat.name, count + 1);
            });
        }

        // Get top threats
        summary.topThreats = Array.from(summary.threatTypes.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([name, count]) => ({ name, count }));

        return summary;
    }

    async generateReport(format = 'json') {
        try {
            const report = {
                timestamp: new Date().toISOString(),
                summary: this.getThreatSummary(),
                recentScans: Array.from(this.scanResults.values()).slice(-10),
                recommendations: this.getRecommendations(),
                config: this.config
            };

            if (format === 'json') {
                const filename = `security-report-${Date.now()}.json`;
                await fs.writeFile(filename, JSON.stringify(report, null, 2));
                return { success: true, filename, format };
            } else if (format === 'html') {
                const html = this.generateHTMLReport(report);
                const filename = `security-report-${Date.now()}.html`;
                await fs.writeFile(filename, html);
                return { success: true, filename, format };
            } else {
                throw new Error(`Unsupported format: ${format}`);
            }
        } catch (error) {
            logger.error('Report generation failed', { error: error.message });
            return { success: false, error: error.message };
        }
    }

    generateHTMLReport(report) {
        return `
<!DOCTYPE html>
<html>
<head>
    <title>RawrZ Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .threat { margin: 10px 0; padding: 10px; border-left: 4px solid #ff0000; background: #ffe6e6; }
        .clean { border-left-color: #00ff00; background: #e6ffe6; }
        .low { border-left-color: #ffff00; background: #ffffe6; }
        .medium { border-left-color: #ff8800; background: #fff0e6; }
        .high { border-left-color: #ff4400; background: #ffe6e6; }
        .critical { border-left-color: #ff0000; background: #ffe6e6; }
    </style>
</head>
<body>
    <div class="header">
        <h1>RawrZ Security Analysis Report</h1>
        <p>Generated: ${report.timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Scans: ${report.summary.totalScans}</p>
        <p>Clean: ${report.summary.clean}</p>
        <p>Low Risk: ${report.summary.low_risk}</p>
        <p>Medium Risk: ${report.summary.medium_risk}</p>
        <p>High Risk: ${report.summary.high_risk}</p>
        <p>Critical: ${report.summary.critical}</p>
    </div>
    
    <div>
        <h2>Top Threats</h2>
        <ul>
            ${report.summary.topThreats.map(threat => `<li>${threat.name}: ${threat.count} occurrences</li>`).join('')}
        </ul>
    </div>
    
    <div>
        <h2>Recent Scans</h2>
        ${report.recentScans.map(scan => `
            <div class="threat ${scan.status}">
                <strong>${scan.filePath}</strong> - ${scan.status.toUpperCase()}
                ${scan.threats.length > 0 ? `<br>Threats: ${scan.threats.map(t => t.name).join(', ')}` : ''}
            </div>
        `).join('')}
    </div>
</body>
</html>`;
    }

    getRecommendations() {
        const recommendations = [];
        const summary = this.getThreatSummary();

        if (summary.critical > 0) {
            recommendations.push('Immediate action required: Critical threats detected');
        }
        if (summary.high_risk > 0) {
            recommendations.push('High priority: Review and address high-risk threats');
        }
        if (summary.medium_risk > 0) {
            recommendations.push('Medium priority: Monitor medium-risk threats');
        }
        if (summary.totalScans === 0) {
            recommendations.push('No scans performed yet - run security analysis');
        }

        return recommendations;
    }

    async cleanup() {
        try {
            this.scanResults.clear();
            this.threats.malware.signatures.clear();
            this.threats.malware.heuristics = [];
            this.initialized = false;
            
            logger.info('Security Analyzer cleanup completed');
            return { success: true };
        } catch (error) {
            logger.error('Security Analyzer cleanup failed', { error: error.message });
            return { success: false, error: error.message };
        }
    }
}

module.exports = new SecurityAnalyzer();