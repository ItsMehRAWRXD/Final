// RawrZ Performance Monitor - Advanced performance monitoring and optimization
const os = require('os');
const fs = require('fs').promises;
const { logger } = require('./utils/logger');

class PerformanceMonitor {
    constructor() {
        this.metrics = {
            cpu: {
                usage: 0,
                loadAverage: [0, 0, 0],
                cores: os.cpus().length,
                model: os.cpus()[0].model
            },
            memory: {
                total: os.totalmem(),
                free: os.freemem(),
                used: 0,
                percentage: 0
            },
            system: {
                uptime: 0,
                platform: os.platform(),
                arch: os.arch(),
                nodeVersion: process.version
            },
            processes: {
                pid: process.pid,
                ppid: process.ppid,
                memoryUsage: {},
                cpuUsage: {}
            },
            network: {
                interfaces: {},
                connections: 0
            },
            disk: {
                total: 0,
                free: 0,
                used: 0,
                percentage: 0
            }
        };
        
        this.history = [];
        this.alerts = [];
        this.thresholds = {
            cpu: 80,        // 80% CPU usage
            memory: 85,     // 85% memory usage
            disk: 90        // 90% disk usage
        };
        
        this.monitoring = false;
        this.interval = null;
        this.maxHistory = 1000;
    }

    async initialize(options = {}) {
        try {
            this.config = {
                interval: options.interval || 5000,  // 5 seconds
                maxHistory: options.maxHistory || this.maxHistory,
                thresholds: { ...this.thresholds, ...options.thresholds },
                enableAlerts: options.enableAlerts !== false,
                enableLogging: options.enableLogging !== false,
                ...options
            };

            // Initial system scan
            await this.updateMetrics();
            
            this.initialized = true;
            logger.info('Performance Monitor initialized', { 
                interval: this.config.interval,
                thresholds: this.config.thresholds 
            });
            
            return { success: true, config: this.config };
        } catch (error) {
            logger.error('Performance Monitor initialization failed', { error: error.message });
            throw error;
        }
    }

    async updateMetrics() {
        try {
            const startTime = Date.now();
            
            // CPU metrics
            const cpuUsage = await this.getCPUUsage();
            this.metrics.cpu.usage = cpuUsage;
            this.metrics.cpu.loadAverage = os.loadavg();

            // Memory metrics
            const memUsage = process.memoryUsage();
            this.metrics.memory.used = memUsage.heapUsed;
            this.metrics.memory.free = os.freemem();
            this.metrics.memory.percentage = (this.metrics.memory.used / this.metrics.memory.total) * 100;

            // System metrics
            this.metrics.system.uptime = os.uptime();
            this.metrics.processes.memoryUsage = memUsage;
            this.metrics.processes.cpuUsage = process.cpuUsage();

            // Network metrics
            this.metrics.network.interfaces = os.networkInterfaces();

            // Disk metrics
            const diskUsage = await this.getDiskUsage();
            this.metrics.disk = diskUsage;

            // Add to history
            const timestamp = new Date().toISOString();
            this.history.push({
                timestamp,
                metrics: JSON.parse(JSON.stringify(this.metrics)),
                duration: Date.now() - startTime
            });

            // Keep history within limits
            if (this.history.length > this.config.maxHistory) {
                this.history = this.history.slice(-this.config.maxHistory);
            }

            // Check for alerts
            if (this.config.enableAlerts) {
                await this.checkAlerts();
            }

            logger.debug('Metrics updated', { 
                duration: Date.now() - startTime,
                cpuUsage: this.metrics.cpu.usage,
                memoryUsage: this.metrics.memory.percentage
            });

            return this.metrics;
        } catch (error) {
            logger.error('Failed to update metrics', { error: error.message });
            throw error;
        }
    }

    async getCPUUsage() {
        return new Promise((resolve) => {
            const startUsage = process.cpuUsage();
            const startTime = Date.now();
            
            setTimeout(() => {
                const endUsage = process.cpuUsage(startUsage);
                const endTime = Date.now();
                
                const userTime = endUsage.user / 1000000; // Convert to seconds
                const systemTime = endUsage.system / 1000000;
                const totalTime = (endTime - startTime) / 1000;
                
                const cpuUsage = ((userTime + systemTime) / totalTime) * 100;
                resolve(Math.min(100, Math.max(0, cpuUsage)));
            }, 100);
        });
    }

    async getDiskUsage() {
        try {
            const { exec } = require('child_process');
            const { promisify } = require('util');
            const execAsync = promisify(exec);

            let diskInfo;
            if (os.platform() === 'win32') {
                const { stdout } = await execAsync('wmic logicaldisk get size,freespace,caption');
                const lines = stdout.split('\n').filter(line => line.trim());
                const diskLine = lines.find(line => line.includes('C:'));
                if (diskLine) {
                    const parts = diskLine.trim().split(/\s+/);
                    const free = parseInt(parts[1]) || 0;
                    const total = parseInt(parts[0]) || 0;
                    const used = total - free;
                    const percentage = total > 0 ? (used / total) * 100 : 0;
                    
                    diskInfo = { total, free, used, percentage };
                }
            } else {
                const { stdout } = await execAsync('df -h /');
                const lines = stdout.split('\n');
                const diskLine = lines[1];
                if (diskLine) {
                    const parts = diskLine.split(/\s+/);
                    const total = this.parseSize(parts[1]);
                    const used = this.parseSize(parts[2]);
                    const free = this.parseSize(parts[3]);
                    const percentage = parseFloat(parts[4]) || 0;
                    
                    diskInfo = { total, free, used, percentage };
                }
            }

            return diskInfo || { total: 0, free: 0, used: 0, percentage: 0 };
        } catch (error) {
            logger.warn('Failed to get disk usage', { error: error.message });
            return { total: 0, free: 0, used: 0, percentage: 0 };
        }
    }

    parseSize(sizeStr) {
        const units = { K: 1024, M: 1024**2, G: 1024**3, T: 1024**4 };
        const match = sizeStr.match(/^(\d+(?:\.\d+)?)([KMGT]?)$/);
        if (match) {
            const value = parseFloat(match[1]);
            const unit = match[2] || '';
            return Math.floor(value * (units[unit] || 1));
        }
        return 0;
    }

    async checkAlerts() {
        const alerts = [];

        // CPU alert
        if (this.metrics.cpu.usage > this.config.thresholds.cpu) {
            alerts.push({
                type: 'cpu',
                level: 'warning',
                message: `High CPU usage: ${this.metrics.cpu.usage.toFixed(1)}%`,
                value: this.metrics.cpu.usage,
                threshold: this.config.thresholds.cpu,
                timestamp: new Date().toISOString()
            });
        }

        // Memory alert
        if (this.metrics.memory.percentage > this.config.thresholds.memory) {
            alerts.push({
                type: 'memory',
                level: 'warning',
                message: `High memory usage: ${this.metrics.memory.percentage.toFixed(1)}%`,
                value: this.metrics.memory.percentage,
                threshold: this.config.thresholds.memory,
                timestamp: new Date().toISOString()
            });
        }

        // Disk alert
        if (this.metrics.disk.percentage > this.config.thresholds.disk) {
            alerts.push({
                type: 'disk',
                level: 'warning',
                message: `High disk usage: ${this.metrics.disk.percentage.toFixed(1)}%`,
                value: this.metrics.disk.percentage,
                threshold: this.config.thresholds.disk,
                timestamp: new Date().toISOString()
            });
        }

        // Add new alerts
        this.alerts.push(...alerts);

        // Log alerts
        if (alerts.length > 0 && this.config.enableLogging) {
            alerts.forEach(alert => {
                logger.warn('Performance alert', alert);
            });
        }

        return alerts;
    }

    startMonitoring() {
        if (this.monitoring) {
            logger.warn('Performance monitoring already started');
            return;
        }

        this.monitoring = true;
        this.interval = setInterval(async () => {
            try {
                await this.updateMetrics();
            } catch (error) {
                logger.error('Monitoring error', { error: error.message });
            }
        }, this.config.interval);

        logger.info('Performance monitoring started', { interval: this.config.interval });
    }

    stopMonitoring() {
        if (!this.monitoring) {
            logger.warn('Performance monitoring not started');
            return;
        }

        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }

        this.monitoring = false;
        logger.info('Performance monitoring stopped');
    }

    getMetrics() {
        return {
            current: this.metrics,
            history: this.history.slice(-10), // Last 10 entries
            alerts: this.alerts.slice(-20),   // Last 20 alerts
            monitoring: this.monitoring,
            config: this.config
        };
    }

    getPerformanceReport() {
        const recentHistory = this.history.slice(-10);
        const avgCpu = recentHistory.reduce((sum, entry) => sum + entry.metrics.cpu.usage, 0) / recentHistory.length;
        const avgMemory = recentHistory.reduce((sum, entry) => sum + entry.metrics.memory.percentage, 0) / recentHistory.length;
        const avgDisk = recentHistory.reduce((sum, entry) => sum + entry.metrics.disk.percentage, 0) / recentHistory.length;

        return {
            summary: {
                avgCpuUsage: avgCpu.toFixed(2),
                avgMemoryUsage: avgMemory.toFixed(2),
                avgDiskUsage: avgDisk.toFixed(2),
                totalAlerts: this.alerts.length,
                monitoringDuration: this.monitoring ? Date.now() - this.history[0]?.timestamp : 0
            },
            current: this.metrics,
            recommendations: this.getRecommendations()
        };
    }

    getRecommendations() {
        const recommendations = [];
        const current = this.metrics;

        if (current.cpu.usage > 70) {
            recommendations.push('Consider optimizing CPU-intensive operations');
        }
        if (current.memory.percentage > 70) {
            recommendations.push('Consider implementing memory optimization or increasing available memory');
        }
        if (current.disk.percentage > 80) {
            recommendations.push('Consider cleaning up disk space or expanding storage');
        }
        if (current.cpu.loadAverage[0] > current.cpu.cores) {
            recommendations.push('System is overloaded - consider reducing concurrent operations');
        }

        return recommendations;
    }

    async optimize() {
        try {
            const optimizations = [];

            // Force garbage collection if available
            if (global.gc) {
                global.gc();
                optimizations.push('Garbage collection forced');
            }

            // Clear old history if too large
            if (this.history.length > this.config.maxHistory * 1.5) {
                this.history = this.history.slice(-this.config.maxHistory);
                optimizations.push('History cleared');
            }

            // Clear old alerts
            if (this.alerts.length > 100) {
                this.alerts = this.alerts.slice(-50);
                optimizations.push('Old alerts cleared');
            }

            logger.info('Performance optimization completed', { optimizations });
            return { success: true, optimizations };
        } catch (error) {
            logger.error('Performance optimization failed', { error: error.message });
            return { success: false, error: error.message };
        }
    }

    async exportMetrics(format = 'json') {
        try {
            const data = {
                metrics: this.metrics,
                history: this.history,
                alerts: this.alerts,
                config: this.config,
                exportedAt: new Date().toISOString()
            };

            if (format === 'json') {
                const filename = `performance-metrics-${Date.now()}.json`;
                await fs.writeFile(filename, JSON.stringify(data, null, 2));
                return { success: true, filename, format };
            } else if (format === 'csv') {
                const csv = this.convertToCSV(data.history);
                const filename = `performance-metrics-${Date.now()}.csv`;
                await fs.writeFile(filename, csv);
                return { success: true, filename, format };
            } else {
                throw new Error(`Unsupported format: ${format}`);
            }
        } catch (error) {
            logger.error('Failed to export metrics', { error: error.message });
            return { success: false, error: error.message };
        }
    }

    convertToCSV(history) {
        if (history.length === 0) return '';

        const headers = [
            'timestamp',
            'cpu_usage',
            'memory_percentage',
            'disk_percentage',
            'load_average_1m',
            'load_average_5m',
            'load_average_15m'
        ];

        const rows = history.map(entry => [
            entry.timestamp,
            entry.metrics.cpu.usage.toFixed(2),
            entry.metrics.memory.percentage.toFixed(2),
            entry.metrics.disk.percentage.toFixed(2),
            entry.metrics.cpu.loadAverage[0].toFixed(2),
            entry.metrics.cpu.loadAverage[1].toFixed(2),
            entry.metrics.cpu.loadAverage[2].toFixed(2)
        ]);

        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }

    async cleanup() {
        try {
            this.stopMonitoring();
            this.history = [];
            this.alerts = [];
            this.monitoring = false;
            
            logger.info('Performance Monitor cleanup completed');
            return { success: true };
        } catch (error) {
            logger.error('Performance Monitor cleanup failed', { error: error.message });
            return { success: false, error: error.message };
        }
    }
}

module.exports = new PerformanceMonitor();