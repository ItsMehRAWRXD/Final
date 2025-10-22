// RawrZ Security Monitor - Comprehensive security monitoring and logging
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class SecurityMonitor {
    constructor() {
        this.logsDir = path.join(__dirname, 'logs');
        this.securityLogFile = path.join(this.logsDir, 'security.log');
        this.auditLogFile = path.join(this.logsDir, 'audit.log');
        this.performanceLogFile = path.join(this.logsDir, 'performance.log');
        
        this.securityEvents = [];
        this.auditTrail = [];
        this.performanceMetrics = new Map();
        
        this.initializeLogging();
    }

    async initializeLogging() {
        try {
            await fs.mkdir(this.logsDir, { recursive: true });
            console.log('[OK] Security monitoring initialized');
        } catch (error) {
            console.error('[ERROR] Failed to initialize security monitoring:', error.message);
        }
    }

    // Log security events
    async logSecurityEvent(event) {
        const timestamp = new Date().toISOString();
        const eventId = crypto.randomUUID();
        
        const securityEvent = {
            id: eventId,
            timestamp,
            type: event.type || 'security',
            severity: event.severity || 'info',
            message: event.message,
            details: event.details || {},
            source: event.source || 'unknown',
            user: event.user || 'system',
            ip: event.ip || 'unknown'
        };
        
        this.securityEvents.push(securityEvent);
        
        // Write to log file
        await this.writeToLog(this.securityLogFile, securityEvent);
        
        // Alert on high severity events
        if (event.severity === 'critical' || event.severity === 'high') {
            await this.sendSecurityAlert(securityEvent);
        }
        
        return securityEvent;
    }

    // Log audit events
    async logAuditEvent(event) {
        const timestamp = new Date().toISOString();
        const eventId = crypto.randomUUID();
        
        const auditEvent = {
            id: eventId,
            timestamp,
            action: event.action,
            resource: event.resource,
            user: event.user || 'system',
            ip: event.ip || 'unknown',
            result: event.result || 'success',
            details: event.details || {}
        };
        
        this.auditTrail.push(auditEvent);
        
        // Write to audit log
        await this.writeToLog(this.auditLogFile, auditEvent);
        
        return auditEvent;
    }

    // Write to log file
    async writeToLog(logFile, event) {
        try {
            const logEntry = JSON.stringify(event) + '\n';
            await fs.appendFile(logFile, logEntry);
        } catch (error) {
            console.error('[ERROR] Failed to write to log file:', error.message);
        }
    }

    // Send security alert
    async sendSecurityAlert(event) {
        console.log(`[SECURITY ALERT] ${event.severity.toUpperCase()}: ${event.message}`);
        console.log(`[SECURITY ALERT] Event ID: ${event.id}`);
        console.log(`[SECURITY ALERT] Timestamp: ${event.timestamp}`);
    }

    // Get system health status
    getSystemHealth() {
        const memoryUsage = process.memoryUsage();
        const uptime = process.uptime();
        
        return {
            memory: {
                used: memoryUsage.heapUsed,
                total: memoryUsage.heapTotal,
                external: memoryUsage.external,
                rss: memoryUsage.rss
            },
            uptime: uptime,
            securityEvents: this.securityEvents.length,
            auditEvents: this.auditTrail.length,
            health: this.calculateHealthScore()
        };
    }

    // Calculate health score
    calculateHealthScore() {
        let score = 100;
        
        // Deduct points for critical events
        const criticalEvents = this.securityEvents.filter(e => e.severity === 'critical');
        score -= criticalEvents.length * 10;
        
        // Deduct points for high severity events
        const highEvents = this.securityEvents.filter(e => e.severity === 'high');
        score -= highEvents.length * 5;
        
        return Math.max(0, Math.min(100, score));
    }
}

module.exports = new SecurityMonitor();
