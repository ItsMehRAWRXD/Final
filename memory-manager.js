// RawrZ Memory Manager - Advanced memory management and optimization
const os = require('os');
const fs = require('fs').promises;
const path = require('path');

class MemoryManager {
    constructor() {
        this.memoryStats = {
            totalAllocated: 0,
            totalFreed: 0,
            currentUsage: 0,
            peakUsage: 0,
            operations: 0,
            startTime: Date.now()
        };
        
        this.memoryPools = new Map();
        this.gcThreshold = 100 * 1024 * 1024; // 100MB
        this.maxMemoryUsage = 0.8; // 80% of total system memory
        this.initialized = false;
    }

    async initialize(config = {}) {
        try {
            this.config = {
                gcThreshold: config.gcThreshold || this.gcThreshold,
                maxMemoryUsage: config.maxMemoryUsage || this.maxMemoryUsage,
                enableAutoGC: config.enableAutoGC !== false,
                memoryPoolSize: config.memoryPoolSize || 1024 * 1024, // 1MB
                ...config
            };
            
            this.initialized = true;
            console.log('[OK] Memory Manager initialized');
            
            // Start memory monitoring if enabled
            if (this.config.enableAutoGC) {
                this.startMemoryMonitoring();
            }
            
            return { success: true, config: this.config };
        } catch (error) {
            console.error('[ERROR] Memory Manager initialization failed:', error.message);
            throw error;
        }
    }

    // Get current memory usage
    getMemoryUsage() {
        const usage = process.memoryUsage();
        const systemMemory = {
            total: os.totalmem(),
            free: os.freemem(),
            used: os.totalmem() - os.freemem()
        };
        
        return {
            process: {
                rss: usage.rss,
                heapTotal: usage.heapTotal,
                heapUsed: usage.heapUsed,
                external: usage.external,
                arrayBuffers: usage.arrayBuffers
            },
            system: systemMemory,
            percentage: (usage.heapUsed / systemMemory.total) * 100,
            timestamp: new Date().toISOString()
        };
    }

    // Allocate memory pool
    async allocatePool(name, size = null) {
        try {
            const poolSize = size || this.config.memoryPoolSize;
            const pool = Buffer.alloc(poolSize);
            
            this.memoryPools.set(name, {
                buffer: pool,
                size: poolSize,
                used: 0,
                createdAt: Date.now()
            });
            
            this.memoryStats.totalAllocated += poolSize;
            this.memoryStats.currentUsage += poolSize;
            this.memoryStats.peakUsage = Math.max(this.memoryStats.peakUsage, this.memoryStats.currentUsage);
            this.memoryStats.operations++;
            
            console.log(`[OK] Memory pool allocated: ${name} (${poolSize} bytes)`);
            return { success: true, name, size: poolSize };
        } catch (error) {
            console.error(`[ERROR] Failed to allocate memory pool ${name}:`, error.message);
            return { success: false, error: error.message };
        }
    }

    // Free memory pool
    async freePool(name) {
        try {
            const pool = this.memoryPools.get(name);
            if (!pool) {
                throw new Error(`Memory pool not found: ${name}`);
            }
            
            this.memoryStats.totalFreed += pool.size;
            this.memoryStats.currentUsage -= pool.size;
            this.memoryPools.delete(name);
            this.memoryStats.operations++;
            
            console.log(`[OK] Memory pool freed: ${name} (${pool.size} bytes)`);
            return { success: true, name, size: pool.size };
        } catch (error) {
            console.error(`[ERROR] Failed to free memory pool ${name}:`, error.message);
            return { success: false, error: error.message };
        }
    }

    // Get memory from pool
    getFromPool(name, offset = 0, length = null) {
        try {
            const pool = this.memoryPools.get(name);
            if (!pool) {
                throw new Error(`Memory pool not found: ${name}`);
            }
            
            const actualLength = length || (pool.size - offset);
            if (offset + actualLength > pool.size) {
                throw new Error('Requested memory exceeds pool size');
            }
            
            return pool.buffer.slice(offset, offset + actualLength);
        } catch (error) {
            console.error(`[ERROR] Failed to get memory from pool ${name}:`, error.message);
            return null;
        }
    }

    // Write to memory pool
    writeToPool(name, data, offset = 0) {
        try {
            const pool = this.memoryPools.get(name);
            if (!pool) {
                throw new Error(`Memory pool not found: ${name}`);
            }
            
            if (offset + data.length > pool.size) {
                throw new Error('Data exceeds pool size');
            }
            
            data.copy(pool.buffer, offset);
            pool.used = Math.max(pool.used, offset + data.length);
            
            return { success: true, written: data.length };
        } catch (error) {
            console.error(`[ERROR] Failed to write to memory pool ${name}:`, error.message);
            return { success: false, error: error.message };
        }
    }

    // Memory optimization
    async optimize() {
        const startTime = Date.now();
        const before = this.getMemoryUsage();
        
        try {
            // Force garbage collection if available
            if (global.gc) {
                global.gc();
            }
            
            // Clear unused memory pools
            const now = Date.now();
            const maxAge = 5 * 60 * 1000; // 5 minutes
            
            for (const [name, pool] of this.memoryPools.entries()) {
                if (now - pool.createdAt > maxAge && pool.used === 0) {
                    await this.freePool(name);
                }
            }
            
            const after = this.getMemoryUsage();
            const freed = before.process.heapUsed - after.process.heapUsed;
            
            console.log(`[OK] Memory optimization completed: ${freed} bytes freed`);
            
            return {
                type: 'memory-optimization',
                before: before.process,
                after: after.process,
                freed: Math.max(0, freed),
                optimized: true,
                duration: Date.now() - startTime,
                pools: this.memoryPools.size
            };
        } catch (error) {
            console.error('[ERROR] Memory optimization failed:', error.message);
            return {
                type: 'memory-optimization',
                before: before.process,
                after: this.getMemoryUsage().process,
                freed: 0,
                optimized: false,
                error: error.message,
                duration: Date.now() - startTime
            };
        }
    }

    // Check if memory usage is high
    isMemoryUsageHigh() {
        const usage = this.getMemoryUsage();
        const threshold = this.config.maxMemoryUsage * os.totalmem();
        return usage.process.heapUsed > threshold;
    }

    // Start memory monitoring
    startMemoryMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
        }
        
        this.monitoringInterval = setInterval(async () => {
            if (this.isMemoryUsageHigh()) {
                console.log('[WARN] High memory usage detected, running optimization...');
                await this.optimize();
            }
        }, 30000); // Check every 30 seconds
        
        console.log('[OK] Memory monitoring started');
    }

    // Stop memory monitoring
    stopMemoryMonitoring() {
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
            console.log('[OK] Memory monitoring stopped');
        }
    }

    // Get memory statistics
    getStats() {
        const usage = this.getMemoryUsage();
        const uptime = Date.now() - this.memoryStats.startTime;
        
        return {
            ...this.memoryStats,
            current: usage,
            pools: {
                count: this.memoryPools.size,
                totalSize: Array.from(this.memoryPools.values()).reduce((sum, pool) => sum + pool.size, 0),
                totalUsed: Array.from(this.memoryPools.values()).reduce((sum, pool) => sum + pool.used, 0)
            },
            uptime,
            monitoring: !!this.monitoringInterval
        };
    }

    // Clear all memory pools
    async clearAllPools() {
        const poolNames = Array.from(this.memoryPools.keys());
        const results = [];
        
        for (const name of poolNames) {
            const result = await this.freePool(name);
            results.push({ name, ...result });
        }
        
        console.log(`[OK] Cleared ${poolNames.length} memory pools`);
        return results;
    }

    // Memory leak detection
    detectMemoryLeaks() {
        const usage = this.getMemoryUsage();
        const stats = this.getStats();
        
        const leakIndicators = {
            highHeapUsage: usage.process.heapUsed > 500 * 1024 * 1024, // 500MB
            growingPools: stats.pools.count > 10,
            highOperations: stats.operations > 1000,
            lowFreedMemory: stats.totalFreed < stats.totalAllocated * 0.5
        };
        
        const leakScore = Object.values(leakIndicators).filter(Boolean).length;
        
        return {
            hasLeaks: leakScore > 2,
            score: leakScore,
            indicators: leakIndicators,
            recommendations: this.getLeakRecommendations(leakIndicators)
        };
    }

    // Get leak recommendations
    getLeakRecommendations(indicators) {
        const recommendations = [];
        
        if (indicators.highHeapUsage) {
            recommendations.push('Consider running garbage collection or freeing unused objects');
        }
        if (indicators.growingPools) {
            recommendations.push('Review memory pool allocation strategy');
        }
        if (indicators.highOperations) {
            recommendations.push('Consider implementing memory pooling for frequent allocations');
        }
        if (indicators.lowFreedMemory) {
            recommendations.push('Ensure proper cleanup of allocated memory');
        }
        
        return recommendations;
    }

    // Cleanup
    async cleanup() {
        try {
            this.stopMemoryMonitoring();
            await this.clearAllPools();
            
            this.memoryStats = {
                totalAllocated: 0,
                totalFreed: 0,
                currentUsage: 0,
                peakUsage: 0,
                operations: 0,
                startTime: Date.now()
            };
            
            console.log('[OK] Memory Manager cleanup completed');
            return { success: true };
        } catch (error) {
            console.error('[ERROR] Memory Manager cleanup failed:', error.message);
            return { success: false, error: error.message };
        }
    }
}

module.exports = new MemoryManager();
