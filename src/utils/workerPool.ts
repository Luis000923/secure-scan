/**
 * Parallel Analyzer Worker Pool
 * Uses worker_threads for parallel file analysis
 */

import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import * as os from 'os';
import * as path from 'path';
import { ScannedFile, Finding, Rule } from '../types';
import { logger } from './logger';

/**
 * Worker task definition
 */
export interface AnalysisTask {
  id: string;
  file: ScannedFile;
  rules: Rule[];
  analyzerType: string;
}

/**
 * Worker result
 */
export interface AnalysisResult {
  taskId: string;
  filePath: string;
  findings: Finding[];
  duration: number;
  error?: string;
}

/**
 * Worker pool configuration
 */
export interface WorkerPoolConfig {
  /** Maximum number of workers (default: CPU cores - 1) */
  maxWorkers?: number;
  /** Task timeout in ms (default: 30000) */
  taskTimeout?: number;
  /** Idle timeout before terminating worker (default: 60000) */
  idleTimeout?: number;
}

/**
 * Worker state
 */
interface WorkerState {
  worker: Worker;
  busy: boolean;
  taskId?: string;
  startTime?: number;
}

/**
 * Queued task
 */
interface QueuedTask {
  task: AnalysisTask;
  resolve: (result: AnalysisResult) => void;
  reject: (error: Error) => void;
}

/**
 * Worker Pool Manager
 * Manages a pool of worker threads for parallel file analysis
 */
export class WorkerPool {
  private workers: Map<number, WorkerState> = new Map();
  private taskQueue: QueuedTask[] = [];
  private maxWorkers: number;
  private taskTimeout: number;
  private idleTimeout: number;
  private workerScript: string;
  private initialized = false;
  private shutdownRequested = false;

  constructor(config: WorkerPoolConfig = {}) {
    this.maxWorkers = config.maxWorkers || Math.max(1, os.cpus().length - 1);
    this.taskTimeout = config.taskTimeout || 30000;
    this.idleTimeout = config.idleTimeout || 60000;
    this.workerScript = path.join(__dirname, 'analysisWorker.js');
  }

  /**
   * Initialize the worker pool
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    logger.debug(`Initializing worker pool with ${this.maxWorkers} workers`);
    
    // Pre-spawn some workers
    const initialWorkers = Math.min(2, this.maxWorkers);
    for (let i = 0; i < initialWorkers; i++) {
      this.spawnWorker();
    }

    this.initialized = true;
  }

  /**
   * Spawn a new worker
   */
  private spawnWorker(): number {
    const workerId = Date.now() + Math.random();
    
    const worker = new Worker(this.workerScript, {
      workerData: { workerId }
    });

    const state: WorkerState = {
      worker,
      busy: false
    };

    worker.on('message', (result: AnalysisResult) => {
      this.handleWorkerResult(workerId, result);
    });

    worker.on('error', (error) => {
      logger.error(`Worker ${workerId} error: ${error.message}`);
      this.handleWorkerError(workerId, error);
    });

    worker.on('exit', (code) => {
      if (code !== 0 && !this.shutdownRequested) {
        logger.warn(`Worker ${workerId} exited with code ${code}`);
      }
      this.workers.delete(workerId);
    });

    this.workers.set(workerId, state);
    return workerId;
  }

  /**
   * Handle worker result
   */
  private handleWorkerResult(workerId: number, result: AnalysisResult): void {
    const state = this.workers.get(workerId);
    if (!state) return;

    state.busy = false;
    state.taskId = undefined;
    state.startTime = undefined;

    // Process next task in queue
    this.processQueue();
  }

  /**
   * Handle worker error
   */
  private handleWorkerError(workerId: number, error: Error): void {
    const state = this.workers.get(workerId);
    if (!state) return;

    // If worker was processing a task, reject it
    if (state.taskId) {
      const queuedTask = this.taskQueue.find(t => t.task.id === state.taskId);
      if (queuedTask) {
        queuedTask.reject(error);
      }
    }

    // Remove failed worker
    this.workers.delete(workerId);

    // Spawn replacement if needed
    if (this.workers.size < this.maxWorkers && !this.shutdownRequested) {
      this.spawnWorker();
    }
  }

  /**
   * Submit a task for analysis
   */
  async submitTask(task: AnalysisTask): Promise<AnalysisResult> {
    if (!this.initialized) {
      await this.initialize();
    }

    return new Promise((resolve, reject) => {
      this.taskQueue.push({ task, resolve, reject });
      this.processQueue();
    });
  }

  /**
   * Submit multiple tasks and wait for all results
   */
  async submitBatch(tasks: AnalysisTask[]): Promise<AnalysisResult[]> {
    const promises = tasks.map(task => this.submitTask(task));
    return Promise.all(promises);
  }

  /**
   * Process the task queue
   */
  private processQueue(): void {
    if (this.taskQueue.length === 0) return;

    // Find an available worker
    let availableWorker: [number, WorkerState] | undefined;
    
    for (const [id, state] of this.workers) {
      if (!state.busy) {
        availableWorker = [id, state];
        break;
      }
    }

    // If no worker available, try to spawn one
    if (!availableWorker && this.workers.size < this.maxWorkers) {
      const newWorkerId = this.spawnWorker();
      availableWorker = [newWorkerId, this.workers.get(newWorkerId)!];
    }

    if (!availableWorker) {
      // All workers busy, task will be processed when one becomes available
      return;
    }

    const [workerId, state] = availableWorker;
    const queuedTask = this.taskQueue.shift();
    
    if (!queuedTask) return;

    // Mark worker as busy
    state.busy = true;
    state.taskId = queuedTask.task.id;
    state.startTime = Date.now();

    // Send task to worker
    state.worker.postMessage(queuedTask.task);

    // Set up timeout
    setTimeout(() => {
      if (state.busy && state.taskId === queuedTask.task.id) {
        logger.warn(`Task ${queuedTask.task.id} timed out`);
        queuedTask.reject(new Error('Task timeout'));
        
        // Terminate and replace worker
        state.worker.terminate();
        this.workers.delete(workerId);
        
        if (!this.shutdownRequested) {
          this.spawnWorker();
        }
      }
    }, this.taskTimeout);
  }

  /**
   * Get pool statistics
   */
  getStats(): {
    totalWorkers: number;
    busyWorkers: number;
    queuedTasks: number;
    maxWorkers: number;
  } {
    let busyCount = 0;
    for (const state of this.workers.values()) {
      if (state.busy) busyCount++;
    }

    return {
      totalWorkers: this.workers.size,
      busyWorkers: busyCount,
      queuedTasks: this.taskQueue.length,
      maxWorkers: this.maxWorkers
    };
  }

  /**
   * Shutdown the worker pool
   */
  async shutdown(): Promise<void> {
    this.shutdownRequested = true;

    // Wait for current tasks to complete (with timeout)
    const shutdownTimeout = 5000;
    const startTime = Date.now();

    while (this.taskQueue.length > 0 || this.hasBusyWorkers()) {
      if (Date.now() - startTime > shutdownTimeout) {
        logger.warn('Shutdown timeout, forcing termination');
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }

    // Terminate all workers
    for (const [id, state] of this.workers) {
      await state.worker.terminate();
    }

    this.workers.clear();
    this.taskQueue = [];
    this.initialized = false;
    
    logger.debug('Worker pool shutdown complete');
  }

  /**
   * Check if any workers are busy
   */
  private hasBusyWorkers(): boolean {
    for (const state of this.workers.values()) {
      if (state.busy) return true;
    }
    return false;
  }
}

/**
 * Singleton worker pool instance
 */
let globalWorkerPool: WorkerPool | null = null;

/**
 * Get or create the global worker pool
 */
export function getWorkerPool(config?: WorkerPoolConfig): WorkerPool {
  if (!globalWorkerPool) {
    globalWorkerPool = new WorkerPool(config);
  }
  return globalWorkerPool;
}

/**
 * Shutdown the global worker pool
 */
export async function shutdownWorkerPool(): Promise<void> {
  if (globalWorkerPool) {
    await globalWorkerPool.shutdown();
    globalWorkerPool = null;
  }
}

export default WorkerPool;
