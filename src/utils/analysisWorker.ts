/**
 * Analysis Worker Script
 * Runs in a separate thread to analyze files
 */

import { parentPort, workerData } from 'worker_threads';
import { AnalysisTask, AnalysisResult } from './workerPool';
import { Finding, Rule, ScannedFile } from '../types';

// Worker ID for logging
const workerId = workerData?.workerId || 'unknown';

/**
 * Simple regex-based analysis for worker thread
 * Note: Complex analyzers should be imported dynamically
 */
function analyzeFile(file: ScannedFile, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  const lines = file.content.split('\n');

  for (const rule of rules) {
    if (!rule.enabled) continue;
    
    // Check if rule applies to this language
    if (rule.languages && !rule.languages.includes(file.language as any)) {
      continue;
    }

    // Process patterns
    for (const rulePattern of rule.patterns || []) {
      if (rulePattern.type === 'regex') {
        try {
          const regex = new RegExp(rulePattern.pattern, rulePattern.flags || 'gm');
          let match;

          while ((match = regex.exec(file.content)) !== null) {
            // Find line number
            const beforeMatch = file.content.substring(0, match.index);
            const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;
            const matchedLine = lines[lineNumber - 1] || '';

            findings.push({
              id: `${rule.id}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
              ruleId: rule.id,
              title: rule.name,
              description: rule.description,
              severity: rule.severity,
              threatType: rule.threatType,
              category: rule.category,
              location: {
                file: file.relativePath,
                startLine: lineNumber,
                endLine: lineNumber
              },
              snippet: {
                code: matchedLine.trim(),
                contextBefore: lineNumber > 1 ? lines[lineNumber - 2] || '' : '',
                contextAfter: lines[lineNumber] || ''
              },
              standards: rule.standards || [],
              remediation: rule.remediation,
              confidence: 80,
              tags: rule.tags || [],
              analyzer: 'parallel-worker',
              timestamp: new Date()
            });

            // Prevent infinite loops for zero-width matches
            if (match.index === regex.lastIndex) {
              regex.lastIndex++;
            }
          }
        } catch (error) {
          // Invalid regex, skip
          console.error(`Worker ${workerId}: Invalid regex in rule ${rule.id}: ${error}`);
        }
      }
    }
  }

  return findings;
}

/**
 * Handle incoming tasks
 */
if (parentPort) {
  parentPort.on('message', (task: AnalysisTask) => {
    const startTime = Date.now();
    
    try {
      const findings = analyzeFile(task.file, task.rules);
      
      const result: AnalysisResult = {
        taskId: task.id,
        filePath: task.file.relativePath,
        findings,
        duration: Date.now() - startTime
      };

      parentPort!.postMessage(result);
    } catch (error) {
      const result: AnalysisResult = {
        taskId: task.id,
        filePath: task.file.relativePath,
        findings: [],
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error)
      };

      parentPort!.postMessage(result);
    }
  });
}

export {};
