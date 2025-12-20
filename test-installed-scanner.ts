/**
 * Test Script for Installed Dependencies Scanner
 * Run with: npx ts-node test-installed-scanner.ts
 * 
 */

import { InstalledDependenciesScanner, scanInstalledDependencies } from './src/dependencies/installed';
import { generateInstalledDependenciesSection } from './src/reports/installedDepsReportGenerator';
import * as fs from 'fs';
import * as path from 'path';

async function runTest() {
  console.log('🔍 Testing Installed Dependencies Scanner\n');
  console.log('='.repeat(60));

  // Test with fake-node_modules folder
  const testPath = path.join(__dirname, 'test-samples');
  
  console.log(`\n📂 Scanning test samples at: ${testPath}\n`);

  const scanner = new InstalledDependenciesScanner({
    projectPath: testPath,
    foldersToScan: [path.join(testPath, 'fake-node_modules')],
    verbose: true,
    verifyIntegrity: false, // No lock file for test samples
    scanPostInstallScripts: true
  });

  const result = await scanner.scan();

  // Print results
  console.log('\n' + '='.repeat(60));
  console.log('📊 SCAN RESULTS');
  console.log('='.repeat(60));

  console.log(`\n📦 Packages scanned: ${result.stats.totalPackagesFound}`);
  console.log(`📄 Files scanned: ${result.stats.totalFilesScanned}`);
  console.log(`⏱️  Duration: ${result.stats.duration}ms`);

  console.log('\n🦠 MALWARE FINDINGS:');
  console.log('-'.repeat(40));
  
  if (result.malwareFindings.length === 0) {
    console.log('   No malware detected');
  } else {
    for (const finding of result.malwareFindings) {
      console.log(`\n   [${finding.severity.toUpperCase()}] ${finding.title}`);
      console.log(`   Package: ${finding.package.name}@${finding.package.version}`);
      console.log(`   File: ${finding.filePath}`);
      if (finding.lineNumber) {
        console.log(`   Line: ${finding.lineNumber}`);
      }
      console.log(`   Indicators: ${finding.indicators.join(', ')}`);
      console.log(`   Confidence: ${finding.confidence}%`);
    }
  }

  console.log('\n\n⚠️ SUSPICIOUS POST-INSTALL SCRIPTS:');
  console.log('-'.repeat(40));
  
  if (result.suspiciousScripts.length === 0) {
    console.log('   No suspicious scripts detected');
  } else {
    for (const script of result.suspiciousScripts) {
      console.log(`\n   [${script.severity.toUpperCase()}] ${script.packageName}`);
      console.log(`   Script type: ${script.script.type}`);
      console.log(`   Command: ${script.script.command}`);
      console.log(`   Risk indicators: ${script.riskIndicators.length}`);
    }
  }

  console.log('\n\n📁 SCANNED FOLDERS:');
  console.log('-'.repeat(40));
  
  for (const folder of result.scannedFolders) {
    console.log(`\n   ${folder.path}`);
    console.log(`   Type: ${folder.type}`);
    console.log(`   Ecosystem: ${folder.ecosystem}`);
    console.log(`   Packages: ${folder.packageCount}`);
    console.log(`   Files scanned: ${folder.filesScanned}`);
  }

  // Generate HTML report section
  console.log('\n\n📝 Generating HTML report section...');
  const htmlSection = generateInstalledDependenciesSection(result, 'es');
  
  const reportPath = path.join(testPath, 'installed-deps-report.html');
  const fullHtml = `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Installed Dependencies Malware Scan Report</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      padding: 40px;
      min-height: 100vh;
    }
    h1 {
      color: #58a6ff;
      margin-bottom: 30px;
      text-align: center;
    }
  </style>
</head>
<body>
  <h1>🔐 Secure-Scan: Installed Dependencies Malware Report</h1>
  ${htmlSection}
</body>
</html>
  `;
  
  fs.writeFileSync(reportPath, fullHtml);
  console.log(`   Report saved to: ${reportPath}`);

  console.log('\n' + '='.repeat(60));
  console.log('✅ Test complete!');
  console.log('='.repeat(60) + '\n');

  // Summary
  console.log('📊 SUMMARY:');
  console.log(`   Total malware findings: ${result.malwareFindings.length}`);
  console.log(`   Suspicious scripts: ${result.suspiciousScripts.length}`);
  console.log(`   Integrity issues: ${result.integrityIssues.length}`);
  
  if (result.malwareFindings.length > 0) {
    console.log('\n   ⚠️  Malware detected! Review the report for details.');
  }
}

runTest().catch(console.error);
