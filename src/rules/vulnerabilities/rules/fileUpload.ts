/**
 * @fileoverview File Upload Vulnerabilities Detection Rules
 * @module rules/vulnerabilities/rules/fileUpload
 */

import {
  VulnerabilityRule,
  VulnerabilityType,
  VulnerabilityCategory,
  VulnerabilitySeverity,
  ConfidenceLevel,
  SupportedLanguage,
  PatternType
} from '../types';
import { OWASP_TOP_10_2021, CWE_REFERENCES } from '../constants';

export const fileUploadRules: VulnerabilityRule[] = [
  {
    id: 'VUL-UPLOAD-001',
    name: 'Unrestricted File Upload - No Extension Validation',
    description: 'Detects file upload handling without proper extension validation.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.FILE_UPLOAD,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 80,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'upload-multer-no-filter',
        pattern: 'multer\\s*\\([^)]*\\)(?![\\s\\S]{0,100}fileFilter)',
        flags: 'gi',
        weight: 0.85,
        description: 'Multer without fileFilter'
      },
      {
        type: PatternType.REGEX,
        patternId: 'upload-original-name',
        pattern: '\\.originalname|file\\.name[^\\s]*path',
        flags: 'gi',
        weight: 0.75,
        description: 'Using original filename in path'
      },
      {
        type: PatternType.REGEX,
        patternId: 'upload-write-file',
        pattern: 'fs\\.writeFile(?:Sync)?\\s*\\([^)]*req\\.files?',
        flags: 'gi',
        weight: 0.90,
        description: 'Writing uploaded file without validation'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Upload and execute malicious scripts. Web shell installation.',
      businessImpact: 'Complete server compromise via uploaded web shell.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'low',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Validate file extensions, MIME types, and content. Store outside webroot.',
      steps: [
        'Validate file extension against allowlist',
        'Verify MIME type matches extension',
        'Check file content (magic bytes)',
        'Generate random filename for storage',
        'Store files outside webroot or use CDN',
        'Set Content-Disposition: attachment for downloads'
      ],
      secureCodeExample: `const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.pdf'];
const ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];

const storage = multer.diskStorage({
  destination: './uploads/', // Outside webroot
  filename: (req, file, cb) => {
    // Generate random filename
    const ext = path.extname(file.originalname).toLowerCase();
    const name = crypto.randomBytes(16).toString('hex');
    cb(null, \`\${name}\${ext}\`);
  }
});

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    return cb(new Error('Invalid file type'), false);
  }
  
  if (!ALLOWED_MIMES.includes(file.mimetype)) {
    return cb(new Error('Invalid MIME type'), false);
  }
  
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A04],
      cwe: [CWE_REFERENCES.CWE_434]
    },
    tags: ['file-upload', 'rce', 'webshell'],
    enabled: true
  },
  {
    id: 'VUL-UPLOAD-002',
    name: 'Unrestricted File Upload - PHP',
    description: 'Detects PHP file upload handling without proper validation.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.FILE_UPLOAD,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.CRITICAL,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 90,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'upload-php-move-uploaded',
        pattern: 'move_uploaded_file\\s*\\([^,]+,\\s*[^)]*\\$_FILES',
        flags: 'gi',
        weight: 0.85,
        description: 'move_uploaded_file with user filename'
      },
      {
        type: PatternType.REGEX,
        patternId: 'upload-php-copy',
        pattern: 'copy\\s*\\(\\s*\\$_FILES\\[[\'"][^\'"]+[\'"]\\]\\[[\'"]tmp_name[\'"]\\]',
        flags: 'gi',
        weight: 0.80,
        description: 'copy uploaded file'
      },
      {
        type: PatternType.REGEX,
        patternId: 'upload-php-no-ext-check',
        pattern: '\\$_FILES\\[[\'"][^\'"]+[\'"]\\]\\[[\'"]name[\'"]\\](?![\\s\\S]{0,50}(?:pathinfo|preg_match|extension))',
        flags: 'gi',
        weight: 0.70,
        description: 'Using filename without extension check'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'high',
      technicalImpact: 'Upload PHP scripts for remote code execution.',
      businessImpact: 'Complete server takeover.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'low',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Validate extensions with allowlist. Store outside webroot. Disable PHP in upload directory.',
      steps: [
        'Validate extension against strict allowlist',
        'Check MIME type with finfo_file()',
        'Store files outside webroot',
        'Disable PHP execution in upload directory via .htaccess',
        'Generate random filenames'
      ],
      secureCodeExample: `<?php
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
$upload_dir = '/var/uploads/'; // Outside webroot

function validateUpload($file) {
    global $allowed_extensions, $allowed_mimes;
    
    // Get extension
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!in_array($ext, $allowed_extensions, true)) {
        return false;
    }
    
    // Verify MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file['tmp_name']);
    if (!in_array($mime, $allowed_mimes, true)) {
        return false;
    }
    
    return true;
}

if (validateUpload($_FILES['upload'])) {
    $ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
    $newname = bin2hex(random_bytes(16)) . '.' . $ext;
    move_uploaded_file($_FILES['upload']['tmp_name'], $upload_dir . $newname);
}

// .htaccess in upload directory
// php_flag engine off
?>`,
      effort: 'medium',
      priority: 'immediate'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A04],
      cwe: [CWE_REFERENCES.CWE_434]
    },
    tags: ['file-upload', 'php', 'rce', 'critical'],
    enabled: true
  },
  {
    id: 'VUL-UPLOAD-003',
    name: 'Unrestricted File Upload - Python/Flask',
    description: 'Detects Flask/Django file upload handling without proper validation.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.FILE_UPLOAD,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.MEDIUM,
    baseScore: 75,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'upload-flask-save',
        pattern: 'request\\.files\\[[\'"][^\'"]+[\'"]\\]\\.save\\s*\\([^)]*filename',
        flags: 'gi',
        weight: 0.85,
        description: 'Flask file.save with user filename'
      },
      {
        type: PatternType.REGEX,
        patternId: 'upload-no-secure-filename',
        pattern: '\\.filename(?![\\s\\S]{0,50}secure_filename)',
        flags: 'gi',
        weight: 0.75,
        description: 'Using filename without secure_filename'
      },
      {
        type: PatternType.REGEX,
        patternId: 'upload-django-chunks',
        pattern: '\\.chunks\\(\\)(?![\\s\\S]{0,50}(?:allowed|extension))',
        flags: 'gi',
        weight: 0.70,
        description: 'Django file upload without extension check'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'high',
      availability: 'medium',
      technicalImpact: 'File overwrite, path traversal, potential code execution.',
      businessImpact: 'Data manipulation, possible RCE.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'low',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Use secure_filename(). Validate extensions. Store safely.',
      steps: [
        'Use werkzeug.utils.secure_filename()',
        'Validate extension against allowlist',
        'Check MIME type with python-magic',
        'Generate random filenames',
        'Store outside webroot'
      ],
      secureCodeExample: `from flask import Flask, request
from werkzeug.utils import secure_filename
import os
import uuid
import magic

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
ALLOWED_MIMES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
UPLOAD_FOLDER = '/var/uploads'  # Outside webroot

def allowed_file(file):
    filename = secure_filename(file.filename)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    
    if ext not in ALLOWED_EXTENSIONS:
        return False
    
    # Check actual MIME type
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)  # Reset file position
    
    return mime in ALLOWED_MIMES

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file or not allowed_file(file):
        return 'Invalid file', 400
    
    ext = secure_filename(file.filename).rsplit('.', 1)[-1]
    new_filename = f'{uuid.uuid4().hex}.{ext}'
    file.save(os.path.join(UPLOAD_FOLDER, new_filename))
    return 'Upload successful'`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A04],
      cwe: [CWE_REFERENCES.CWE_434]
    },
    tags: ['file-upload', 'python', 'flask', 'django'],
    enabled: true
  }
];

export default fileUploadRules;
