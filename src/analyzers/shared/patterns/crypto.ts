/**
 * Weak Cryptography Detection Patterns
 * Shared across all language analyzers
 */

import { Severity, SecurityStandard } from '../../../types';

/**
 * Weak hash algorithms that should not be used for security
 */
export const WEAK_HASH_ALGORITHMS = {
  md5: {
    names: ['md5', 'MD5'],
    severity: Severity.MEDIUM,
    description: 'MD5 está criptográficamente roto y no debe usarse para fines de seguridad.',
    recommendation: 'Use SHA-256 o SHA-3 para hash, o bcrypt/Argon2 para contraseñas.',
  },
  sha1: {
    names: ['sha1', 'SHA1', 'sha-1', 'SHA-1'],
    severity: Severity.MEDIUM,
    description: 'SHA-1 está deprecado y es vulnerable a ataques de colisión.',
    recommendation: 'Use SHA-256 o SHA-3 en su lugar.',
  },
  md4: {
    names: ['md4', 'MD4'],
    severity: Severity.HIGH,
    description: 'MD4 está severamente roto y no debe ser utilizado.',
    recommendation: 'Use SHA-256 o SHA-3 para hash.',
  },
  md2: {
    names: ['md2', 'MD2'],
    severity: Severity.HIGH,
    description: 'MD2 está severamente roto y no debe ser utilizado.',
    recommendation: 'Use SHA-256 o SHA-3 para hash.',
  },
};

/**
 * Weak encryption algorithms
 */
export const WEAK_ENCRYPTION_ALGORITHMS = {
  des: {
    names: ['DES', 'des', 'DESede'],
    severity: Severity.HIGH,
    description: 'DES utiliza una clave de 56 bits que es demasiado corta para la seguridad moderna.',
    recommendation: 'Use AES-256 con modo GCM.',
  },
  tripleDes: {
    names: ['3DES', 'TripleDES', 'DESede', 'TDEA'],
    severity: Severity.MEDIUM,
    description: 'Triple DES está deprecado debido a su pequeño tamaño de bloque.',
    recommendation: 'Use AES-256 con modo GCM.',
  },
  rc2: {
    names: ['RC2', 'rc2'],
    severity: Severity.HIGH,
    description: 'RC2 se considera inseguro.',
    recommendation: 'Use AES-256 con modo GCM.',
  },
  rc4: {
    names: ['RC4', 'rc4', 'ARCFOUR', 'ARC4'],
    severity: Severity.HIGH,
    description: 'RC4 tiene múltiples vulnerabilidades conocidas.',
    recommendation: 'Use AES-256 con modo GCM.',
  },
  blowfish: {
    names: ['Blowfish', 'blowfish'],
    severity: Severity.MEDIUM,
    description: 'Blowfish tiene un tamaño de bloque de 64 bits, vulnerable a ataques de cumpleaños.',
    recommendation: 'Use AES-256 con modo GCM.',
  },
};

/**
 * Insecure cryptographic modes
 */
export const INSECURE_CRYPTO_MODES = {
  ecb: {
    names: ['ECB', 'ecb', '/ECB/', 'AES/ECB', 'DES/ECB'],
    severity: Severity.HIGH,
    description: 'El modo ECB revela patrones en los datos cifrados.',
    recommendation: 'Use el modo GCM o CBC con un manejo adecuado del IV.',
  },
  cbc_no_hmac: {
    names: ['CBC'],
    severity: Severity.MEDIUM,
    description: 'El modo CBC sin autenticación es vulnerable a ataques de padding oracle.',
    recommendation: 'Use el modo GCM o agregue autenticación HMAC.',
    // Note: CBC alone is not necessarily insecure, need context
    requiresContext: true,
  },
};

/**
 * Weak random number generators
 */
export const WEAK_RANDOM_PATTERNS: Record<string, {
  pattern: RegExp;
  severity: Severity;
  description: string;
  recommendation: string;
}> = {
  javascript: {
    pattern: /Math\.random\s*\(\s*\)/g,
    severity: Severity.MEDIUM,
    description: 'Math.random() no es criptográficamente seguro.',
    recommendation: 'Use crypto.getRandomValues() o crypto.randomBytes().',
  },
  python: {
    pattern: /\brandom\.(random|randint|choice|randrange|sample)\s*\(/g,
    severity: Severity.MEDIUM,
    description: 'El módulo random no es criptográficamente seguro.',
    recommendation: 'Use el módulo secrets o os.urandom() para operaciones sensibles a la seguridad.',
  },
  java: {
    pattern: /new\s+(?:java\.util\.)?Random\s*\(/g,
    severity: Severity.MEDIUM,
    description: 'java.util.Random no es criptográficamente seguro.',
    recommendation: 'Use java.security.SecureRandom en su lugar.',
  },
  csharp: {
    pattern: /new\s+Random\s*\(/g,
    severity: Severity.MEDIUM,
    description: 'System.Random no es criptográficamente seguro.',
    recommendation: 'Use System.Security.Cryptography.RandomNumberGenerator.',
  },
  php: {
    pattern: /\b(rand|mt_rand|array_rand)\s*\(/g,
    severity: Severity.MEDIUM,
    description: 'rand() y mt_rand() no son criptográficamente seguros.',
    recommendation: 'Use random_bytes() o random_int() en su lugar.',
  },
  cpp: {
    pattern: /\b(rand|srand)\s*\(/g,
    severity: Severity.MEDIUM,
    description: 'rand() no es criptográficamente seguro y tiene baja entropía.',
    recommendation: 'Use <random> con std::random_device o un CSPRNG específico de la plataforma.',
  },
};

/**
 * Build language-specific weak crypto patterns
 */
export function buildWeakCryptoPatterns(language: string): Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
}> {
  const patterns: Array<{
    pattern: RegExp;
    name: string;
    severity: Severity;
    description: string;
    recommendation: string;
  }> = [];

  // Add weak hash patterns based on language
  switch (language) {
    case 'javascript':
    case 'typescript':
      patterns.push(
        {
          pattern: /crypto\.createHash\s*\(\s*['"](?:md5|sha1|md4)['"]\s*\)/gi,
          name: 'Weak Hash Algorithm',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm (MD5/SHA1).',
          recommendation: 'Use sha256 or sha512 instead.',
        },
        {
          pattern: /CryptoJS\.(?:MD5|SHA1|MD4)\s*\(/gi,
          name: 'Weak Hash Algorithm (CryptoJS)',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use CryptoJS.SHA256 or CryptoJS.SHA3 instead.',
        }
      );
      break;

    case 'python':
      patterns.push(
        {
          pattern: /hashlib\.(md5|sha1|md4)\s*\(/gi,
          name: 'Weak Hash Algorithm',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use hashlib.sha256() or hashlib.sha3_256() instead.',
        },
        {
          pattern: /Crypto\.Hash\.(?:MD5|SHA1|MD4)\./gi,
          name: 'Weak Hash Algorithm (PyCrypto)',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use Crypto.Hash.SHA256 instead.',
        }
      );
      break;

    case 'java':
      patterns.push(
        {
          pattern: /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-1|MD4|MD2)["']\s*\)/gi,
          name: 'Weak Hash Algorithm',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use "SHA-256" or "SHA-512" instead.',
        },
        {
          pattern: /Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC2|RC4|Blowfish)(?:\/[^"']+)?["']\s*\)/gi,
          name: 'Weak Encryption Algorithm',
          severity: Severity.HIGH,
          description: 'Using weak/deprecated encryption algorithm.',
          recommendation: 'Use "AES/GCM/NoPadding" instead.',
        },
        {
          pattern: /Cipher\.getInstance\s*\(\s*["'][^"']*\/ECB\/[^"']*["']\s*\)/gi,
          name: 'ECB Mode Encryption',
          severity: Severity.HIGH,
          description: 'ECB mode reveals patterns in encrypted data.',
          recommendation: 'Use GCM or CBC mode with HMAC.',
        }
      );
      break;

    case 'csharp':
      patterns.push(
        {
          pattern: /(?:MD5|SHA1)\.Create\s*\(\s*\)/gi,
          name: 'Weak Hash Algorithm',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use SHA256.Create() or SHA512.Create() instead.',
        },
        {
          pattern: /new\s+(?:DES|TripleDES|RC2)CryptoServiceProvider\s*\(/gi,
          name: 'Weak Encryption Algorithm',
          severity: Severity.HIGH,
          description: 'Using weak/deprecated encryption algorithm.',
          recommendation: 'Use Aes.Create() with GCM mode.',
        },
        {
          pattern: /CipherMode\.ECB/gi,
          name: 'ECB Mode Encryption',
          severity: Severity.HIGH,
          description: 'ECB mode reveals patterns in encrypted data.',
          recommendation: 'Use CipherMode.GCM or CipherMode.CBC with HMAC.',
        }
      );
      break;

    case 'php':
      patterns.push(
        {
          pattern: /\b(md5|sha1)\s*\(/gi,
          name: 'Weak Hash Algorithm',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use hash("sha256", ...) or password_hash() for passwords.',
        },
        {
          pattern: /openssl_encrypt\s*\([^,]+,\s*["'](?:des|des-ede|des-ede3|rc2|rc4|bf)[^"']*["']/gi,
          name: 'Weak Encryption Algorithm',
          severity: Severity.HIGH,
          description: 'Using weak/deprecated encryption algorithm.',
          recommendation: 'Use "aes-256-gcm" instead.',
        },
        {
          pattern: /openssl_encrypt\s*\([^,]+,\s*["'][^"']*-ecb["']/gi,
          name: 'ECB Mode Encryption',
          severity: Severity.HIGH,
          description: 'ECB mode reveals patterns in encrypted data.',
          recommendation: 'Use GCM or CBC mode.',
        },
        {
          pattern: /mcrypt_/gi,
          name: 'Deprecated mcrypt Extension',
          severity: Severity.HIGH,
          description: 'mcrypt extension is deprecated and removed in PHP 7.2+.',
          recommendation: 'Use openssl_encrypt() with modern algorithms.',
        }
      );
      break;

    case 'c':
    case 'cpp':
      patterns.push(
        {
          pattern: /EVP_md5\s*\(\s*\)|EVP_sha1\s*\(\s*\)/gi,
          name: 'Weak Hash Algorithm',
          severity: Severity.MEDIUM,
          description: 'Using weak hash algorithm.',
          recommendation: 'Use EVP_sha256() or EVP_sha512() instead.',
        },
        {
          pattern: /EVP_des(?:_ede3)?_(?:ecb|cbc|cfb|ofb)\s*\(\s*\)/gi,
          name: 'Weak Encryption Algorithm',
          severity: Severity.HIGH,
          description: 'DES is too weak for modern security.',
          recommendation: 'Use EVP_aes_256_gcm() instead.',
        }
      );
      break;
  }

  // Add weak random pattern for the language
  if (WEAK_RANDOM_PATTERNS[language]) {
    const weakRandom = WEAK_RANDOM_PATTERNS[language];
    patterns.push({
      pattern: weakRandom.pattern,
      name: 'Insecure Random Number Generator',
      severity: weakRandom.severity,
      description: weakRandom.description,
      recommendation: weakRandom.recommendation,
    });
  }

  return patterns;
}

/**
 * Get security standards for cryptography findings
 */
export function getCryptoStandards(): SecurityStandard[] {
  return [
    {
      name: 'CWE',
      id: 'CWE-327',
      title: 'Use of a Broken or Risky Cryptographic Algorithm',
      description: 'The use of a broken or risky cryptographic algorithm.',
      url: 'https://cwe.mitre.org/data/definitions/327.html'
    },
    {
      name: 'CWE',
      id: 'CWE-328',
      title: 'Reversible One-Way Hash',
      description: 'The product uses a hashing algorithm that produces a reversible hash.',
      url: 'https://cwe.mitre.org/data/definitions/328.html'
    },
    {
      name: 'CWE',
      id: 'CWE-330',
      title: 'Use of Insufficiently Random Values',
      description: 'The product uses insufficiently random numbers or values.',
      url: 'https://cwe.mitre.org/data/definitions/330.html'
    },
    {
      name: 'OWASP',
      id: 'A02:2021',
      title: 'Cryptographic Failures',
      description: 'Failures related to cryptography which often lead to sensitive data exposure.',
      url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'
    }
  ];
}
