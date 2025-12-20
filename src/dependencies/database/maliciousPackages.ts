/**
 * Known Malicious Packages Database
 * Static database of known malicious packages for offline detection
 * Updated: 2024-01
 */

import { MaliciousPackageEntry, MalwareIndicator, PackageEcosystem } from '../types';

/**
 * Database of known malicious packages
 * Sources: npm security advisories, PyPI reports, Snyk, etc.
 */
export const KNOWN_MALICIOUS_PACKAGES: MaliciousPackageEntry[] = [
  // NPM malicious packages
  {
    name: 'event-stream',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.STEALER, MalwareIndicator.BACKDOOR],
    description: 'Compromised package with cryptocurrency wallet stealer (version 3.3.6)',
    reportedDate: '2018-11-26',
    references: ['https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident'],
    affectedVersions: '3.3.6'
  },
  {
    name: 'ua-parser-js',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.CRYPTOMINER, MalwareIndicator.STEALER],
    description: 'Hijacked package with cryptominer and password stealer',
    reportedDate: '2021-10-22',
    references: ['https://github.com/ArmandPhil662/MALWARE-SAMPLE'],
    affectedVersions: '0.7.29, 0.8.0, 1.0.0'
  },
  {
    name: 'coa',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.STEALER],
    description: 'Hijacked package used for credential theft',
    reportedDate: '2021-11-04',
    references: ['https://blog.sonatype.com/npm-hijacked-supply-chain'],
    affectedVersions: '2.0.3, 2.0.4, 2.1.1, 2.1.3, 3.0.1, 3.1.3'
  },
  {
    name: 'rc',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.STEALER],
    description: 'Hijacked package used for credential theft',
    reportedDate: '2021-11-04',
    references: ['https://blog.sonatype.com/npm-hijacked-supply-chain'],
    affectedVersions: '1.2.9, 1.3.9, 2.3.9'
  },
  {
    name: 'flatmap-stream',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.STEALER, MalwareIndicator.BACKDOOR],
    description: 'Malicious package injected into event-stream',
    reportedDate: '2018-11-26',
    references: ['https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident'],
    affectedVersions: '*'
  },
  {
    name: 'colors',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.OBFUSCATED],
    description: 'Sabotaged by maintainer with infinite loop (protestware)',
    reportedDate: '2022-01-09',
    references: ['https://www.bleepingcomputer.com/news/security/dev-corrupts-npm-libs-colors-and-faker-breaking-thousands-of-apps/'],
    affectedVersions: '1.4.1, 1.4.2'
  },
  {
    name: 'faker',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.OBFUSCATED],
    description: 'Sabotaged by maintainer (protestware)',
    reportedDate: '2022-01-09',
    references: ['https://www.bleepingcomputer.com/news/security/dev-corrupts-npm-libs-colors-and-faker-breaking-thousands-of-apps/'],
    affectedVersions: '6.6.6'
  },
  {
    name: 'node-ipc',
    ecosystem: 'npm',
    indicators: [MalwareIndicator.DATA_EXFILTRATION],
    description: 'Supply chain attack targeting Russian/Belarusian IPs (peacenotwar)',
    reportedDate: '2022-03-16',
    references: ['https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/'],
    affectedVersions: '10.1.1, 10.1.2, 10.1.3'
  },
  
  // Python malicious packages
  {
    name: 'ctx',
    ecosystem: 'pip',
    indicators: [MalwareIndicator.STEALER],
    description: 'Compromised package stealing environment variables',
    reportedDate: '2022-05-24',
    references: ['https://www.bleepingcomputer.com/news/security/pypi-package-ctx-compromised-to-steal-aws-credentials/'],
    affectedVersions: '0.1.2, 0.2.2, 0.2.6'
  },
  {
    name: 'phpass',
    ecosystem: 'pip',
    indicators: [MalwareIndicator.STEALER],
    description: 'Compromised package stealing environment variables',
    reportedDate: '2022-05-24',
    references: ['https://www.bleepingcomputer.com/news/security/pypi-package-ctx-compromised-to-steal-aws-credentials/'],
    affectedVersions: '*'
  },
  {
    name: 'colourama',
    ecosystem: 'pip',
    indicators: [MalwareIndicator.CRYPTOMINER],
    description: 'Typosquat of colorama with cryptominer',
    reportedDate: '2019-10-22',
    references: ['https://www.zdnet.com/article/two-malicious-python-libraries-removed-from-pypi/'],
    affectedVersions: '*'
  },
  {
    name: 'python3-dateutil',
    ecosystem: 'pip',
    indicators: [MalwareIndicator.STEALER],
    description: 'Typosquat of python-dateutil stealing SSH keys',
    reportedDate: '2019-12-04',
    references: ['https://snyk.io/blog/malicious-packages-open-source-code-2019/'],
    affectedVersions: '*'
  },
  {
    name: 'jeIlyfish',
    ecosystem: 'pip',
    indicators: [MalwareIndicator.STEALER],
    description: 'Typosquat of jellyfish (using capital I instead of l)',
    reportedDate: '2019-12-04',
    references: ['https://snyk.io/blog/malicious-packages-open-source-code-2019/'],
    affectedVersions: '*'
  },
  {
    name: 'libpeshnern',
    ecosystem: 'pip',
    indicators: [MalwareIndicator.BACKDOOR],
    description: 'Reverse shell backdoor',
    reportedDate: '2021-05-15',
    references: ['https://blog.sonatype.com/sonatype-catches-new-pypi-ransomware'],
    affectedVersions: '*'
  },
  
  // PHP malicious packages (Composer)
  {
    name: 'phpunit/php-unit',
    ecosystem: 'composer',
    indicators: [MalwareIndicator.BACKDOOR],
    description: 'Typosquat of phpunit/phpunit with backdoor',
    reportedDate: '2020-01-15',
    references: ['https://packagist.org/'],
    affectedVersions: '*'
  },
  {
    name: 'symfony/symf0ny',
    ecosystem: 'composer',
    indicators: [MalwareIndicator.BACKDOOR],
    description: 'Typosquat of symfony packages',
    reportedDate: '2020-01-15',
    references: ['https://packagist.org/'],
    affectedVersions: '*'
  },
  
  // NuGet malicious packages
  {
    name: 'SpeechRecognition',
    ecosystem: 'nuget',
    indicators: [MalwareIndicator.CRYPTOMINER],
    description: 'Cryptocurrency miner disguised as legitimate package',
    reportedDate: '2023-03-20',
    references: ['https://blog.jfrog.com/nuget-malware'],
    affectedVersions: '*'
  },

  // Maven malicious packages
  {
    name: 'org.springframework:spring-core',
    ecosystem: 'maven',
    indicators: [MalwareIndicator.BACKDOOR],
    description: 'Note: Legitimate package but check for typosquats',
    reportedDate: '2023-01-01',
    references: [],
    affectedVersions: 'none'
  }
];

/**
 * Popular package names for typosquatting detection
 */
export const POPULAR_PACKAGES: Record<PackageEcosystem, string[]> = {
  npm: [
    'lodash', 'express', 'react', 'webpack', 'axios', 'moment', 'chalk',
    'request', 'commander', 'async', 'debug', 'uuid', 'underscore',
    'typescript', 'jquery', 'vue', 'angular', 'next', 'eslint', 'babel',
    'prettier', 'jest', 'mocha', 'gulp', 'grunt', 'nodemon', 'mongoose',
    'socket.io', 'cheerio', 'passport', 'cors', 'dotenv', 'body-parser',
    'colors', 'minimist', 'yargs', 'inquirer', 'rxjs', 'bluebird', 'fs-extra',
    'glob', 'mkdirp', 'rimraf', 'semver', 'nanoid', 'dayjs', 'date-fns'
  ],
  pip: [
    'requests', 'numpy', 'pandas', 'django', 'flask', 'matplotlib', 'tensorflow',
    'scikit-learn', 'scipy', 'pillow', 'beautifulsoup4', 'selenium', 'pytest',
    'boto3', 'sqlalchemy', 'celery', 'redis', 'psycopg2', 'paramiko', 'pyyaml',
    'cryptography', 'jinja2', 'click', 'aiohttp', 'httpx', 'fastapi', 'uvicorn',
    'colorama', 'tqdm', 'python-dateutil', 'pytz', 'jellyfish', 'pydantic',
    'setuptools', 'wheel', 'pip', 'virtualenv', 'ipython', 'jupyter', 'black',
    'pylint', 'mypy', 'flake8', 'isort', 'poetry', 'torch', 'keras', 'nltk'
  ],
  composer: [
    'laravel/framework', 'symfony/symfony', 'guzzlehttp/guzzle', 'monolog/monolog',
    'phpunit/phpunit', 'doctrine/orm', 'twig/twig', 'vlucas/phpdotenv',
    'nesbot/carbon', 'ramsey/uuid', 'fzaninotto/faker', 'psr/log', 'swiftmailer/swiftmailer',
    'league/flysystem', 'predis/predis', 'nikic/fast-route', 'slim/slim'
  ],
  maven: [
    'org.springframework:spring-core', 'com.google.guava:guava', 'org.apache.commons:commons-lang3',
    'junit:junit', 'org.slf4j:slf4j-api', 'ch.qos.logback:logback-classic',
    'com.fasterxml.jackson.core:jackson-databind', 'org.apache.httpcomponents:httpclient',
    'mysql:mysql-connector-java', 'org.postgresql:postgresql', 'org.projectlombok:lombok'
  ],
  gradle: [
    'org.springframework:spring-core', 'com.google.guava:guava', 'org.jetbrains.kotlin:kotlin-stdlib'
  ],
  nuget: [
    'Newtonsoft.Json', 'Microsoft.EntityFrameworkCore', 'Serilog', 'AutoMapper',
    'Dapper', 'MediatR', 'FluentValidation', 'Polly', 'xunit', 'NUnit', 'Moq'
  ],
  vcpkg: [
    'boost', 'openssl', 'curl', 'zlib', 'fmt', 'nlohmann-json', 'sqlite3',
    'gtest', 'opencv', 'protobuf', 'grpc', 'abseil', 'cpprestsdk'
  ],
  conan: [
    'boost', 'openssl', 'zlib', 'fmt', 'spdlog', 'gtest', 'catch2', 'nlohmann_json',
    'abseil', 'protobuf', 'grpc', 'opencv', 'poco', 'cpprestsdk'
  ],
  cmake: [
    'Boost', 'OpenSSL', 'CURL', 'ZLIB', 'GTest', 'OpenCV', 'Protobuf', 'gRPC'
  ]
};

/**
 * Known abandoned/deprecated packages
 */
export const DEPRECATED_PACKAGES: Record<string, { ecosystem: PackageEcosystem; replacement?: string; reason: string }> = {
  'request': { ecosystem: 'npm', replacement: 'axios or node-fetch', reason: 'Deprecated in 2020' },
  'moment': { ecosystem: 'npm', replacement: 'dayjs or date-fns', reason: 'Deprecated, large bundle size' },
  'underscore': { ecosystem: 'npm', replacement: 'lodash', reason: 'Maintenance mode' },
  'node-uuid': { ecosystem: 'npm', replacement: 'uuid', reason: 'Renamed to uuid' },
  'faker': { ecosystem: 'npm', replacement: '@faker-js/faker', reason: 'Sabotaged, use community fork' },
  'crypto': { ecosystem: 'pip', replacement: 'cryptography', reason: 'Deprecated, use cryptography' },
  'pycrypto': { ecosystem: 'pip', replacement: 'pycryptodome', reason: 'Unmaintained since 2012' },
  'nose': { ecosystem: 'pip', replacement: 'pytest', reason: 'Unmaintained since 2016' },
  'phpmailer/phpmailer': { ecosystem: 'composer', replacement: 'Check for security updates', reason: 'Had critical RCE vulnerabilities' }
};

/**
 * Packages known to have dangerous post-install scripts
 */
export const DANGEROUS_POSTINSTALL_PACKAGES: string[] = [
  // These are examples - some packages legitimately need postinstall
  // but unusual ones should be flagged for review
];

/**
 * Get malicious package entry if exists
 */
export function getMaliciousPackage(name: string, ecosystem: PackageEcosystem): MaliciousPackageEntry | undefined {
  return KNOWN_MALICIOUS_PACKAGES.find(p => 
    p.name.toLowerCase() === name.toLowerCase() && p.ecosystem === ecosystem
  );
}

/**
 * Check if package is deprecated
 */
export function isDeprecatedPackage(name: string): { deprecated: boolean; info?: typeof DEPRECATED_PACKAGES[string] } {
  const info = DEPRECATED_PACKAGES[name.toLowerCase()];
  return { deprecated: !!info, info };
}

/**
 * Get popular packages for an ecosystem (for typosquatting detection)
 */
export function getPopularPackages(ecosystem: PackageEcosystem): string[] {
  return POPULAR_PACKAGES[ecosystem] || [];
}
