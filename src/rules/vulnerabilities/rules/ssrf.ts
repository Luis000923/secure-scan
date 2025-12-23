/**
 * @fileoverview SSRF (Server-Side Request Forgery) Detection Rules
 * @module rules/vulnerabilities/rules/ssrf
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

export const ssrfRules: VulnerabilityRule[] = [
  {
    id: 'VUL-SSRF-001',
    name: 'SSRF - Node.js HTTP Request with User URL',
    description: 'Detects server-side HTTP requests using user-controlled URLs.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SSRF,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVASCRIPT, SupportedLanguage.TYPESCRIPT],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 85,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-fetch-req',
        pattern: 'fetch\\s*\\([^)]*(?:req\\.|params\\.|query\\.|\\$\\{)',
        flags: 'gi',
        weight: 1.0,
        description: 'fetch with user-controlled URL'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-axios-req',
        pattern: 'axios\\.(?:get|post|put|delete|request)\\s*\\([^)]*(?:req\\.|\\$\\{)',
        flags: 'gi',
        weight: 1.0,
        description: 'axios with user URL'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-http-request',
        pattern: 'http[s]?\\.(?:get|request)\\s*\\([^)]*(?:req\\.|\\+)',
        flags: 'gi',
        weight: 0.95,
        description: 'http.get with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-node-fetch',
        pattern: 'require\\s*\\([\'"]node-fetch[\'"]\\)[^)]*\\([^)]*(?:req\\.|\\$\\{)',
        flags: 'gi',
        weight: 0.90,
        description: 'node-fetch with user URL'
      }
    ],
    taintAnalysis: {
      sources: ['req.query.url', 'req.body.url', 'req.params.url', 'req.body.target'],
      sinks: ['fetch(', 'axios.get(', 'axios.post(', 'http.get(', 'https.get(', 'request(', 'got('],
      sanitizers: ['new URL(', 'URL.parse(', 'allowlist.includes(', 'isAllowedHost(']
    },
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'medium',
      technicalImpact: 'Access internal services, cloud metadata, port scanning, bypass firewalls.',
      businessImpact: 'Cloud credential theft, internal network mapping, data exfiltration.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      knownExploits: true
    },
    remediation: {
      summary: 'Validate URLs against allowlist of hosts. Block private IP ranges and cloud metadata endpoints.',
      steps: [
        'Parse URL and validate hostname against allowlist',
        'Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x)',
        'Block cloud metadata endpoints (169.254.169.254)',
        'Use URL validation library',
        'Disable HTTP redirects or revalidate on redirect'
      ],
      secureCodeExample: `const { URL } = require('url');
const ipRangeCheck = require('ip-range-check');

const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];
const BLOCKED_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16'];

async function safeFetch(userUrl) {
  const parsed = new URL(userUrl);
  
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    throw new Error('Host not allowed');
  }
  
  // Resolve DNS and check IP
  const addresses = await dns.promises.lookup(parsed.hostname);
  if (BLOCKED_RANGES.some(range => ipRangeCheck(addresses.address, range))) {
    throw new Error('Internal IP not allowed');
  }
  
  return fetch(userUrl, { redirect: 'manual' });
}`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A10],
      cwe: [CWE_REFERENCES.CWE_918]
    },
    tags: ['ssrf', 'nodejs', 'cloud-security', 'network'],
    enabled: true
  },
  {
    id: 'VUL-SSRF-002',
    name: 'SSRF - Python requests/urllib with User URL',
    description: 'Detects Python HTTP requests using user-controlled URLs.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SSRF,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PYTHON],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 85,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-requests',
        pattern: 'requests\\.(?:get|post|put|delete|head|patch)\\s*\\([^)]*(?:request\\.|f[\'"]|\\+)',
        flags: 'gi',
        weight: 1.0,
        description: 'requests with user URL'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-urllib',
        pattern: 'urllib\\.request\\.urlopen\\s*\\([^)]*(?:request\\.|\\+)',
        flags: 'gi',
        weight: 0.95,
        description: 'urllib.urlopen with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-httpx',
        pattern: 'httpx\\.(?:get|post|AsyncClient)\\s*\\([^)]*(?:request\\.|\\+)',
        flags: 'gi',
        weight: 0.90,
        description: 'httpx with user URL'
      }
    ],
    taintAnalysis: {
      sources: ['request.args', 'request.form', 'request.json'],
      sinks: ['requests.get(', 'requests.post(', 'urllib.request.urlopen(', 'httpx.get('],
      sanitizers: ['urlparse(', 'validators.url(', 'is_safe_url(']
    },
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'medium',
      technicalImpact: 'Internal network access, metadata service access.',
      businessImpact: 'AWS/GCP/Azure credential theft from metadata.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Validate URLs with allowlist. Block internal IPs and metadata endpoints.',
      steps: [
        'Parse and validate URL hostname',
        'Use allowlist of permitted domains',
        'Block private IP ranges after DNS resolution',
        'Disable redirects or revalidate'
      ],
      secureCodeExample: `from urllib.parse import urlparse
import ipaddress
import socket

ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
]

def safe_request(url: str):
    parsed = urlparse(url)
    
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError('Host not allowed')
    
    # Check resolved IP
    ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if any(ip in network for network in BLOCKED_NETWORKS):
        raise ValueError('Internal IP not allowed')
    
    return requests.get(url, allow_redirects=False)`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A10],
      cwe: [CWE_REFERENCES.CWE_918]
    },
    tags: ['ssrf', 'python', 'requests', 'cloud-security'],
    enabled: true
  },
  {
    id: 'VUL-SSRF-003',
    name: 'SSRF - PHP curl/file_get_contents with User URL',
    description: 'Detects PHP HTTP requests using user-controlled URLs.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SSRF,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.PHP],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 85,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-php-curl',
        pattern: 'curl_setopt\\s*\\([^,]*,\\s*CURLOPT_URL\\s*,\\s*\\$_(?:GET|POST|REQUEST)',
        flags: 'gi',
        weight: 1.0,
        description: 'curl with user URL'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-php-file-get',
        pattern: 'file_get_contents\\s*\\([^)]*(?:\\$_(?:GET|POST|REQUEST)|http)',
        flags: 'gi',
        weight: 0.95,
        description: 'file_get_contents with URL'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-php-fopen-url',
        pattern: 'fopen\\s*\\([^)]*(?:\\$_(?:GET|POST|REQUEST).*(?:http|ftp))',
        flags: 'gi',
        weight: 0.90,
        description: 'fopen with URL wrapper'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'medium',
      technicalImpact: 'Access internal resources, cloud metadata.',
      businessImpact: 'Internal network exposure, credential theft.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Validate URLs against allowlist. Use parse_url() and validate hostname.',
      steps: [
        'Parse URL with parse_url()',
        'Validate hostname against allowlist',
        'Block internal IP ranges',
        'Disable allow_url_fopen if not needed',
        'Use CURLOPT_FOLLOWLOCATION carefully'
      ],
      secureCodeExample: `<?php
$allowed_hosts = ['api.example.com', 'cdn.example.com'];

function safe_fetch($url) {
    global $allowed_hosts;
    
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['host'])) {
        throw new Exception('Invalid URL');
    }
    
    if (!in_array($parsed['host'], $allowed_hosts, true)) {
        throw new Exception('Host not allowed');
    }
    
    // Resolve and check IP
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new Exception('Internal IP not allowed');
    }
    
    return file_get_contents($url);
}
?>`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A10],
      cwe: [CWE_REFERENCES.CWE_918]
    },
    tags: ['ssrf', 'php', 'curl'],
    enabled: true
  },
  {
    id: 'VUL-SSRF-004',
    name: 'SSRF - Java HttpClient/URL with User Input',
    description: 'Detects Java HTTP requests using user-controlled URLs.',
    version: '1.0.0',
    vulnerabilityType: VulnerabilityType.SSRF,
    category: VulnerabilityCategory.INJECTION,
    languages: [SupportedLanguage.JAVA],
    severity: VulnerabilitySeverity.HIGH,
    confidence: ConfidenceLevel.HIGH,
    baseScore: 85,
    patterns: [
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-java-url',
        pattern: 'new\\s+URL\\s*\\([^)]*(?:request\\.getParameter|\\+)',
        flags: 'gi',
        weight: 1.0,
        description: 'new URL with user input'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-java-httpclient',
        pattern: 'HttpClient\\..*\\.send\\s*\\([^)]*(?:request\\.getParameter|\\+)',
        flags: 'gi',
        weight: 0.95,
        description: 'HttpClient with user URL'
      },
      {
        type: PatternType.REGEX,
        patternId: 'ssrf-java-resttemplate',
        pattern: 'RestTemplate\\s*\\(\\)\\.(?:get|post)ForObject\\s*\\([^)]*(?:\\+|request)',
        flags: 'gi',
        weight: 0.90,
        description: 'RestTemplate with dynamic URL'
      }
    ],
    impact: {
      confidentiality: 'high',
      integrity: 'medium',
      availability: 'medium',
      technicalImpact: 'Internal service access, cloud metadata access.',
      businessImpact: 'AWS/Azure/GCP credential theft, internal API access.'
    },
    exploitability: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none'
    },
    remediation: {
      summary: 'Validate URLs against allowlist. Use URL class to parse and validate hostname.',
      steps: [
        'Parse URL and extract hostname',
        'Validate against allowlist',
        'Resolve DNS and block private IPs',
        'Use HttpClient with redirect policy'
      ],
      secureCodeExample: `import java.net.URL;
import java.net.InetAddress;
import java.util.Set;

public class SafeHttpClient {
    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");
    
    public String safeFetch(String urlString) throws Exception {
        URL url = new URL(urlString);
        
        if (!ALLOWED_HOSTS.contains(url.getHost())) {
            throw new SecurityException("Host not allowed");
        }
        
        InetAddress address = InetAddress.getByName(url.getHost());
        if (address.isSiteLocalAddress() || address.isLoopbackAddress()) {
            throw new SecurityException("Internal IP not allowed");
        }
        
        // Proceed with request
        return HttpClient.newHttpClient()
            .send(HttpRequest.newBuilder().uri(url.toURI()).build(),
                  HttpResponse.BodyHandlers.ofString())
            .body();
    }
}`,
      effort: 'medium',
      priority: 'high'
    },
    standards: {
      owasp: [OWASP_TOP_10_2021.A10],
      cwe: [CWE_REFERENCES.CWE_918]
    },
    tags: ['ssrf', 'java', 'httpclient'],
    enabled: true
  }
];

export default ssrfRules;
