/**
 * Modern Web Security Patterns
 * WebSocket, OAuth2, CORS, Open Redirect, Mass Assignment
 * Shared across all language analyzers
 */

import { Severity, SecurityStandard } from '../../../types';

/**
 * WebSocket security patterns by language
 */
export const WEBSOCKET_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /new\s+WebSocket\s*\(\s*(?:req\.|user\.|input|.*\+)/gi,
      name: 'Inyección de URL de WebSocket',
      severity: Severity.HIGH,
      description: 'La URL de WebSocket controlada por el usuario permite el secuestro de la conexión.',
      recommendation: 'Valide y ponga en lista blanca las URLs de los servidores WebSocket.',
      cwe: 'CWE-940',
    },
    {
      pattern: /ws\.on\s*\(\s*['"]message['"]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{[^}]*eval\s*\(/gi,
      name: 'Ejecución de Código en Mensaje de WebSocket (eval)',
      severity: Severity.CRITICAL,
      description: 'Ejecutar el contenido del mensaje de WebSocket a través de eval.',
      recommendation: 'Analice y valide el contenido del mensaje antes de procesarlo.',
      cwe: 'CWE-94',
    },
    {
      pattern: /ws\.on\s*\(\s*['"]message['"]\s*,\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{[^}]*(?:innerHTML|outerHTML)\s*=/gi,
      name: 'XSS en Mensaje de WebSocket',
      severity: Severity.HIGH,
      description: 'El contenido del mensaje de WebSocket se renderiza como HTML.',
      recommendation: 'Sanitice el contenido del mensaje antes de insertarlo en el DOM.',
      cwe: 'CWE-79',
    },
    {
      pattern: /(?:verifyClient|handleProtocols)\s*:\s*(?:null|undefined|false|\(\)\s*=>\s*true)/gi,
      name: 'Falta de Validación de Origen en WebSocket',
      severity: Severity.MEDIUM,
      description: 'El servidor WebSocket acepta conexiones sin validación de origen.',
      recommendation: 'Implemente verifyClient para validar el origen de la conexión.',
      cwe: 'CWE-346',
    },
    {
      pattern: /WebSocketServer\s*\(\s*\{[^}]*(?!verifyClient)[^}]*\}\s*\)/gi,
      name: 'WebSocket sin Verificación de Cliente',
      severity: Severity.MEDIUM,
      description: 'Servidor WebSocket sin verificación de cliente.',
      recommendation: 'Agregue la opción verifyClient para validar las conexiones de los clientes.',
      cwe: 'CWE-346',
    },
  ],

  python: [
    {
      pattern: /websockets\.connect\s*\(\s*(?:f["']|["'].*\+|.*\.format)/gi,
      name: 'WebSocket URL Injection',
      severity: Severity.HIGH,
      description: 'Dynamic WebSocket URL construction.',
      recommendation: 'Validate and whitelist WebSocket URLs.',
      cwe: 'CWE-940',
    },
    {
      pattern: /async\s+for\s+\w+\s+in\s+websocket:.*exec\s*\(/gi,
      name: 'WebSocket Message Execution',
      severity: Severity.CRITICAL,
      description: 'Executing code from WebSocket messages.',
      recommendation: 'Never execute WebSocket message content.',
      cwe: 'CWE-94',
    },
    {
      pattern: /origins\s*=\s*(?:\[\s*\]|None|["']\*["'])/gi,
      name: 'WebSocket Open Origins',
      severity: Severity.MEDIUM,
      description: 'WebSocket accepting connections from any origin.',
      recommendation: 'Restrict origins to trusted domains.',
      cwe: 'CWE-346',
    },
  ],

  java: [
    {
      pattern: /@ServerEndpoint.*@OnMessage\s*\([^)]*\)\s*\{[^}]*eval/gi,
      name: 'WebSocket Message Execution',
      severity: Severity.CRITICAL,
      description: 'Executing WebSocket message content.',
      recommendation: 'Validate and sanitize all WebSocket messages.',
      cwe: 'CWE-94',
    },
    {
      pattern: /configurator\s*=\s*.*class.*modifyHandshake\s*\([^)]*\)\s*\{[^}]*return\s+true/gi,
      name: 'WebSocket Handshake Bypass',
      severity: Severity.MEDIUM,
      description: 'WebSocket handshake validation always passes.',
      recommendation: 'Validate origin and credentials in handshake.',
      cwe: 'CWE-346',
    },
  ],

  csharp: [
    {
      pattern: /WebSocket\.CreateClientWebSocket\s*\([^)]*\+/gi,
      name: 'WebSocket URL Injection',
      severity: Severity.HIGH,
      description: 'Dynamic WebSocket URL construction.',
      recommendation: 'Validate WebSocket URLs before connection.',
      cwe: 'CWE-940',
    },
    {
      pattern: /app\.UseWebSockets\s*\(\s*\)\s*;[^}]*(?!Origin)/gi,
      name: 'WebSocket Missing Origin Check',
      severity: Severity.MEDIUM,
      description: 'WebSocket middleware without origin validation.',
      recommendation: 'Validate WebSocket request origins.',
      cwe: 'CWE-346',
    },
  ],

  php: [
    {
      pattern: /new\s+(?:Ratchet\\|React\\).*\$(?:_GET|_POST|_REQUEST)/gi,
      name: 'WebSocket User Input',
      severity: Severity.HIGH,
      description: 'User input in WebSocket configuration.',
      recommendation: 'Validate all WebSocket configuration values.',
      cwe: 'CWE-20',
    },
  ],
};

/**
 * OAuth2 security patterns by language
 */
export const OAUTH2_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /response_type\s*[=:]\s*["']token["']/gi,
      name: 'Flujo Implícito de OAuth2',
      severity: Severity.HIGH,
      description: 'El flujo implícito de OAuth2 expone tokens en fragmentos de URL.',
      recommendation: 'Use el flujo de Código de Autorización con PKCE en su lugar.',
      cwe: 'CWE-522',
    },
    {
      pattern: /state\s*[=:]\s*(?:null|undefined|["']['"])/gi,
      name: 'OAuth2: Falta Parámetro State',
      severity: Severity.HIGH,
      description: 'El flujo de OAuth2 sin el parámetro state permite CSRF.',
      recommendation: 'Genere y valide un parámetro de estado criptográfico.',
      cwe: 'CWE-352',
    },
    {
      pattern: /redirect_uri\s*[=:]\s*(?:req\.|user\.|.*\+)/gi,
      name: 'OAuth2: Redirección Abierta',
      severity: Severity.HIGH,
      description: 'Una redirect_uri controlada por el usuario permite el robo de tokens.',
      recommendation: 'Ponga las URIs de redirección en una lista blanca, nunca acepte entrada de usuario.',
      cwe: 'CWE-601',
    },
    {
      pattern: /client_secret\s*[=:]\s*["'][^"']+["']/gi,
      name: 'OAuth2: Exposición de Client Secret',
      severity: Severity.CRITICAL,
      description: 'Client secret hardcoded en el código del lado del cliente.',
      recommendation: 'Nunca exponga los client secrets, use el intercambio de tokens en el backend.',
      cwe: 'CWE-798',
    },
    {
      pattern: /(?:localStorage|sessionStorage)\.setItem\s*\([^)]*(?:access_token|id_token)/gi,
      name: 'OAuth2: Token en el Almacenamiento',
      severity: Severity.MEDIUM,
      description: 'Los tokens de OAuth almacenados en localStorage son vulnerables a XSS.',
      recommendation: 'Use cookies httpOnly o un manejo seguro de tokens.',
      cwe: 'CWE-922',
    },
    {
      pattern: /(?:code_challenge_method|code_verifier)\s*[=:]\s*(?:null|undefined)/gi,
      name: 'OAuth2: PKCE Deshabilitado',
      severity: Severity.MEDIUM,
      description: 'El flujo de Código de Autorización sin PKCE es vulnerable.',
      recommendation: 'Implemente PKCE con el método de desafío S256.',
      cwe: 'CWE-287',
    },
  ],

  python: [
    {
      pattern: /response_type\s*=\s*["']token["']/gi,
      name: 'OAuth2 Implicit Flow',
      severity: Severity.HIGH,
      description: 'OAuth2 implicit flow is deprecated and insecure.',
      recommendation: 'Use Authorization Code flow with PKCE.',
      cwe: 'CWE-522',
    },
    {
      pattern: /state\s*=\s*(?:None|["']["'])/gi,
      name: 'OAuth2 Missing State',
      severity: Severity.HIGH,
      description: 'OAuth2 without state parameter is vulnerable to CSRF.',
      recommendation: 'Generate random state and validate on callback.',
      cwe: 'CWE-352',
    },
    {
      pattern: /redirect_uri\s*=\s*(?:request\.|.*\+|f["'])/gi,
      name: 'OAuth2 Open Redirect',
      severity: Severity.HIGH,
      description: 'Dynamic redirect_uri allows token theft.',
      recommendation: 'Use fixed, registered redirect URIs.',
      cwe: 'CWE-601',
    },
  ],

  java: [
    {
      pattern: /ResponseType\.TOKEN/gi,
      name: 'OAuth2 Implicit Flow',
      severity: Severity.HIGH,
      description: 'Implicit grant type is insecure.',
      recommendation: 'Use Authorization Code grant with PKCE.',
      cwe: 'CWE-522',
    },
    {
      pattern: /\.state\s*\(\s*null\s*\)/gi,
      name: 'OAuth2 Missing State',
      severity: Severity.HIGH,
      description: 'OAuth2 without state enables CSRF attacks.',
      recommendation: 'Set cryptographically random state parameter.',
      cwe: 'CWE-352',
    },
  ],

  csharp: [
    {
      pattern: /ResponseType\s*=\s*["']token["']/gi,
      name: 'OAuth2 Implicit Flow',
      severity: Severity.HIGH,
      description: 'Implicit flow exposes tokens in URL.',
      recommendation: 'Use Authorization Code flow with PKCE.',
      cwe: 'CWE-522',
    },
    {
      pattern: /SaveTokens\s*=\s*true.*(?!HttpOnly)/gi,
      name: 'OAuth2 Token Storage',
      severity: Severity.MEDIUM,
      description: 'OAuth tokens may be stored insecurely.',
      recommendation: 'Use secure, httpOnly cookie storage.',
      cwe: 'CWE-922',
    },
  ],

  php: [
    {
      pattern: /\$_GET\s*\[\s*['"]code['"]\s*\].*(?!state)/gi,
      name: 'OAuth2 Missing State Validation',
      severity: Severity.HIGH,
      description: 'OAuth callback without state validation.',
      recommendation: 'Validate state parameter matches session.',
      cwe: 'CWE-352',
    },
  ],
};

/**
 * CORS (Cross-Origin Resource Sharing) security patterns
 */
export const CORS_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /Access-Control-Allow-Origin['"]\s*[,:]\s*["']\*["']/gi,
      name: 'Origen Comodín en CORS',
      severity: Severity.MEDIUM,
      description: 'El origen CORS con comodín permite cualquier dominio.',
      recommendation: 'Especifique los orígenes permitidos explícitamente.',
      cwe: 'CWE-942',
    },
    {
      pattern: /Access-Control-Allow-Credentials.*true.*Access-Control-Allow-Origin.*(?:req\.headers\.origin|\*)/gi,
      name: 'Credenciales CORS con Origen Dinámico',
      severity: Severity.HIGH,
      description: 'Reflejar el origen con credenciales permite CSRF.',
      recommendation: 'Ponga los orígenes específicos en una lista blanca, nunca refleje el origen de la solicitud.',
      cwe: 'CWE-942',
    },
    {
      pattern: /origin\s*:\s*true/gi,
      name: 'Reflejo de Origen en CORS',
      severity: Severity.MEDIUM,
      description: 'Middleware de CORS que refleja el origen de la solicitud.',
      recommendation: 'Use una lista blanca de orígenes explícita.',
      cwe: 'CWE-942',
    },
    {
      pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|\*|req\.headers\.origin)/gi,
      name: 'Configuración Insegura de CORS',
      severity: Severity.MEDIUM,
      description: 'CORS que permite todos los orígenes o refleja el origen.',
      recommendation: 'Ponga los orígenes de confianza en una lista blanca explícitamente.',
      cwe: 'CWE-942',
    },
  ],

  python: [
    {
      pattern: /CORS_ALLOW_ALL_ORIGINS\s*=\s*True/gi,
      name: 'Django CORS Allow All',
      severity: Severity.MEDIUM,
      description: 'Django CORS allowing all origins.',
      recommendation: 'Set CORS_ALLOWED_ORIGINS with specific domains.',
      cwe: 'CWE-942',
    },
    {
      pattern: /CORS\s*\(\s*app\s*,\s*(?:origins\s*=\s*["']\*["']|supports_credentials\s*=\s*True)/gi,
      name: 'Flask CORS Misconfiguration',
      severity: Severity.MEDIUM,
      description: 'Flask-CORS with wildcard or credentials misconfiguration.',
      recommendation: 'Specify origins and avoid credentials with wildcards.',
      cwe: 'CWE-942',
    },
    {
      pattern: /Access-Control-Allow-Origin['"]\s*:\s*request\.headers\.get\s*\(\s*['"]Origin['"]/gi,
      name: 'CORS Origin Reflection',
      severity: Severity.HIGH,
      description: 'Reflecting request origin in CORS header.',
      recommendation: 'Validate origin against whitelist.',
      cwe: 'CWE-942',
    },
  ],

  java: [
    {
      pattern: /@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']\s*\)/gi,
      name: 'Spring CORS Wildcard',
      severity: Severity.MEDIUM,
      description: 'Spring @CrossOrigin with wildcard origin.',
      recommendation: 'Specify allowed origins in annotation.',
      cwe: 'CWE-942',
    },
    {
      pattern: /allowedOrigins\s*\(\s*["']\*["']\s*\)/gi,
      name: 'Spring CORS Allow All Origins',
      severity: Severity.MEDIUM,
      description: 'Spring CORS configuration allowing all origins.',
      recommendation: 'List specific allowed origins.',
      cwe: 'CWE-942',
    },
    {
      pattern: /allowCredentials\s*\(\s*true\s*\).*allowedOrigins\s*\(\s*["']\*["']/gi,
      name: 'Spring CORS Credentials with Wildcard',
      severity: Severity.HIGH,
      description: 'Credentials with wildcard origin is blocked but misconfigured.',
      recommendation: 'Use specific origins with credentials.',
      cwe: 'CWE-942',
    },
  ],

  csharp: [
    {
      pattern: /\.AllowAnyOrigin\s*\(\s*\)/gi,
      name: 'ASP.NET CORS Allow Any Origin',
      severity: Severity.MEDIUM,
      description: 'CORS policy allowing any origin.',
      recommendation: 'Use WithOrigins() to specify allowed origins.',
      cwe: 'CWE-942',
    },
    {
      pattern: /\.AllowCredentials\s*\(\s*\).*\.AllowAnyOrigin\s*\(\s*\)/gi,
      name: 'ASP.NET CORS Credentials with Any Origin',
      severity: Severity.HIGH,
      description: 'Credentials cannot be used with AllowAnyOrigin.',
      recommendation: 'Specify origins explicitly when using credentials.',
      cwe: 'CWE-942',
    },
    {
      pattern: /SetIsOriginAllowed\s*\(\s*(?:_\s*=>|origin\s*=>)\s*true\s*\)/gi,
      name: 'ASP.NET CORS Allow All Origins',
      severity: Severity.MEDIUM,
      description: 'Custom origin validation always returns true.',
      recommendation: 'Validate origins against whitelist.',
      cwe: 'CWE-942',
    },
  ],

  php: [
    {
      pattern: /header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]/gi,
      name: 'PHP CORS Wildcard',
      severity: Severity.MEDIUM,
      description: 'CORS header with wildcard origin.',
      recommendation: 'Set specific allowed origins.',
      cwe: 'CWE-942',
    },
    {
      pattern: /header\s*\(\s*['"]Access-Control-Allow-Origin:\s*['"]\s*\.\s*\$_SERVER\s*\[\s*['"]HTTP_ORIGIN['"]/gi,
      name: 'PHP CORS Origin Reflection',
      severity: Severity.HIGH,
      description: 'Reflecting HTTP_ORIGIN header.',
      recommendation: 'Validate origin against whitelist before reflecting.',
      cwe: 'CWE-942',
    },
  ],
};

/**
 * Open Redirect patterns by language
 */
export const OPEN_REDIRECT_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /(?:window\.)?location(?:\.href)?\s*=\s*(?:req\.|user\.|params\.|query\.)/gi,
      name: 'Redirección Abierta (location)',
      severity: Severity.MEDIUM,
      description: 'Redirección controlada por el usuario mediante la asignación de location.',
      recommendation: 'Valide las URLs de redirección contra una lista blanca.',
      cwe: 'CWE-601',
    },
    {
      pattern: /res\.redirect\s*\(\s*(?:req\.query|req\.body|req\.params)/gi,
      name: 'Redirección Abierta (Express)',
      severity: Severity.MEDIUM,
      description: 'Redirección de Express con URL controlada por el usuario.',
      recommendation: 'Valide que el objetivo de la redirección sea del mismo origen o esté en la lista blanca.',
      cwe: 'CWE-601',
    },
    {
      pattern: /window\.open\s*\(\s*(?:req\.|user\.|.*\+)/gi,
      name: 'Redirección Abierta (window.open)',
      severity: Severity.MEDIUM,
      description: 'URL controlada por el usuario en window.open.',
      recommendation: 'Valide las URLs antes de abrir nuevas ventanas.',
      cwe: 'CWE-601',
    },
    {
      pattern: /return_url|redirect_url|next|continue|goto|dest(?:ination)?|redir/gi,
      name: 'Redirección Abierta (nombre de parámetro)',
      severity: Severity.LOW,
      description: 'El nombre del parámetro sugiere funcionalidad de redirección.',
      recommendation: 'Valide los parámetros de redirección meticulosamente.',
      cwe: 'CWE-601',
    },
  ],

  python: [
    {
      pattern: /redirect\s*\(\s*(?:request\.(?:GET|POST|args)|.*\+)/gi,
      name: 'Open Redirect (redirect)',
      severity: Severity.MEDIUM,
      description: 'User-controlled redirect URL.',
      recommendation: 'Use url_has_allowed_host_and_scheme() for validation.',
      cwe: 'CWE-601',
    },
    {
      pattern: /HttpResponseRedirect\s*\(\s*(?:request\.|.*\+)/gi,
      name: 'Open Redirect (Django)',
      severity: Severity.MEDIUM,
      description: 'Django redirect with user input.',
      recommendation: 'Validate URL with is_safe_url() or whitelist.',
      cwe: 'CWE-601',
    },
    {
      pattern: /flask\.redirect\s*\(\s*(?:request\.args|.*\+)/gi,
      name: 'Open Redirect (Flask)',
      severity: Severity.MEDIUM,
      description: 'Flask redirect with user-controlled URL.',
      recommendation: 'Validate URL before redirecting.',
      cwe: 'CWE-601',
    },
  ],

  java: [
    {
      pattern: /response\.sendRedirect\s*\(\s*(?:request\.getParameter|.*\+)/gi,
      name: 'Open Redirect (sendRedirect)',
      severity: Severity.MEDIUM,
      description: 'User-controlled redirect in sendRedirect.',
      recommendation: 'Validate URL against allowed domains.',
      cwe: 'CWE-601',
    },
    {
      pattern: /return\s+["']redirect:\s*["']\s*\+/gi,
      name: 'Open Redirect (Spring)',
      severity: Severity.MEDIUM,
      description: 'Spring redirect view with concatenation.',
      recommendation: 'Validate redirect target before returning.',
      cwe: 'CWE-601',
    },
  ],

  php: [
    {
      pattern: /header\s*\(\s*['"]Location:\s*['"]?\s*\.\s*\$_(?:GET|POST|REQUEST)/gi,
      name: 'Open Redirect (header)',
      severity: Severity.MEDIUM,
      description: 'User-controlled Location header.',
      recommendation: 'Validate redirect URL against whitelist.',
      cwe: 'CWE-601',
    },
    {
      pattern: /wp_redirect\s*\(\s*\$_(?:GET|POST|REQUEST)/gi,
      name: 'Open Redirect (WordPress)',
      severity: Severity.MEDIUM,
      description: 'WordPress redirect with user input.',
      recommendation: 'Use wp_safe_redirect() instead.',
      cwe: 'CWE-601',
    },
  ],

  csharp: [
    {
      pattern: /(?:Redirect|RedirectToAction)\s*\(\s*(?:Request\.|.*\+)/gi,
      name: 'Open Redirect (Redirect)',
      severity: Severity.MEDIUM,
      description: 'User-controlled redirect URL.',
      recommendation: 'Use LocalRedirect() or validate with Url.IsLocalUrl().',
      cwe: 'CWE-601',
    },
    {
      pattern: /Response\.Redirect\s*\(\s*(?:Request\.QueryString|.*\+)/gi,
      name: 'Open Redirect (Response.Redirect)',
      severity: Severity.MEDIUM,
      description: 'Redirect with query string parameter.',
      recommendation: 'Validate URL is local or whitelisted.',
      cwe: 'CWE-601',
    },
  ],
};

/**
 * Mass Assignment patterns by language
 */
export const MASS_ASSIGNMENT_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)/gi,
      name: 'Mass Assignment (Object.assign)',
      severity: Severity.HIGH,
      description: 'Entire request body assigned to object.',
      recommendation: 'Pick specific allowed properties.',
      cwe: 'CWE-915',
    },
    {
      pattern: /\{\s*\.\.\.req\.body\s*\}/gi,
      name: 'Mass Assignment (spread)',
      severity: Severity.HIGH,
      description: 'Request body spread into object.',
      recommendation: 'Destructure only allowed properties.',
      cwe: 'CWE-915',
    },
    {
      pattern: /Model\.create\s*\(\s*req\.body\s*\)/gi,
      name: 'Mass Assignment (Mongoose create)',
      severity: Severity.HIGH,
      description: 'Request body directly to Model.create.',
      recommendation: 'Whitelist properties or use schema validation.',
      cwe: 'CWE-915',
    },
    {
      pattern: /\.update\s*\(\s*\{[^}]*\$set\s*:\s*req\.body/gi,
      name: 'Mass Assignment (MongoDB update)',
      severity: Severity.HIGH,
      description: 'Request body in MongoDB $set operation.',
      recommendation: 'Validate and whitelist update fields.',
      cwe: 'CWE-915',
    },
  ],

  python: [
    {
      pattern: /\*\*request\.(?:data|POST|json)/gi,
      name: 'Mass Assignment (kwargs)',
      severity: Severity.HIGH,
      description: 'Request data unpacked as keyword arguments.',
      recommendation: 'Explicitly list allowed parameters.',
      cwe: 'CWE-915',
    },
    {
      pattern: /\.objects\.create\s*\(\s*\*\*request/gi,
      name: 'Mass Assignment (Django create)',
      severity: Severity.HIGH,
      description: 'Request data directly to model create.',
      recommendation: 'Use serializers with explicit fields.',
      cwe: 'CWE-915',
    },
    {
      pattern: /for\s+\w+\s*,\s*\w+\s+in\s+request\.(?:POST|data)\.items\(\):/gi,
      name: 'Mass Assignment (loop)',
      severity: Severity.MEDIUM,
      description: 'Iterating over request data for assignment.',
      recommendation: 'Whitelist allowed fields.',
      cwe: 'CWE-915',
    },
    {
      pattern: /setattr\s*\(\s*\w+\s*,\s*\w+\s*,\s*request/gi,
      name: 'Mass Assignment (setattr)',
      severity: Severity.HIGH,
      description: 'Dynamic attribute setting from request.',
      recommendation: 'Validate attribute names against whitelist.',
      cwe: 'CWE-915',
    },
  ],

  java: [
    {
      pattern: /BeanUtils\.copyProperties\s*\(\s*request/gi,
      name: 'Mass Assignment (BeanUtils)',
      severity: Severity.HIGH,
      description: 'Request properties copied to bean.',
      recommendation: 'Use DTO pattern with explicit mapping.',
      cwe: 'CWE-915',
    },
    {
      pattern: /@ModelAttribute\s*(?!\s*\([^)]*binding\s*=\s*false)/gi,
      name: 'Mass Assignment (Spring ModelAttribute)',
      severity: Severity.MEDIUM,
      description: 'Spring auto-binding without protection.',
      recommendation: 'Use @InitBinder to whitelist fields.',
      cwe: 'CWE-915',
    },
    {
      pattern: /ObjectMapper.*readValue\s*\([^)]*request/gi,
      name: 'Mass Assignment (Jackson)',
      severity: Severity.MEDIUM,
      description: 'Request body deserialized to object.',
      recommendation: 'Use DTOs and @JsonIgnoreProperties.',
      cwe: 'CWE-915',
    },
  ],

  php: [
    {
      pattern: /\$model->fill\s*\(\s*\$request->all\(\)\s*\)/gi,
      name: 'Mass Assignment (Laravel fill)',
      severity: Severity.HIGH,
      description: 'All request data passed to model fill.',
      recommendation: 'Use $request->only() with allowed fields.',
      cwe: 'CWE-915',
    },
    {
      pattern: /Model::create\s*\(\s*\$_(?:POST|REQUEST)/gi,
      name: 'Mass Assignment (create)',
      severity: Severity.HIGH,
      description: 'Superglobal directly to model create.',
      recommendation: 'Define $fillable or use $request->validated().',
      cwe: 'CWE-915',
    },
    {
      pattern: /->update\s*\(\s*\$request->all\(\)\s*\)/gi,
      name: 'Mass Assignment (update)',
      severity: Severity.HIGH,
      description: 'All request data in update.',
      recommendation: 'Use $request->only() with specific fields.',
      cwe: 'CWE-915',
    },
  ],

  csharp: [
    {
      pattern: /TryUpdateModel(?:Async)?\s*\(\s*\w+\s*\)/gi,
      name: 'Mass Assignment (TryUpdateModel)',
      severity: Severity.MEDIUM,
      description: 'Model binding without property whitelist.',
      recommendation: 'Use overload with includeProperties parameter.',
      cwe: 'CWE-915',
    },
    {
      pattern: /\[Bind\s*\(\s*(?!.*Exclude)(?!.*Include)/gi,
      name: 'Mass Assignment (Bind attribute)',
      severity: Severity.MEDIUM,
      description: 'Bind attribute without Include/Exclude.',
      recommendation: 'Specify Include with allowed properties.',
      cwe: 'CWE-915',
    },
    {
      pattern: /UpdateModel\s*\(\s*\w+\s*,\s*Request\.Form\s*\)/gi,
      name: 'Mass Assignment (UpdateModel)',
      severity: Severity.HIGH,
      description: 'Form data bound to model.',
      recommendation: 'Use DTO pattern or [Bind(Include=...)].',
      cwe: 'CWE-915',
    },
  ],
};

/**
 * CSRF (Cross-Site Request Forgery) patterns by language
 */
export const CSRF_PATTERNS: Record<string, Array<{
  pattern: RegExp;
  name: string;
  severity: Severity;
  description: string;
  recommendation: string;
  cwe: string;
}>> = {
  javascript: [
    {
      pattern: /app\.(?:post|put|patch|delete)\s*\([^)]*(?!csrf|csrfProtection|csurf)/gi,
      name: 'CSRF Missing Protection (Express)',
      severity: Severity.MEDIUM,
      description: 'State-changing endpoint without CSRF protection.',
      recommendation: 'Use csurf middleware for CSRF protection.',
      cwe: 'CWE-352',
    },
    {
      pattern: /csrf\s*:\s*false/gi,
      name: 'CSRF Disabled',
      severity: Severity.HIGH,
      description: 'CSRF protection explicitly disabled.',
      recommendation: 'Enable CSRF protection for state-changing requests.',
      cwe: 'CWE-352',
    },
    {
      pattern: /SameSite\s*[=:]\s*["']?None["']?(?!.*Secure)/gi,
      name: 'Cookie SameSite None without Secure',
      severity: Severity.HIGH,
      description: 'SameSite=None requires Secure flag.',
      recommendation: 'Add Secure flag when using SameSite=None.',
      cwe: 'CWE-352',
    },
  ],

  python: [
    {
      pattern: /@csrf_exempt/gi,
      name: 'CSRF Exempt (Django)',
      severity: Severity.MEDIUM,
      description: 'CSRF protection disabled for view.',
      recommendation: 'Remove @csrf_exempt or implement alternative protection.',
      cwe: 'CWE-352',
    },
    {
      pattern: /CSRF_ENABLED\s*=\s*False/gi,
      name: 'CSRF Disabled (Flask)',
      severity: Severity.HIGH,
      description: 'CSRF protection disabled in Flask.',
      recommendation: 'Enable CSRF_ENABLED in configuration.',
      cwe: 'CWE-352',
    },
    {
      pattern: /WTF_CSRF_ENABLED\s*=\s*False/gi,
      name: 'CSRF Disabled (Flask-WTF)',
      severity: Severity.HIGH,
      description: 'Flask-WTF CSRF protection disabled.',
      recommendation: 'Enable WTF_CSRF_ENABLED.',
      cwe: 'CWE-352',
    },
  ],

  java: [
    {
      pattern: /\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)/gi,
      name: 'CSRF Disabled (Spring)',
      severity: Severity.HIGH,
      description: 'Spring Security CSRF protection disabled.',
      recommendation: 'Enable CSRF or use stateless token validation.',
      cwe: 'CWE-352',
    },
    {
      pattern: /http\.csrf\s*\(\s*csrf\s*->\s*csrf\.disable\s*\(\s*\)\s*\)/gi,
      name: 'CSRF Disabled (Spring Lambda)',
      severity: Severity.HIGH,
      description: 'CSRF disabled in Spring Security config.',
      recommendation: 'Configure CSRF protection appropriately.',
      cwe: 'CWE-352',
    },
  ],

  php: [
    {
      pattern: /VerifyCsrfToken.*\$except\s*=\s*\[/gi,
      name: 'CSRF Exception (Laravel)',
      severity: Severity.MEDIUM,
      description: 'Routes excluded from CSRF verification.',
      recommendation: 'Minimize CSRF exceptions, protect all state-changing routes.',
      cwe: 'CWE-352',
    },
    {
      pattern: /CSRF.*=.*false|disable.*csrf/gi,
      name: 'CSRF Disabled',
      severity: Severity.HIGH,
      description: 'CSRF protection disabled.',
      recommendation: 'Enable CSRF protection for all forms.',
      cwe: 'CWE-352',
    },
  ],

  csharp: [
    {
      pattern: /\[IgnoreAntiforgeryToken\]/gi,
      name: 'CSRF Ignored (ASP.NET)',
      severity: Severity.MEDIUM,
      description: 'Antiforgery token validation disabled.',
      recommendation: 'Use [ValidateAntiForgeryToken] instead.',
      cwe: 'CWE-352',
    },
    {
      pattern: /options\.SuppressXFrameOptionsHeader\s*=\s*true/gi,
      name: 'X-Frame-Options Suppressed',
      severity: Severity.MEDIUM,
      description: 'Clickjacking protection disabled.',
      recommendation: 'Keep X-Frame-Options enabled.',
      cwe: 'CWE-1021',
    },
    {
      pattern: /\[HttpPost\](?!.*\[ValidateAntiForgeryToken\])/gi,
      name: 'CSRF Missing Token Validation',
      severity: Severity.MEDIUM,
      description: 'POST action without antiforgery validation.',
      recommendation: 'Add [ValidateAntiForgeryToken] attribute.',
      cwe: 'CWE-352',
    },
  ],
};

/**
 * Get security standards for modern web vulnerabilities
 */
export function getModernSecurityStandards(category: string): SecurityStandard[] {
  const standards: Record<string, SecurityStandard[]> = {
    'WebSocket': [
      {
        name: 'CWE',
        id: 'CWE-940',
        title: 'Improper Verification of Source of a Communication Channel',
        description: 'The software does not properly verify the source of a communication channel.',
        url: 'https://cwe.mitre.org/data/definitions/940.html'
      },
      {
        name: 'OWASP',
        id: 'A07:2021',
        title: 'Identification and Authentication Failures',
        description: 'WebSocket connections require proper authentication and origin validation.',
        url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
      }
    ],
    'OAuth2': [
      {
        name: 'CWE',
        id: 'CWE-287',
        title: 'Improper Authentication',
        description: 'OAuth2 misconfigurations can lead to authentication bypass.',
        url: 'https://cwe.mitre.org/data/definitions/287.html'
      },
      {
        name: 'OWASP',
        id: 'A07:2021',
        title: 'Identification and Authentication Failures',
        description: 'OAuth2 implementations must follow security best practices.',
        url: 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'
      }
    ],
    'CORS': [
      {
        name: 'CWE',
        id: 'CWE-942',
        title: 'Permissive Cross-domain Policy with Untrusted Domains',
        description: 'CORS policy allows access from untrusted origins.',
        url: 'https://cwe.mitre.org/data/definitions/942.html'
      },
      {
        name: 'OWASP',
        id: 'A01:2021',
        title: 'Broken Access Control',
        description: 'CORS misconfiguration is a form of broken access control.',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      }
    ],
    'Open Redirect': [
      {
        name: 'CWE',
        id: 'CWE-601',
        title: 'URL Redirection to Untrusted Site',
        description: 'Redirect based on user input without validation.',
        url: 'https://cwe.mitre.org/data/definitions/601.html'
      },
      {
        name: 'OWASP',
        id: 'A01:2021',
        title: 'Broken Access Control',
        description: 'Open redirects enable phishing attacks.',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      }
    ],
    'Mass Assignment': [
      {
        name: 'CWE',
        id: 'CWE-915',
        title: 'Improperly Controlled Modification of Dynamically-Determined Object Attributes',
        description: 'Object attributes modified based on external input.',
        url: 'https://cwe.mitre.org/data/definitions/915.html'
      },
      {
        name: 'OWASP',
        id: 'A04:2021',
        title: 'Insecure Design',
        description: 'Mass assignment is a design-level vulnerability.',
        url: 'https://owasp.org/Top10/A04_2021-Insecure_Design/'
      }
    ],
    'CSRF': [
      {
        name: 'CWE',
        id: 'CWE-352',
        title: 'Cross-Site Request Forgery (CSRF)',
        description: 'State-changing requests without proper validation.',
        url: 'https://cwe.mitre.org/data/definitions/352.html'
      },
      {
        name: 'OWASP',
        id: 'A01:2021',
        title: 'Broken Access Control',
        description: 'CSRF allows unauthorized actions on behalf of users.',
        url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/'
      }
    ],
  };

  return standards[category] || [];
}
