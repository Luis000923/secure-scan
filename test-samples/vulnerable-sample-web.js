/**
 * Vulnerable Web Application Sample
 * Contains intentional security vulnerabilities for testing Secure-Scan.
 * DO NOT use in production.
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// ============================================================================
// OPEN REDIRECT VULNERABILITIES
// ============================================================================

// VUL-REDIRECT-001: res.redirect with req.query (open redirect)
app.get('/login-redirect', (req, res) => {
    const returnUrl = req.query.returnUrl;
    res.redirect(returnUrl); // VULNERABLE: unvalidated redirect
});

// VUL-REDIRECT-001: Location header with user input
app.get('/goto', (req, res) => {
    const destination = req.query.url;
    res.setHeader('Location', destination); // VULNERABLE
    res.status(302).end();
});

// ============================================================================
// JWT WEAKNESS VULNERABILITIES
// ============================================================================

// VUL-JWT-001: Algorithm set to "none"
const unsafePayload = jwt.verify(token, '', {
    algorithms: ['none'] // VULNERABLE: alg=none attack
});

// VUL-JWT-002: Hardcoded JWT secret
const token1 = jwt.sign({ userId: 1 }, 'my-super-secret-jwt-key-12345', {
    expiresIn: '1h'
});

// VUL-JWT-002: Another hardcoded secret
const JWT_SECRET = 'hardcoded-secret-key-for-jwt-signing';

// VUL-JWT-003: jwt.sign without expiresIn
const permanentToken = jwt.sign({ admin: true }, process.env.JWT_SECRET);

// ============================================================================
// SESSION / COOKIE VULNERABILITIES
// ============================================================================

// VUL-SESSION-001: httpOnly explicitly false
res.cookie('session', token, {
    httpOnly: false, // VULNERABLE: accessible via JavaScript
    secure: true,
    sameSite: 'strict'
});

// VUL-SESSION-002: secure explicitly false
res.cookie('auth', token, {
    httpOnly: true,
    secure: false, // VULNERABLE: sent over HTTP
    sameSite: 'lax'
});

// VUL-SESSION-003: SameSite=None without secure
res.cookie('tracking', 'abc', {
    sameSite: 'none', // VULNERABLE: SameSite=None requires Secure
    httpOnly: true
});

// ============================================================================
// EXISTING PATTERNS THAT SHOULD STILL TRIGGER
// ============================================================================

// SQL injection
const userId = req.params.id;
db.query('SELECT * FROM users WHERE id = ' + userId);

// XSS
element.innerHTML = userInput;

// Command injection
const exec = require('child_process').exec;
exec(req.body.command);

// ============================================================================
// FALSE POSITIVE EXAMPLES (SHOULD NOT TRIGGER)
// ============================================================================

// Comment: eval('test') - this is a comment, should not trigger

// Type definition, should not trigger credential alert
// type PasswordForm = { password: string; confirmPassword: string };

// Placeholder, should not trigger credential alert
const config = { password: 'changeme' };

// DOMPurify sanitized innerHTML, should not trigger XSS
element.innerHTML = DOMPurify.sanitize(userHtml);

// Static string innerHTML, should not trigger XSS
loader.innerHTML = '<div class="spinner"></div>';

module.exports = app;
