<?php
/**
 * ⚠️ ARCHIVO DE PRUEBA - CONTIENE CÓDIGO VULNERABLE INTENCIONALMENTE
 * 
 * Este archivo contiene ejemplos de vulnerabilidades comunes en PHP
 * para probar el scanner. NO USAR EN PRODUCCIÓN.
 */

// ========================================
// INYECCIÓN SQL
// ========================================

// ❌ SQL Injection - Concatenación directa
function getUserById($id) {
    $conn = mysqli_connect("localhost", "root", "password", "app");
    $query = "SELECT * FROM users WHERE id = " . $id;
    $result = mysqli_query($conn, $query);
    return mysqli_fetch_assoc($result);
}

// ❌ SQL Injection - Sin sanitizar
function searchProducts($term) {
    global $pdo;
    $sql = "SELECT * FROM products WHERE name LIKE '%" . $_GET['term'] . "%'";
    return $pdo->query($sql)->fetchAll();
}

// ❌ SQL Injection en login
function login($username, $password) {
    global $mysqli;
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
    return mysqli_query($mysqli, $query);
}


// ========================================
// INYECCIÓN DE COMANDOS
// ========================================

// ❌ Command Injection - system()
if (isset($_GET['host'])) {
    $host = $_GET['host'];
    system("ping -c 4 " . $host);
}

// ❌ Command Injection - exec()
function runCommand($cmd) {
    return exec($cmd);
}

// ❌ Command Injection - shell_exec()
if (isset($_POST['command'])) {
    $output = shell_exec($_POST['command']);
    echo "<pre>$output</pre>";
}

// ❌ Command Injection - passthru()
function processFile($filename) {
    passthru("cat /var/uploads/" . $filename);
}

// ❌ Command Injection con backticks
function checkDns($domain) {
    return `nslookup $domain`;
}


// ========================================
// CROSS-SITE SCRIPTING (XSS)
// ========================================

// ❌ XSS Reflejado - Sin escapar
echo "<h1>Welcome, " . $_GET['name'] . "</h1>";

// ❌ XSS - echo directo
function displayMessage() {
    echo $_POST['message'];
}

// ❌ XSS - print
function showUser($user) {
    print "User: " . $user;
}


// ========================================
// INCLUSIÓN DE ARCHIVOS
// ========================================

// ❌ LFI - Local File Inclusion
$page = $_GET['page'];
include($page);

// ❌ LFI - include_once
if (isset($_GET['module'])) {
    include_once($_GET['module'] . '.php');
}

// ❌ RFI - Remote File Inclusion
$url = $_GET['url'];
require($url);

// ❌ require_once con entrada de usuario
function loadPlugin($plugin) {
    require_once("plugins/" . $plugin);
}


// ========================================
// DESERIALIZACIÓN INSEGURA
// ========================================

// ❌ unserialize con datos de usuario
if (isset($_COOKIE['data'])) {
    $data = unserialize($_COOKIE['data']);
    process($data);
}

// ❌ unserialize en POST
function loadUserPreferences() {
    return unserialize(base64_decode($_POST['prefs']));
}


// ========================================
// CREDENCIALES HARDCODEADAS
// ========================================

// ❌ Contraseñas en código
define('DB_PASSWORD', 'super_secret_password_123');
define('API_KEY', 'sk-prod-1234567890abcdef');

$config = array(
    'db_host' => 'localhost',
    'db_user' => 'admin',
    'db_pass' => 'admin123',  // ❌ Hardcoded
    'jwt_secret' => 'my-secret-jwt-key'
);

// ❌ Conexión con credenciales
$conn = new mysqli("localhost", "root", "root123", "database");


// ========================================
// CRIPTOGRAFÍA DÉBIL
// ========================================

// ❌ MD5 para contraseñas
function hashPassword($password) {
    return md5($password);
}

// ❌ SHA1 para seguridad
function hashToken($token) {
    return sha1($token);
}

// ❌ mcrypt (obsoleto)
function encryptData($data, $key) {
    return mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);
}


// ========================================
// PATH TRAVERSAL
// ========================================

// ❌ Lectura de archivo arbitrario
function readFile() {
    $file = $_GET['file'];
    return file_get_contents("./uploads/" . $file);
}

// ❌ Escritura de archivo arbitrario
function saveFile() {
    $path = $_POST['path'];
    $content = $_POST['content'];
    file_put_contents($path, $content);
}


// ========================================
// UPLOAD INSEGURO
// ========================================

// ❌ Upload sin validación
if (isset($_FILES['file'])) {
    $target = "uploads/" . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
}


// ========================================
// SSRF
// ========================================

// ❌ SSRF con file_get_contents
function fetchUrl() {
    $url = $_GET['url'];
    return file_get_contents($url);
}

// ❌ SSRF con curl
function curlFetch($url) {
    $ch = curl_init($_GET['target']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($ch);
}


// ========================================
// EVAL Y CÓDIGO DINÁMICO
// ========================================

// ❌ eval() - Extremadamente peligroso
if (isset($_GET['code'])) {
    eval($_GET['code']);
}

// ❌ preg_replace con modificador /e (obsoleto pero peligroso)
function processPattern($input) {
    return preg_replace('/(\w+)/e', 'strtoupper("$1")', $input);
}

// ❌ assert() con entrada de usuario
function checkCondition() {
    assert($_GET['condition']);
}

// ❌ create_function (obsoleto)
$func = create_function('$x', 'return $x * 2;');


// ========================================
// WEBSHELL / BACKDOOR
// ========================================

// ❌ Web Shell típica
if (isset($_REQUEST['cmd'])) {
    system($_REQUEST['cmd']);
}

// ❌ Backdoor oculto
@eval(@$_POST['code']);

// ❌ Backdoor con base64
if (isset($_GET['c'])) {
    eval(base64_decode($_GET['c']));
}

// ❌ Webshell ofuscada
$a = 'sys'; $b = 'tem'; $c = $a.$b; if(isset($_GET['x'])) $c($_GET['x']);


// ========================================
// INFORMACIÓN EXPUESTA
// ========================================

// ❌ phpinfo() expuesto
if ($_GET['debug'] == '1') {
    phpinfo();
}

// ❌ Error reporting en producción
error_reporting(E_ALL);
ini_set('display_errors', 1);


// ========================================
// OPEN REDIRECT
// ========================================

// ❌ Redirección abierta
if (isset($_GET['url'])) {
    header("Location: " . $_GET['url']);
}


// ========================================
// SESSION INSEGURA
// ========================================

// ❌ Session fixation
session_id($_GET['sessid']);
session_start();

// ❌ Cookies inseguras
setcookie('auth', $token, 0, '/', '', false, false);

?>
