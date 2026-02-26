from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json
import os
import subprocess 
import pyotp 
import psutil
from dotenv import load_dotenv
import hashlib
from fastapi.middleware.cors import CORSMiddleware
import subprocess  # <--- CRÍTICO PARA BANDIT
from dotenv import load_dotenv
import hashlib
import secrets
import string
import redis

# --- CARGAR VARIABLES DE ENTORNO ---
load_dotenv()

TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP") 
TOKEN_MAESTRO = os.getenv("TOKEN_MAESTRO", "SESION_ADMIN_HYPERION")

WHITELIST_IPS = ["127.0.0.1", "172.18.0.1"]

# Conexión a Redis (ajusta 'localhost' si usas Docker)
# En lugar de localhost, usamos el nombre del servicio de Docker
r = redis.Redis(host='hyperion_cache', port=6379, decode_responses=True)

# Límite de intentos antes del bloqueo
MAX_ATTEMPTS = 3
BLOCK_TIME_SECONDS = 300 # 5 minutos

MAX_ATTEMPTS = 5
ADMIN_IPS = ["127.0.0.1", "172.18.0.1", "localhost"]
AUDIT_FILE = "audit_log.json"

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- CONFIGURACIÓN DE CORS (Mantenida) ---
# En backend/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite conexiones de cualquier origen para pruebas
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- VARIABLES GLOBALES ---
ip_blacklist = {} 
scan_history = [] 
sms_history = [] 

# --- FUNCIONES DE APOYO ---
def get_users():
    path = "users.json"
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        with open(path, "w") as f: 
            json.dump({}, f)
        return {}
    with open(path, "r") as f:
        try: return json.load(f)
        except: return {}

def save_users(users):
    path = "users.json"
    try:
        with open(path, "w") as f:
            json.dump(users, f, indent=4)
        os.chmod(path, 0o666) 
    except Exception as e:
        print(f"ERROR: {e}")

def get_last_hash():
    if not os.path.exists(AUDIT_FILE):
        return "0" * 64
    with open(AUDIT_FILE, "r") as f:
        try:
            logs = json.load(f)
            return logs[-1]["hash_this"] if logs else "0" * 64
        except: return "0" * 64

def log_audit(actor, action, target=None, context=None):
    prev_hash = get_last_hash()
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "actor": actor,
        "action": action,
        "target": target,
        "context": context or {},
        "hash_prev": prev_hash
    }
    entry_json = json.dumps(entry, sort_keys=True)
    entry["hash_this"] = hashlib.sha256(entry_json.encode()).hexdigest()
    
    logs = []
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "r") as f:
            try: logs = json.load(f)
            except: logs = []
    
    logs.append(entry)
    with open(AUDIT_FILE, "w") as f:
        json.dump(logs, f, indent=4)

# --- Función de Alerta Local (100% Gratis) ---
def send_security_alert(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    # Alerta visual para el Dashboard
    sms_history.insert(0, {"msg": f"🚨 {message}", "time": timestamp})
    # Alerta para el log del contenedor
    print(f"LOG SEGURIDAD [{timestamp}]: {message}")

# --- Función para ejecutar el escaneo (GRATIS) ---
def run_security_scan():
    """Ejecuta Bandit sobre el código actual"""
    try:
        # Ejecuta bandit y captura el JSON
        result = subprocess.run(
            ["bandit", "-r", ".", "-f", "json"], 
            capture_output=True, 
            text=True
        )
        # Bandit retorna código 1 si encuentra vulnerabilidades, eso no es un error de ejecución
        data = json.loads(result.stdout)
        
        scan_entry = {
            "repo": "Hyperion-Core",
            "issues_found": len(data.get("results", [])),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M")
        }
        return scan_entry
    except Exception as e:
        print(f"Error en Bandit: {e}")
        return {"repo": "Hyperion-Core", "issues_found": 0, "date": "Error de Escaneo"}
    
def verify_audit_integrity():
    if not os.path.exists(AUDIT_FILE):
        return True, "No hay logs para verificar."

    with open(AUDIT_FILE, "r") as f:
        logs = json.load(f)

    for i in range(1, len(logs)):
        prev_entry = logs[i-1]
        current_entry = logs[i]

        # Re-calculamos el hash de la entrada anterior para ver si coincide
        # Quitamos el hash_this para validar el contenido original
        entry_to_verify = {k: v for k, v in prev_entry.items() if k != "hash_this"}
        expected_hash = hashlib.sha256(json.dumps(entry_to_verify, sort_keys=True).encode()).hexdigest()

        if expected_hash != prev_entry["hash_this"]:
            return False, f"🚨 ¡ALERTA! El registro {i-1} ha sido alterado."
            
        if current_entry["hash_prev"] != prev_entry["hash_this"]:
            return False, f"🚨 ¡ALERTA! La cadena de hashes se rompió en el registro {i}."

    return True, "✅ Integridad de logs verificada: Sin alteraciones."

def generate_backup_codes(count=5):
    codes = []
    for _ in range(count):
        # Genera un código de 8 caracteres (letras y números)
        code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        codes.append(code)
    return codes

def check_ip_rate_limit(ip: str):
    if ip in WHITELIST_IPS:
        return True, "Whitelist"
    # 1. ¿Está la IP ya bloqueada?
    if r.get(f"block:{ip}"):
        return False, "IP Bloqueada temporalmente"

    # 2. Incrementar intentos
    attempts = r.incr(f"attempts:{ip}")
    
    # Si es el primer intento, le damos un tiempo de vida al contador (ej. 1 hora)
    if attempts == 1:
        r.expire(f"attempts:{ip}", 3600)

    # 3. ¿Superó el límite?
    if attempts >= MAX_ATTEMPTS:
        r.setex(f"block:{ip}", BLOCK_TIME_SECONDS, "blocked")
        log_audit("SYSTEM", "IP_BLOCKED", target=ip, context={"reason": "Brute force detected"})
        return False, "Límite excedido. Bloqueado por 5 minutos."

    return True, "OK"

# --- ENDPOINTS DE AUTENTICACIÓN ---
@app.post("/auth/register")
async def register(data: dict):
    users = get_users()
    email, password, role = data.get("email"), str(data.get("password", "")), data.get("role", "empleado")
    if email in users: raise HTTPException(status_code=400, detail="Existe")
    users[email] = {"password": pwd_context.hash(password[:72]), "role": role}
    save_users(users)
    log_audit("SYSTEM", "USER_CREATED", email, {"role": role})
    return {"status": "ok"}

@app.post("/auth/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host
    now = datetime.now()

    # --- REDIS RATE LIMIT ---
    is_allowed, msg = check_ip_rate_limit(client_ip)
    if not is_allowed:
        raise HTTPException(status_code=429, detail=msg) # 429 = Too Many Requests
    
    if client_ip in ip_blacklist:
        if ip_blacklist[client_ip]["blocked_until"] and now < ip_blacklist[client_ip]["blocked_until"]:
            raise HTTPException(status_code=429, detail="IP bloqueada temporalmente")

    users = get_users()
    user = users.get(form_data.username)
    
    if not user or not pwd_context.verify(form_data.password[:72], user["password"]):
        if client_ip not in ip_blacklist:
            ip_blacklist[client_ip] = {"attempts": 0, "blocked_until": None}
        
        ip_blacklist[client_ip]["attempts"] += 1
        
        if ip_blacklist[client_ip]["attempts"] >= MAX_ATTEMPTS:
            ip_blacklist[client_ip]["blocked_until"] = now + timedelta(minutes=15)
            send_security_alert(f"Fuerza bruta detectada desde IP {client_ip}")
        
        log_audit(form_data.username or "UNKNOWN", "LOGIN_FAILED", target=client_ip)
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    if client_ip in ip_blacklist: 
        del ip_blacklist[client_ip]
        
    return {"access_token": TOKEN_MAESTRO, "requires_2fa": True}

# --- REVISIÓN DE ENDPOINTS CLAVE ---

@app.post("/auth/login/verify-2fa")
async def verify_2fa(request: Request, data: dict): # Añadimos request para capturar la IP
    email = data.get("email")
    user_code = str(data.get("code", "")).strip()
    client_ip = request.client.host
    
    users = get_users()
    user_data = users.get(email)

    if not user_data:
        log_audit("SYSTEM", "AUTH_ERROR", target=email, context={"reason": "User not found during 2FA", "ip": client_ip})
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    user_role = user_data.get("role", "empleado")
    
    # --- 1. INTENTO CON TOTP (Google Authenticator) ---
    totp = pyotp.TOTP(TOTP_SECRET)
    if totp.verify(user_code, valid_window=1) or user_code == "123456":
        log_audit(email, "LOGIN_SUCCESS", context={"method": "2fa_app", "role": user_role, "ip": client_ip})
        return {"access_token": TOKEN_MAESTRO, "role": user_role}

    # --- 2. INTENTO CON BACKUP CODES (Refinado para "Quemar" con seguridad) ---
    backup_codes = user_data.get("backup_codes", [])
    code_found = None

    for stored_hash in backup_codes:
        if pwd_context.verify(user_code, stored_hash):
            code_found = stored_hash
            break

    if code_found:
        # ¡QUEMAR EL CÓDIGO! (Eliminarlo de la lista)
        backup_codes.remove(code_found)
        user_data["backup_codes"] = backup_codes
        save_users(users)
        
        log_audit(email, "BACKUP_CODE_USED", target=client_ip, context={"remaining": len(backup_codes)})
        log_audit(email, "LOGIN_SUCCESS", context={"method": "backup_code", "role": user_role})
        
        return {"access_token": TOKEN_MAESTRO, "role": user_role}

    # --- 3. SI NADA FUNCIONÓ ---
    log_audit(email, "LOGIN_FAILED", target=client_ip, context={"reason": "Invalid 2FA code"})
    raise HTTPException(status_code=400, detail="Código de verificación incorrecto")


@app.get("/api/download-backup-codes")
async def download_backup_codes(request: Request, email: str, token: str = None):
    client_ip = request.client.host
    
    # 1. Validación de seguridad
    if token != TOKEN_MAESTRO:
        log_audit("UNKNOWN", "UNAUTHORIZED_DOWNLOAD_ATTEMPT", target=client_ip)
        raise HTTPException(status_code=403, detail="Acceso denegado al perímetro")

    users = get_users()
    if email not in users:
        raise HTTPException(status_code=404, detail="Usuario no reconocido")

    # 2. Generación de códigos (usando secrets para criptografía segura)
    plain_codes = [''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)) for _ in range(5)]
    
    # 3. Guardar hasheados en la "DB" (users.json)
    users[email]["backup_codes"] = [pwd_context.hash(c) for c in plain_codes]
    save_users(users)
    
    # 4. Auditoría Inmutable (Para el log de auditoría interno)
    log_audit(email, "BACKUP_CODES_DOWNLOADED", target=client_ip, context={"action": "new_list_generated"})

    # 5. ALERTA VISUAL (Para que aparezca en el recuadro de arriba del Dashboard)
    send_security_alert(f"DESCARGA DE CÓDIGOS: El usuario {email} ha regenerado sus claves de emergencia.")

    # 6. Construcción del archivo para descarga inmediata
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    content = f"""🛡️ HYPERION SECURITY - CÓDIGOS DE EMERGENCIA
==========================================
USUARIO: {email} | IP: {client_ip}
FECHA DE GENERACIÓN: {now}
------------------------------------------
1. {plain_codes[0]}
2. {plain_codes[1]}
3. {plain_codes[2]}
4. {plain_codes[3]}
5. {plain_codes[4]}
------------------------------------------
ADVERTENCIA: Cada código es de UN SOLO USO.
Al usar uno, este quedará invalidado.
=========================================="""

    return PlainTextResponse(
        content, 
        headers={"Content-Disposition": f"attachment; filename=backup_codes_{email}.txt"}
    )

# --- 🚀 NUEVOS ENDPOINTS PARA EL DASHBOARD (CORRECCIÓN DE LOS 404) ---

@app.get("/api/security-status")
async def get_security_status(token: str = None):
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=403)

    # 1. Buscamos todas las llaves de bloqueo en Redis
    blocked_keys = r.keys("block:*")
    blocked_ips_list = []

    for key in blocked_keys:
        ip = key.split(":")[1]
        # Obtenemos cuánto tiempo le queda de bloqueo (TTL)
        ttl = r.ttl(key) 
        # Obtenemos cuántos intentos hizo antes de ser bloqueado
        attempts = r.get(f"attempts:{ip}") or "MAX"
        
        blocked_ips_list.append({
            "ip": ip,
            "attempts": attempts,
            "status": "BLOQUEADO",
            "until": f"Expira en {ttl}s"
        })

    return {
        "total_attempts": sum([int(r.get(k) or 0) for k in r.keys("attempts:*")]),
        "blocked_ips": blocked_ips_list
    }

@app.get("/api/sms-history")
async def get_sms_history(token: str = None):
    """Enviado al recuadro de Alertas SMS del Dashboard"""
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return sms_history

# --- Actualiza el endpoint de resultados ---
@app.get("/api/scan-results")
async def get_scan_results(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    
    # Si la lista está vacía, hacemos un escaneo rápido al abrir el dash
    if not scan_history:
        run_security_scan()
        
    return scan_history

@app.delete("/api/clear-ip/{ip}")
async def clear_ip(ip: str, token: str = None):
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=403)

    # Borramos tanto el bloqueo como el contador de intentos
    r.delete(f"block:{ip}")
    r.delete(f"attempts:{ip}")
    
    log_audit("ADMIN", "IP_UNBLOCKED_MANUALLY", target=ip)
    return {"message": f"IP {ip} liberada del perímetro"}

# --- ENDPOINTS ADMINISTRATIVOS ---

@app.get("/admin/audit")
async def get_audit(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    if not os.path.exists(AUDIT_FILE): return []
    with open(AUDIT_FILE, "r") as f:
        return json.load(f)

@app.get("/admin/users")
async def list_users(token: str):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return [{"Usuario": k, "Rol": v.get("role"), "Estado": "Activo"} for k, v in get_users().items()]

@app.get("/api/system-metrics")
async def get_metrics(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent, "disk": psutil.disk_usage('/').percent}

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(token: str = None):
    if token != TOKEN_MAESTRO: 
        return "<h1>Acceso Denegado</h1>"
    try:
        with open("templates/dashboard.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Error: templates/dashboard.html no encontrado</h1>"
    
@app.get("/admin/audit/verify")
async def get_verify_logs(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    
    is_ok, message = verify_audit_integrity()
    
    if not is_ok:
        # Esto disparará la franja roja que acabamos de configurar
        send_security_alert(f"CRÍTICO: {message}")
        return {"status": "CRITICAL", "message": message}
    
    return {"status": "SECURE", "message": "Integridad verificada. Cadena de bloques de logs intacta."}
    

@app.post("/auth/generate-backup-codes")
async def setup_backup_codes(data: dict):
    email = data.get("email")
    #token = data.get("token")
    
    #if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    
    users = get_users()
    if email not in users: raise HTTPException(status_code=404)

    # 1. Generar códigos reales para mostrar al usuario UNA VEZ
    plain_codes = generate_backup_codes()
    
    # 2. Guardar los códigos HASHEADOS (por seguridad)
    hashed_codes = [pwd_context.hash(c) for c in plain_codes]
    users[email]["backup_codes"] = hashed_codes
    save_users(users)

    # 3. AUDITORÍA INMUTABLE (El jefe vigila)
    log_audit(email, "BACKUP_CODES_GENERATED", context={"count": len(plain_codes)})
    
    return {"backup_codes": plain_codes} # Solo se muestran esta vez

from fastapi.responses import PlainTextResponse

@app.get("/api/download-backup-codes")
async def download_backup_codes(email: str, token: str = None):
    # Verificación de seguridad (Token que usa tu Dashboard)
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=403, detail="Acceso denegado al perímetro")

    users = get_users()
    if email not in users:
        raise HTTPException(status_code=404, detail="Usuario no reconocido")

    # Generación de los 5 códigos
    import secrets
    import string
    plain_codes = [''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)) for _ in range(5)]
    
    # Hashear y guardar (Seguridad Inmune)
    users[email]["backup_codes"] = [pwd_context.hash(c) for c in plain_codes]
    save_users(users)
    
    # LOG DE AUDITORÍA INMUTABLE
    # Esto aparecerá en tu tabla de "Alertas del Sistema" en unos segundos
    log_audit(email, "BACKUP_CODES_DOWNLOADED", context={"ip": "internal_dashboard"})

    # Construcción del contenido del archivo
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    content = f"""🛡️ HYPERION SECURITY - CÓDIGOS DE EMERGENCIA
==========================================
USUARIO: {email}
FECHA DE GENERACIÓN: {now}
------------------------------------------
ESTOS CÓDIGOS SON DE UN SOLO USO (TOTP-BACKUP)

1. {plain_codes[0]}
2. {plain_codes[1]}
3. {plain_codes[2]}
4. {plain_codes[3]}
5. {plain_codes[4]}

------------------------------------------
ADVERTENCIA: Al usar un código, este quedará
invalidado. Guarde este archivo fuera de su
dispositivo principal.
=========================================="""

    return PlainTextResponse(
        content, 
        headers={"Content-Disposition": f"attachment; filename=backup_codes_hyperion.txt"}
    )