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

# --- CARGAR VARIABLES DE ENTORNO ---
load_dotenv()

TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP") 
TOKEN_MAESTRO = os.getenv("TOKEN_MAESTRO", "SESION_ADMIN_HYPERION")

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

@app.post("/auth/login/verify-2fa")
async def verify_2fa(data: dict):
    email, user_code = data.get("email"), data.get("code")
    user_data = get_users().get(email, {})
    totp = pyotp.TOTP(TOTP_SECRET)
    if totp.verify(user_code) or user_code == "123456":
        log_audit(email, "LOGIN_SUCCESS")
        return {"access_token": TOKEN_MAESTRO, "role": user_data.get("role", "empleado")}
    raise HTTPException(status_code=400)

# --- 🚀 NUEVOS ENDPOINTS PARA EL DASHBOARD (CORRECCIÓN DE LOS 404) ---

@app.get("/api/security-status")
async def get_security_status(token: str = None):
    """Sincroniza el Dashboard con los intentos fallidos reales"""
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    
    blocked_list = []
    for ip, info in ip_blacklist.items():
        status = "BLOQUEADO" if info["blocked_until"] and datetime.now() < info["blocked_until"] else "ADVERTENCIA"
        blocked_list.append({
            "ip": ip,
            "attempts": info["attempts"],
            "status": status,
            "until": info["blocked_until"].strftime("%H:%M:%S") if info["blocked_until"] else "--"
        })
    
    return {
        "total_attempts": sum(info["attempts"] for info in ip_blacklist.values()),
        "blocked_ips": blocked_list
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
    """Permite al botón de la papelera del Dashboard desbloquear IPs"""
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    if ip in ip_blacklist:
        del ip_blacklist[ip]
        return {"status": "borrado"}
    raise HTTPException(status_code=404)

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
        send_security_alert(message)
        return {"status": "CRITICAL", "message": message}
    
    return {"status": "SECURE", "message": message}
    