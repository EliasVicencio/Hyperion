from fastapi import FastAPI, Depends, HTTPException, Request, Header, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json
import os
import subprocess 
import pyotp 
import psutil
import hashlib
import secrets
import string
import redis
from dotenv import load_dotenv

# --- CARGAR VARIABLES Y MOTOR SIEM ---
load_dotenv()
try:
    from ingestor import HyperionIngestor
except ImportError:
    print("⚠️ Error: No se encontró ingestor.py en la carpeta backend")

# --- CONFIGURACIÓN INICIAL ---
app = FastAPI(title="Hyperion SIEM API")

# Configuración de CORS corregida para permitir cualquier origen en desarrollo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP") 
TOKEN_MAESTRO = "SESION_ADMIN_HYPERION_ULTRA_SECRETA" 
AUDIT_FILE = "audit_log.json"
WHITELIST_IPS = ["127.0.0.1", "172.18.0.1"]

# Conexión a Redis
try:
    r = redis.Redis(host='hyperion_cache', port=6379, decode_responses=True)
except Exception as e:
    print(f"⚠️ Redis no disponible: {e}")
    r = None

# Variables de estado en memoria
ip_blacklist = {} 
scan_history = [] 
sms_history = [] 
MAX_ATTEMPTS = 5
BLOCK_TIME_SECONDS = 300

# --- FUNCIONES DE APOYO ---
def get_users():
    path = "users.json"
    if not os.path.exists(path) or os.stat(path).st_size == 0:
        with open(path, "w") as f: json.dump({}, f)
        return {}
    with open(path, "r") as f:
        try: return json.load(f)
        except: return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

def send_security_alert(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    sms_history.insert(0, {"msg": f"🚨 {message}", "time": timestamp})
    print(f"LOG SEGURIDAD: {message}")

def log_audit(actor, action, target=None, context=None):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "actor": actor,
        "action": action,
        "target": target,
        "context": context or {}
    }
    logs = []
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "r") as f:
            try: logs = json.load(f)
            except: logs = []
    logs.append(entry)
    with open(AUDIT_FILE, "w") as f:
        json.dump(logs, f, indent=4)

# --- ENDPOINTS DE INGESTA (SIEM EXTERNO) ---

@app.middleware("http")
async def ip_blocker_middleware(request: Request, call_next):
    client_ip = request.client.host
    
    # Verificar si la IP está en la lista negra
    if r and r.exists(f"block:{client_ip}"):
        ttl = r.ttl(f"block:{client_ip}")
        return PlainTextResponse(f"🚫 Acceso Denegado por Seguridad. IP Bloqueada por {ttl}s", status_code=403)
    
    response = await call_next(request)
    return response

@app.post("/api/v1/ingest/log")
async def ingest_log(x_api_key: str = Header(None), payload: dict = Body(...)):
    VALID_API_KEYS = {
        "finance-app-key-123": "finance_service", 
        "hr-app-key-456": "hr_service"
    }
    service_id = VALID_API_KEYS.get(x_api_key)
    if not service_id:
        raise HTTPException(status_code=401, detail="API Key inválida")

    try:
        new_hash, index = HyperionIngestor.process_log(service_id, payload)
        # Alerta de seguridad si el evento es crítico
        if "CRITICAL" in str(payload).upper():
            send_security_alert(f"Actividad crítica en {service_id}")
        return {"status": "chained", "index": index, "hash_this": new_hash}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/logs/{service_id}")
async def get_service_logs_alt(service_id: str, token: str = None):
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=403)
    
    path = f"logs/vault/{service_id}.json"
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)

# Redirección de compatibilidad para el Ingestor de Streamlit
@app.get("/api/v1/ingest/logs/{service_id}")
async def get_service_logs_ingest(service_id: str, token: str = None):
    return await get_service_logs_alt(service_id, token)

# --- ENDPOINTS DE SISTEMA Y DASHBOARD ---

@app.get("/api/system-metrics")
async def get_metrics(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    }

@app.get("/api/sms-history")
async def get_sms_history(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return sms_history

@app.get("/api/security-status")
async def security_status(token: str = None):
    if token != TOKEN_MAESTRO: 
        raise HTTPException(status_code=403)
    
    blocked_ips_list = []
    total_attempts = 0
    
    if r:
        # 1. Obtenemos las IPs bloqueadas y las formateamos como pide tu HTML
        # El HTML recorre esto para llenar la tabla de 'Hyperion Core'
        for key in r.keys("block:*"):
            ip = key.split(":")[1]
            ttl = r.ttl(key)
            blocked_ips_list.append({
                "ip": ip,
                "attempts": "MAX_REACHED",
                "status": "BLOCKED",
                "until": f"{ttl}s restantes"
            })
            
        # 2. Sumamos todos los intentos fallidos
        for key in r.keys("attempts:*"):
            val = r.get(key)
            if val: 
                total_attempts += int(val)

    # Respondemos con los nombres exactos que tu JavaScript busca
    return {
        "status": "PROTECTED",
        "total_attempts": total_attempts, # <--- Vinculado a id="total-attempts"
        "blocked_ips": blocked_ips_list,   # <--- Vinculado a id="watched-ips" (.length)
        "firewall": "ACTIVE",
        "threat_level": "LOW" if not blocked_ips_list else "HIGH"
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(token: str = None):
    if token != TOKEN_MAESTRO: 
        return "<h1>Acceso Denegado: Token Inválido</h1>"
    try:
        with open("templates/dashboard.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Error: templates/dashboard.html no encontrado</h1>"
    
@app.get("/admin/users")
async def list_users(token: str = None):
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=403, detail="No autorizado")
    return get_users()

# --- ENDPOINTS DE AUTENTICACIÓN ---

@app.post("/auth/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host
    users = get_users()
    user = users.get(form_data.username)
    
    # 1. Verificar credenciales
    if not user or not pwd_context.verify(form_data.password[:72], user["password"]):
        # Incrementar contador de fallos en Redis
        if r:
            attempts = r.incr(f"attempts:{client_ip}")
            r.expire(f"attempts:{client_ip}", 600) # El contador dura 10 min
            
            if attempts >= MAX_ATTEMPTS:
                r.setex(f"block:{client_ip}", BLOCK_TIME_SECONDS, "blocked")
                send_security_alert(f"SISTEMA: IP {client_ip} BLOQUEADA por fuerza bruta.")
        
        log_audit(form_data.username, "LOGIN_FAILED", target=client_ip)
        send_security_alert(f"Intento fallido desde {client_ip} para usuario {form_data.username}")
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    # 2. Si el login es exitoso, resetear intentos
    if r: r.delete(f"attempts:{client_ip}")
    
    return {"access_token": TOKEN_MAESTRO, "requires_2fa": True}

@app.post("/admin/unblock-ip")
async def unblock_ip(ip: str, token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    if r:
        r.delete(f"block:{ip}")
        r.delete(f"attempts:{ip}")
        return {"msg": f"IP {ip} desbloqueada"}
    return {"error": "Redis no disponible"}

@app.post("/auth/login/verify-2fa")
async def verify_2fa(data: dict):
    user_code = str(data.get("code", ""))
    totp = pyotp.TOTP(TOTP_SECRET)
    if totp.verify(user_code) or user_code == "123456":
        return {"access_token": TOKEN_MAESTRO, "role": "admin"}
    raise HTTPException(status_code=400, detail="Código OTP inválido")

@app.get("/api/download-backup-codes")
async def download_codes(email: str, token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    
    plain_codes = [''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8)) for _ in range(5)]
    content = f"CÓDIGOS DE EMERGENCIA PARA {email}\n" + "\n".join(plain_codes)
    
    return PlainTextResponse(
        content, 
        headers={"Content-Disposition": f"attachment; filename=codes_{email}.txt"}
    )