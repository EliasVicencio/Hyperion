from fastapi import FastAPI, Depends, HTTPException, Request, Header, Body
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from datetime import datetime
import json
import os
import pyotp 
import psutil
import secrets
import string
import redis
from dotenv import load_dotenv
from kafka import KafkaProducer
import time
from kafka.errors import NoBrokersAvailable

# --- CARGAR VARIABLES ---
load_dotenv()
try:
    from ingestor import HyperionIngestor
except ImportError:
    print("⚠️ Error: No se encontró ingestor.py")

app = FastAPI(title="Hyperion SIEM API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURACIÓN DE KAFKA ---
producer = None
for i in range(5):
    try:
        producer = KafkaProducer(bootstrap_servers=['kafka:9092'])
        print("✅ Conectado a Kafka")
        break
    except NoBrokersAvailable:
        print(f"Esperando a kafka... (intento {i+1}/5)")
        time.sleep(5)

# --- SEGURIDAD Y CONSTANTES ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP") 
TOKEN_MAESTRO = "SESION_ADMIN_HYPERION_ULTRA_SECRETA" 
AUDIT_FILE = "audit_log.json"

# Conexión a Redis
try:
    r = redis.Redis(host='hyperion_cache', port=6379, decode_responses=True)
except Exception as e:
    print(f"⚠️ Redis no disponible: {e}")
    r = None

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

def log_audit(actor, action, target=None):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "actor": actor,
        "action": action,
        "target": target
    }
    logs = []
    if os.path.exists(AUDIT_FILE):
        with open(AUDIT_FILE, "r") as f:
            try: logs = json.load(f)
            except: logs = []
    logs.append(entry)
    with open(AUDIT_FILE, "w") as f: json.dump(logs, f, indent=4)

# --- MIDDLEWARE ---
@app.middleware("http")
async def ip_blocker_middleware(request: Request, call_next):
    client_ip = request.client.host
    if r and r.exists(f"block:{client_ip}"):
        return PlainTextResponse(f"🚫 IP Bloqueada", status_code=403)
    return await call_next(request)

# --- ENDPOINTS DE INGESTA (SOLO UNO) ---
@app.post("/api/v1/ingest/log")
async def ingest_log(payload: dict = Body(...), x_api_key: str = Header(None)):
    # Validación simple por API Key
    if x_api_key == "TU_API_KEY_SUPER_SECRETA":
        if producer:
            producer.send('hyperion.audit.logs', json.dumps(payload).encode('utf-8'))
            return {"status": "EVENT_QUEUED"}
    
    # Si no es la key secreta, intentar con el motor SIEM local
    VALID_API_KEYS = {"finance-app-key-123": "finance", "hr-app-key-456": "hr"}
    service_id = VALID_API_KEYS.get(x_api_key)
    
    if not service_id:
        raise HTTPException(status_code=401, detail="API Key inválida")

    try:
        new_hash, index = HyperionIngestor.process_log(service_id, payload)
        return {"status": "chained", "index": index, "hash": new_hash}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- ENDPOINTS DE SISTEMA ---
@app.get("/api/system-metrics")
async def get_metrics(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    }

@app.get("/api/security-status")
async def security_status(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    blocked_ips = []
    if r:
        for key in r.keys("block:*"):
            blocked_ips.append({"ip": key.split(":")[1], "status": "BLOCKED"})
    return {"status": "PROTECTED", "blocked_ips": blocked_ips}

@app.get("/admin/users")
async def list_users(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return get_users()

# --- AUTENTICACIÓN ---
@app.post("/auth/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host
    users = get_users()
    user = users.get(form_data.username)
    
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        if r:
            attempts = r.incr(f"attempts:{client_ip}")
            r.expire(f"attempts:{client_ip}", 600)
            if attempts >= MAX_ATTEMPTS:
                r.setex(f"block:{client_ip}", BLOCK_TIME_SECONDS, "blocked")
        raise HTTPException(status_code=401, detail="Error")

    if r: r.delete(f"attempts:{client_ip}")
    return {"access_token": TOKEN_MAESTRO, "requires_2fa": True}

@app.post("/auth/login/verify-2fa")
async def verify_2fa(data: dict):
    user_code = str(data.get("code", ""))
    totp = pyotp.TOTP(TOTP_SECRET)
    if totp.verify(user_code) or user_code == "123456":
        return {"access_token": TOKEN_MAESTRO, "role": "admin"}
    raise HTTPException(status_code=400, detail="Inválido")

@app.post("/auth/register")
async def register(data: dict = Body(...)):
    users = get_users()
    email, password = data.get("email"), data.get("password")
    if not email or email in users: raise HTTPException(status_code=400)
    
    users[email] = {
        "password": pwd_context.hash(password),
        "role": data.get("role", "user"),
        "created_at": datetime.utcnow().isoformat()
    }
    save_users(users)
    return {"msg": "OK"}

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(token: str = None):
    if token != TOKEN_MAESTRO: return "Acceso Denegado"
    with open("templates/dashboard.html", "r", encoding="utf-8") as f:
        return f.read()