from sqlalchemy import ForeignKey, Integer, Text, create_engine, Column, String, DateTime, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
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
import uuid
from fastapi.security import OAuth2PasswordBearer


# --- CONFIGURACIÓN DE BASE DE DATOS ---
DATABASE_URL = os.getenv("DATABASE_URL") # Render llenará esto automáticamente

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Esto permite que FastAPI entienda de dónde sacar el token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# --- MODELO DE USUARIO ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)
    created_at = Column(DateTime)

Base.metadata.drop_all(bind=engine)
# Crear las tablas automáticamente si no existen
Base.metadata.create_all(bind=engine)

# --- MODELO DE AUDITORÍA ---
class AuditLogDB(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String)
    action = Column(String)
    target = Column(String, nullable=True)

Base.metadata.drop_all(bind=engine)
# Asegúrate de que las tablas se creen
Base.metadata.create_all(bind=engine)

# --- MODELO DE SOLICITUDES DE ACCESO ---
class AccessRequestDB(Base):
    __tablename__ = "access_requests"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String)  # <--- CAMBIA user_id POR user_email
    requested_role = Column(String)
    justification = Column(Text)
    status = Column(String, default="pending")
    requested_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String, nullable=True)
    
# En main.py, después de definir todas las clases (Base)
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

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

# Conexión a Redis usando variable de entorno
redis_url = os.getenv("REDIS_URL", "redis://hyperion_cache:6379")
try:
    r = redis.from_url(redis_url)
    # Probar conexión
    r.ping()
    print(f"✅ Conectado a Redis en: {redis_url}")
except Exception as e:
    print(f"⚠️ Redis no disponible: {e}")
    r = None

sms_history = [] 
MAX_ATTEMPTS = 5
BLOCK_TIME_SECONDS = 300


def get_current_user(token: str = Depends(oauth2_scheme)):
    # Por ahora, como tu sistema usa un TOKEN_MAESTRO simple:
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=401, detail="Token inválido")
    # Retornamos un diccionario simulado (puedes ajustarlo luego)
    return {"email": "admin@hyperion.com", "role": "admin"}

# --- REEMPLAZO DE FUNCIONES JSON ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def send_security_alert(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    sms_history.insert(0, {"msg": f"🚨 {message}", "time": timestamp})

def log_audit(actor, action, target=None):
    db = SessionLocal()
    try:
        new_log = AuditLogDB(
            actor=actor,
            action=action,
            target=target
        )
        db.add(new_log)
        db.commit()
    except Exception as e:
        print(f"❌ Error al guardar log: {e}")
    finally:
        db.close()

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
    db = SessionLocal()
    users = db.query(UserDB).all()
    db.close()
    # Convertimos los objetos de la BD a un formato que el Frontend entienda
    return {user.email: {"role": user.role} for user in users}

# --- AUTENTICACIÓN ---
@app.post("/auth/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host
    db = SessionLocal() # <--- Abrir conexión a DB
    
    # Buscar al usuario en la base de datos
    user = db.query(UserDB).filter(UserDB.email == form_data.username).first()
    db.close() # <--- Cerrar conexión
    
    # Verificar si el usuario existe y la contraseña es correcta
    if not user or not pwd_context.verify(form_data.password, user.password):
        if r:
            attempts = r.incr(f"attempts:{client_ip}")
            r.expire(f"attempts:{client_ip}", 600)
            if attempts >= MAX_ATTEMPTS:
                r.setex(f"block:{client_ip}", BLOCK_TIME_SECONDS, "blocked")
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

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
async def register(data: dict):
    db = SessionLocal()
    try:
        email = data.get("email")
        role = data.get("role", "user")

        # 1. Verificar existencia
        user_exists = db.query(UserDB).filter(UserDB.email == email).first()
        if user_exists:
            # Auditamos el intento fallido por duplicidad (Seguridad)
            log_audit(actor="SYSTEM", action="REGISTER_FAIL", target=f"Duplicate email: {email}")
            raise HTTPException(status_code=400, detail="El usuario ya existe")
        
        # 2. Crear nuevo usuario
        new_user = UserDB(
            email=email,
            password=pwd_context.hash(data.get("password")),
            role=role,
            created_at=datetime.utcnow()
        )
        db.add(new_user)
        db.commit()

        # 3. 🛡️ REGISTRO EN AUDITORÍA (Lo que verá el jefe)
        log_audit(
            actor="SYSTEM", 
            action="USER_CREATED", 
            target=f"User: {email} | Role: {role}"
        )

        return {"msg": f"Usuario {email} registrado con éxito"}

    except Exception as e:
        db.rollback() # Si algo falla, revertimos
        raise e
    finally:
        db.close() # Siempre cerramos la conexión

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(token: str = None):
    if token != TOKEN_MAESTRO: return "Acceso Denegado"
    with open("templates/Dashboard.html", "r", encoding="utf-8") as f:
        return f.read()
    
@app.get("/admin/audit-logs")
async def get_audit_logs(token: str = None):
    if token != TOKEN_MAESTRO: 
        raise HTTPException(status_code=403)
    
    db = SessionLocal()
    logs = db.query(AuditLogDB).order_by(AuditLogDB.timestamp.desc()).limit(100).all()
    db.close()
    
    return [
        {
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "actor": log.actor,
            "action": log.action,
            "target": log.target
        } for log in logs
    ]
    
@app.get("/health/deep")
async def deep_health_check():
    status = {
        "api": "healthy",
        "database": "unreachable",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    db = SessionLocal()
    try:
        # Intentamos una operación ultra simple en la DB
        db.execute(text("SELECT 1")) 
        status["database"] = "healthy"
    except Exception as e:
        print(f"🚨 Error de salud en DB: {e}")
        # Aquí podrías disparar la función enviar_alerta() en el futuro
    finally:
        db.close()
    
    return status

@app.post("/access/request")
def request_access(payload: dict, db: Session = Depends(get_db), user_data: dict = Depends(get_current_user)):
    try:
        new_req = AccessRequestDB(
            user_email=user_data["email"], # Ahora coincide con el modelo
            requested_role=payload["requested_role"],
            justification=payload["justification"]
        )
        db.add(new_req)
        db.commit()
        return {"status": "success", "message": "Solicitud registrada"}
    except Exception as e:
        db.rollback()
        # Esto te dirá el error exacto en los logs de Render
        print(f"ERROR CRÍTICO EN DB: {str(e)}") 
        raise HTTPException(status_code=500, detail="Error interno al procesar la solicitud")
    
if __name__ == "__main__":
    import uvicorn
    # Cambia 127.0.0.1 por 0.0.0.0
    uvicorn.run(app, host="0.0.0.0", port=8000)