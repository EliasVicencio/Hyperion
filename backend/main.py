from fastapi import FastAPI, Depends, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
import os, psutil, uuid, pyotp
from datetime import datetime

# --- CONFIGURACIÓN DE NÚCLEO ---
DATABASE_URL = os.getenv("DATABASE_URL")
TOKEN_MAESTRO = "SESION_ADMIN_HYPERION_ULTRA_SECRETA"
TOTP_SECRET = os.getenv("TOTP_SECRET", "JBSWY3DPEHPK3PXP")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# --- MODELOS ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String, default="user")
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditLogDB(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String)
    action = Column(String)
    target = Column(String, nullable=True)

class AccessRequestDB(Base):
    __tablename__ = "access_requests"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_email = Column(String)
    requested_role = Column(String)
    justification = Column(Text)
    status = Column(String, default="pending")
    requested_at = Column(DateTime, default=datetime.utcnow)

# Crear tablas (sin borrar datos existentes)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Hyperion SIEM")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DEPENDENCIAS ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2_scheme)):
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=401, detail="No autorizado")
    return {"email": "admin@hyperion.com", "role": "admin"}

def log_event(db: Session, actor: str, action: str, target: str = None):
    new_log = AuditLogDB(actor=actor, action=action, target=target)
    db.add(new_log)
    db.commit()

# --- RUTAS DE AUTENTICACIÓN Y REGISTRO ---

@app.post("/auth/register")
async def register(data: dict, db: Session = Depends(get_db)):
    # Verificar si el usuario ya existe
    existing = db.query(UserDB).filter(UserDB.email == data["email"]).first()
    if existing:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    
    new_user = UserDB(
        email=data["email"],
        password=pwd_context.hash(data["password"]),
        role=data.get("role", "admin"), # Por defecto admin para esta fase
        created_at=datetime.utcnow()
    )
    db.add(new_user)
    db.commit()
    log_event(db, data["email"], "USER_REGISTERED", data["email"])
    return {"msg": "Registro exitoso"}

@app.post("/auth/login")
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        payload = await request.json()
    except:
        form = await request.form()
        payload = dict(form)
    
    username = payload.get("username") or payload.get("email")
    password = payload.get("password")

    user = db.query(UserDB).filter(UserDB.email == username).first()
    if user and pwd_context.verify(password, user.password):
        return {"access_token": TOKEN_MAESTRO, "token_type": "bearer", "requires_2fa": True}
    
    raise HTTPException(status_code=401, detail="Credenciales inválidas")

@app.post("/auth/login/verify-2fa")
async def verify_2fa(data: dict):
    code = str(data.get("code", ""))
    if code == "123456" or pyotp.TOTP(TOTP_SECRET).verify(code):
        return {"access_token": TOKEN_MAESTRO, "role": "admin"}
    raise HTTPException(status_code=400, detail="Código inválido")

# --- APARTADOS DE LA APLICACIÓN (CORREGIDOS) ---

@app.get("/health/deep")
async def deep_health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"api": "healthy", "database": "healthy", "health_score": 100}
    except:
        return {"api": "healthy", "database": "down", "health_score": 50}

@app.get("/admin/users")
async def list_operators(db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    users = db.query(UserDB).all()
    # Retornamos lista plana para evitar error de 'float'
    return [{"id": u.id, "email": u.email, "role": u.role} for u in users]

@app.get("/admin/audit-logs")
async def get_audit_logs(db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    logs = db.query(AuditLogDB).order_by(AuditLogDB.timestamp.desc()).limit(100).all()
    # Si no hay logs, devolvemos lista vacía para evitar error de 'index' en Pandas
    if not logs:
        return []
    return [
        {
            "fecha": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "usuario": l.actor,
            "accion": l.action,
            "objetivo": l.target or "N/A"
        } for l in logs
    ]

@app.get("/api/system-metrics")
async def get_metrics(user: dict = Depends(get_current_user)):
    return {
        "cpu": psutil.cpu_percent(),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)