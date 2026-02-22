import os
import json
import pyotp
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, String, Integer, Boolean, TIMESTAMP, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID
from pydantic import BaseModel, EmailStr
from loguru import logger
from jose import JWTError, jwt

# Importaciones de seguridad
from auth_utils import get_password_hash, verify_password, create_access_token, SECRET_KEY, ALGORITHM, generate_2fa_secret, verify_2fa_code

# --- CONFIGURACIÓN BASE DE DATOS ---
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hyperion_user:hyperion_password@db:5432/hyperion_db")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, server_default="employee")
    created_at = Column(TIMESTAMP, server_default=text("NOW()"))
    twofa_secret = Column(String, nullable=True)
    twofa_enabled = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

# --- INICIALIZACIÓN APP ---
app = FastAPI(title="Hyperion API - Auth System")

# CONFIGURACIÓN DE TEMPLATES (CORREGIDO)
base_dir = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(base_dir, "templates"))

# --- UTILIDADES ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def log_audit(email, success, reason=""):
    audit_logger = logger.bind(email=email, success=success, reason=reason)
    log_msg = f"{'SUCCESS' if success else 'FAILED'}: {email} - {reason}"
    if success: audit_logger.info(log_msg)
    else: audit_logger.warning(log_msg)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise HTTPException(status_code=401, detail="Token inválido")
    except: raise HTTPException(status_code=401, detail="Sesión expirada")
    user = db.query(User).filter(User.email == email).first()
    if user is None: raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user

# --- ESQUEMAS ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "employee"

class TwoFAVerify(BaseModel):
    code: str

class Final2FAVerify(BaseModel):
    email: EmailStr
    code: str

# --- ENDPOINTS ---

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/auth/register", tags=["Autenticación"])
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="El correo ya existe")
    new_user = User(email=user_data.email, password_hash=get_password_hash(user_data.password), role=user_data.role)
    db.add(new_user)
    db.commit()
    return {"message": "Usuario creado"}

@app.post("/auth/login", tags=["Autenticación"])
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        log_audit(form_data.username, False, "Login: Credenciales incorrectas")
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if user.twofa_enabled:
        return {"requires_2fa": True, "message": "Código 2FA requerido", "email": user.email}
    token = create_access_token(data={"sub": user.email})
    log_audit(user.email, True, "Login exitoso (sin 2FA)")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/login/verify-2fa", tags=["Autenticación"])
def verify_login_2fa(data: Final2FAVerify, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_2fa_code(user.twofa_secret, data.code):
        log_audit(data.email, False, "Login 2FA: Código incorrecto")
        raise HTTPException(status_code=401, detail="Código 2FA incorrecto")
    token = create_access_token(data={"sub": user.email})
    log_audit(user.email, True, "Login exitoso con 2FA")
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/2fa/setup", tags=["Seguridad 2FA"])
def setup_2fa(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    secret = generate_2fa_secret()
    current_user.twofa_secret = secret
    db.commit()
    otp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="Hyperion")
    return {"secret": secret, "qr_config_url": otp_auth_url}

@app.post("/auth/2fa/activate", tags=["Seguridad 2FA"])
def activate_2fa(data: TwoFAVerify, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if verify_2fa_code(current_user.twofa_secret, data.code):
        current_user.twofa_enabled = True
        db.commit()
        log_audit(current_user.email, True, "2FA Activado")
        return {"message": "2FA activo"}
    raise HTTPException(status_code=400, detail="Código inválido")

@app.get("/dashboard/stats", tags=["Dashboard"])
def get_dashboard_stats():
    active_users = []
    failed = 0
    if os.path.exists("logs/audit.json"):
        with open("logs/audit.json", "r") as f:
            for line in f:
                log = json.loads(line).get("record", {}).get("extra", {})
                if not log.get("success"): failed += 1
                if log.get("success") and "Login" in log.get("reason", ""):
                    active_users.append(log.get("email"))
    return {
        "total_usuarios_en_red": len(set(active_users)),
        "alertas_seguridad_bloqueadas": failed,
        "usuarios_conectados_recientemente": list(set(active_users))
    }

@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard UI"])
async def read_dashboard(request: Request, token: Optional[str] = None):
    # Verificamos si el token viene en la URL (ej: /dashboard?token=xxx)
    if not token:
        raise HTTPException(status_code=401, detail="Acceso denegado: Se requiere Token de sesión")
    
    try:
        # Validamos el token usando la lógica que ya tenemos
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except Exception:
        raise HTTPException(status_code=401, detail="Sesión expirada o token corrupto")

    # Si todo está OK, le mostramos el dashboard
    return templates.TemplateResponse("dashboard.html", {"request": request})