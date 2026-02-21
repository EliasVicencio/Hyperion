import os
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, String, Integer, Boolean, TIMESTAMP, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import UUID
from pydantic import BaseModel, EmailStr
from loguru import logger
from datetime import datetime

# Importamos la herramienta de seguridad que creamos en auth_utils.py
from auth_utils import get_password_hash

# 1. CONFIGURACIÓN DE BASE DE DATOS
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hyperion_user:hyperion_password@db:5432/hyperion_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 2. MODELO DE BASE DE DATOS (SQLAlchemy)
class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, server_default="employee")
    twofa_secret = Column(String, nullable=True)
    twofa_enabled = Column(Boolean, default=False)
    ip_attempts = Column(Integer, default=0)
    last_ip = Column(String, nullable=True)
    locked_until = Column(TIMESTAMP, nullable=True)
    created_at = Column(TIMESTAMP, server_default=text("NOW()"))

# Crear tablas al iniciar
try:
    with engine.connect() as connection:
        # Esto es vital para que Postgres entienda qué es un UUID
        connection.execute(text('CREATE EXTENSION IF NOT EXISTS "pgcrypto";'))
        connection.commit()
    # Ahora que la extensión existe, creamos la tabla
    Base.metadata.create_all(bind=engine)
    print("✅ Tablas y Extensiones creadas correctamente")
except Exception as e:
    print(f"❌ Error al inicializar DB: {e}")

# 3. CONFIGURACIÓN DE LOGS (Auditoría para el Jefe)
if not os.path.exists("logs"):
    os.makedirs("logs")
logger.add("logs/audit.json", rotation="10 MB", serialize=True)

def log_audit(email, ip, success, reason=""):
    log_entry = {
        "email": email,
        "ip": ip,
        "success": success,
        "reason": reason,
        "timestamp": datetime.now().isoformat()
    }
    if success:
        logger.info(log_entry)
    else:
        logger.warning(log_entry)

# 4. DEPENDENCIAS Y ESQUEMAS
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "employee"

# 5. INICIALIZACIÓN DE FastAPI
app = FastAPI(title="Hyperion API - Auth System")

# 6. ENDPOINTS
@app.get("/health")
def health_check():
    return {"status": "ok", "database": "connected"}

@app.get("/latencia-db")
def get_db_latency():
    inicio = datetime.now().timestamp()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        fin = datetime.now().timestamp()
        ms = (fin - inicio) * 1000
        return {"latencia_ms": round(ms, 2), "status": "online"}
    except Exception as e:
        return {"error": str(e), "status": "offline"}

@app.post("/auth/register", tags=["Autenticación"])
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    Registra un nuevo usuario con contraseña hasheada y auditoría (Día 1).
    """
    Base.metadata.create_all(bind=engine)
    # Verificar si ya existe
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        log_audit(user_data.email, "N/A", False, "El usuario ya existe")
        raise HTTPException(status_code=400, detail="El correo ya está registrado")

    # Crear usuario con password hasheada
    new_user = User(
        email=user_data.email,
        password_hash=get_password_hash(user_data.password),
        role=user_data.role
    )

    try:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        log_audit(new_user.email, "N/A", True, "Registro exitoso")
        return {"message": "Usuario creado con éxito", "user_id": str(new_user.id)}
    except Exception as e:
        db.rollback()
        logger.error(f"Error en registro: {e}")
        raise HTTPException(status_code=500, detail="Error interno al crear usuario")