from fastapi import WebSocket, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime, timedelta
import os
from jose import jwt, JWTError
from sqlalchemy import Column, DateTime, Integer, String, create_engine, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from fastapi.concurrency import run_in_threadpool
import bcrypt

RAW_DB_URL = os.getenv("DATABASE_URL")

if RAW_DB_URL:
    if RAW_DB_URL.startswith("postgres://"):
        RAW_DB_URL = RAW_DB_URL.replace("postgres://", "postgresql+pg8000://", 1)
    elif RAW_DB_URL.startswith("postgresql://"):
        RAW_DB_URL = RAW_DB_URL.replace("postgresql://", "postgresql+pg8000://", 1)

if RAW_DB_URL:
    from sqlalchemy.pool import NullPool
    engine = create_engine(
        RAW_DB_URL,
        poolclass=NullPool,
        connect_args={"ssl_context": True},
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
else:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

JWT_SECRET = os.getenv("JWT_SECRET", "hyperion-core-secret-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

class TokenData(BaseModel):
    email: str | None = None
    role: str | None = None

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar el token de acceso",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email, role=payload.get("role"))
    except JWTError:
        raise credentials_exception
    user = db.execute(text("SELECT email, role FROM usuarios WHERE email = :email"), {"email": token_data.email}).fetchone()
    if user is None:
        raise credentials_exception
    return {"email": user[0], "role": user[1]}

def require_roles(allowed_roles: list[str]):
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="No tienes permisos para esta operación")
        return current_user
    return role_checker

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False

class NuevoOperador(BaseModel):
    email: EmailStr
    password: str
    nombre: str | None = None
    role: str = "operador"

class TokenVerifyRequest(BaseModel):
    username: str
    token: str

class Setup2FAResponse(BaseModel):
    secret: str
    qr_uri: str

class PasswordUpdateRequest(BaseModel):
    username: str = Field(..., description="El email/usuario logueado en sesión")
    new_password: str = Field(..., min_length=8, description="La nueva credencial")

class PasswordRecovery2FARequest(BaseModel):
    username: EmailStr = Field(..., description="El email corporativo del operador")
    new_password: str = Field(..., min_length=8, description="La nueva contraseña")
    token: str = Field(..., description="Código TOTP de 6 dígitos para validar identidad")

class ProgresoLeccionPayload(BaseModel):
    modulo_id: str
    leccion_id: str
    correcta: bool

class EventoVigilancia(Base):
    __tablename__ = "eventos_vigilancia"
    id = Column(Integer, primary_key=True, index=True)
    accion = Column(String, nullable=False)
    detalles = Column(String, nullable=True)
    severidad = Column(String, default="INFO")
    fecha_creacion = Column(DateTime, default=datetime.utcnow)

if not RAW_DB_URL:
    Base.metadata.create_all(bind=engine)

class VigilanciaManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = VigilanciaManager()

def _guardar_log_sincrono(db: Session, query, params):
    db.execute(query, params)
    db.commit()

async def registrar_log(db: Session, operador: str, accion: str, categoria: str = "INFO", origen_ip: str = "0.0.0.0", detalles: str = None):
    categoria = categoria.upper()
    query = text("""
        INSERT INTO logs_auditoria (operador, accion, categoria, origen_ip, detalles)
        VALUES (:operador, :accion, :categoria, :origen_ip, :detalles)
    """)
    params = {
        "operador": operador,
        "accion": accion,
        "categoria": categoria,
        "origen_ip": origen_ip,
        "detalles": detalles
    }
    try:
        await run_in_threadpool(_guardar_log_sincrono, db, query, params)
    except Exception as e:
        db.rollback()
        print(f"🚨 CRITICAL: Falló el registro del log de auditoría: {str(e)}")

    await manager.broadcast({
        "accion": accion,
        "operador": operador,
        "severidad": "CRITICAL" if categoria in ["CRITICAL", "WARN"] else "INFO",
        "detalles": detalles if detalles else "",
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
