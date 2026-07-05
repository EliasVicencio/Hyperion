from fastapi import FastAPI, APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from datetime import datetime
import os
from sqlalchemy import Column, DateTime, Integer, String, create_engine, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base  # 🌟 Corregido Base
from sqlalchemy.exc import IntegrityError
from fastapi.concurrency import run_in_threadpool
import bcrypt

router = APIRouter(prefix="/api/v1/immune", tags=["Immune System"])
app = FastAPI(title="Hyperion Core Backend", version="2.0.0")

# --- MIDDLEWARE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# --- BASE DECLARATIVA REAL DE SQLALCHEMY ---
Base = declarative_base()  # 🌟 Esto reemplaza el import incorrecto de unittest

# --- CONEXIÓN DE BASE DE DATOS ULTRA LIGERA PARA VERCEL ---
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
        connect_args={"ssl_context": True},  # Supabase exige SSL
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
else:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- HASHING DE CONTRASEÑAS ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False
    
# --- MODELOS PYDANTIC ---
class LoginAttempt(BaseModel):
    user_email: str
    hour: int
    country: str

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

class LogFiltro(BaseModel):
    categoria: str | None = None
    operador: str | None = None

# --- MODELO ORM DE VIGILANCIA ---
class EventoVigilancia(Base):
    __tablename__ = "eventos_vigilancia"
    id = Column(Integer, primary_key=True, index=True)
    accion = Column(String, nullable=False)
    detalles = Column(String, nullable=True)
    severidad = Column(String, default="INFO")
    fecha_creacion = Column(DateTime, default=datetime.utcnow)

# Crear tablas automáticamente si estamos en entorno SQLite local
if not RAW_DB_URL:
    Base.metadata.create_all(bind=engine)

# --- GESTOR DE CONEXIONES EN VIVO (WEBSOCKETS) ---
class VigilanciaManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []  # 🌟 Corregido el tipo de lista de ast a nativo

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

# --- FUNCIÓN INTERNA: REGISTRO DE AUDITORÍA E INYECCIÓN EN VIVO ---
async def registrar_log(db: Session, operador: str, accion: str, categoria: str = "INFO", origen_ip: str = "0.0.0.0", detalles: str = None):
    """Inserta un registro en logs_auditoria y lo transmite en tiempo real a Vigilancia."""
    categoria = categoria.upper()
    try:
        query = text("""
            INSERT INTO logs_auditoria (operador, accion, categoria, origen_ip, detalles)
            VALUES (:operador, :accion, :categoria, :origen_ip, :detalles)
        """)
        await run_in_threadpool(
            db.execute, 
            query, 
            {
                "operador": operador,
                "accion": accion,
                "categoria": categoria,
                "origen_ip": origen_ip,
                "detalles": detalles
            }
        )
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"🚨 CRITICAL: Falló el registro del log de auditoría: {str(e)}")

    # 🌟 TRANSMISIÓN EN TIEMPO REAL AL WEBSOCKET DE VIGILANCIA
    # Esto asegura que CUALQUIER evento en el sistema actualice el frontend automáticamente
    await manager.broadcast({
        "accion": accion,
        "operador": operador,
        "severidad": "CRITICAL" if categoria in ["CRITICAL", "WARN"] else "INFO",
        "detalles": detalles if detalles else "",
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

# --- ENDPOINTS ---
@app.get("/health/deep")
def deep_health():
    return {"status": "healthy", "has_db_url": bool(RAW_DB_URL), "timestamp": datetime.now().isoformat()}

@app.get("/api/v1/logs")
async def get_logs_auditoria(categoria: str | None = None, db: Session = Depends(get_db)):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="DATABASE_URL no configurada.")
        
    try:
        if categoria:
            query = text("SELECT id, timestamp, operador, accion, categoria, origen_ip, detalles FROM logs_auditoria WHERE categoria = :categoria ORDER BY timestamp DESC LIMIT 100")
            result = await run_in_threadpool(db.execute, query, {"categoria": categoria.upper()})
        else:
            query = text("SELECT id, timestamp, operador, accion, categoria, origen_ip, detalles FROM logs_auditoria ORDER BY timestamp DESC LIMIT 100")
            result = await run_in_threadpool(db.execute, query)
            
        rows = result.fetchall()
        
        lista_logs = []
        for row in rows:
            lista_logs.append({
                "id": row[0],
                "timestamp": row[1].strftime("%Y-%m-%d %H:%M:%S") if row[1] else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "operador": row[2],
                "accion": row[3],
                "categoria": row[4],
                "origen_ip": row[5],
                "detalles": row[6] if row[6] else ""
            })
        return lista_logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al consultar logs: {str(e)}")

@app.get("/api/v1/operadores")
async def get_operadores_database(db: Session = Depends(get_db)):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: La variable DATABASE_URL está vacía en Vercel.")
        
    try:
        query = text('SELECT id, email, role, nombre, ultima_conexion FROM usuarios')
        result = await run_in_threadpool(db.execute, query)
        rows = result.fetchall()
        
        lista_operadores = []
        for row in rows:
            lista_operadores.append({
                "id": row[0],
                "nombre": row[3] if row[3] else "Operador Corporativo",
                "email": row[1],
                "rol": (row[2].upper() + "_ROLE") if row[2] else "OPERADOR_ROLE",
                "activo": True,
                "ultima_conexion": row[4].strftime("%Y-%m-%d %H:%M:%S") if row[4] else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        return lista_operadores
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

async def _crear_operador_en_bd(payload: NuevoOperador, db: Session):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: La variable DATABASE_URL está vacía en Vercel.")

    if len(payload.password) < 8:
        raise HTTPException(status_code=422, detail="La contraseña debe tener al menos 8 caracteres.")

    hashed = hash_password(payload.password)

    try:
        query = text("""
            INSERT INTO usuarios (email, password, role, nombre)
            VALUES (:email, :password, :role, :nombre)
            RETURNING id, email, role, nombre, ultima_conexion
        """)
        result = await run_in_threadpool(
            db.execute,
            query,
            {
                "email": payload.email,
                "password": hashed,
                "role": payload.role,
                "nombre": payload.nombre,
            },
        )
        row = result.fetchone()
        db.commit()
        
        # 🚨 Envía la alerta de creación a Vigilancia automáticamente por medio del nuevo registrar_log
        await registrar_log(db, payload.email, "OPERADOR_CREATED", "WARN", detalles=f"Alta de nueva identidad por el sistema. Rol: {payload.role}")
        
        return {
            "id": row[0],
            "nombre": row[3] if row[3] else "Operador Corporativo",
            "email": row[1],
            "rol": (row[2].upper() + "_ROLE") if row[2] else "OPERADOR_ROLE",
            "activo": True,
            "ultima_conexion": row[4].strftime("%Y-%m-%d %H:%M:%S") if row[4] else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Ya existe un operador registrado con ese email.")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

@app.post("/api/v1/register", status_code=status.HTTP_201_CREATED)
async def register(payload: NuevoOperador, db: Session = Depends(get_db)):
    return await _crear_operador_en_bd(payload, db)

@app.post("/api/v1/operadores", status_code=status.HTTP_201_CREATED)
async def crear_operador(payload: NuevoOperador, db: Session = Depends(get_db)):
    return await _crear_operador_en_bd(payload, db)

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    
    try:
        query = text('SELECT password, role, two_factor_enabled FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()

        if not user_record or not verify_password(password, user_record[0]):
            # 🚨 Alerta de seguridad si fallan el login
            await registrar_log(db, username, "LOGIN_FAILED", "WARN", detalles="Intento fallido de autenticación.")
            raise HTTPException(status_code=400, detail="Credenciales incorrectas o usuario no registrado.")

        two_factor_enabled = bool(user_record[2])

        if two_factor_enabled:
            return {
                "status": "requires_2fa",
                "message": "Segundo factor de autenticación requerido para este operador.",
                "username": username
            }

        # 🚨 Alerta en tiempo real de inicio correcto
        await registrar_log(db, username, "LOGIN_SUCCESS", "INFO", detalles="Inicio de sesión perimetral correcto.")
        
        return {
            "status": "success", 
            "username": username,
            "role": (user_record[1].upper() + "_ROLE") if user_record[1] else "OPERADOR_ROLE"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el proceso de autenticación: {str(e)}")
    
@app.delete("/api/v1/operadores/{id}")
async def eliminar_operador(id: int, db: Session = Depends(get_db)):
    if not RAW_DB_URL:
        raise HTTPException(status_code=500, detail="Error de configuración: La variable DATABASE_URL está vacía.")
        
    try:
        check_query = text("SELECT email FROM usuarios WHERE id = :id")
        user = db.execute(check_query, {"id": id}).fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail=f"Operador con ID {id} no encontrado en el sistema.")
            
        delete_query = text("DELETE FROM usuarios WHERE id = :id")
        await run_in_threadpool(db.execute, delete_query, {"id": id})
        db.commit()
        
        # 🚨 Alerta crítica: El operador fue purgado
        await registrar_log(db, user[0], "ACCESS_REVOKED", "CRITICAL", detalles=f"Purga de credenciales completada para el ID {id}.")
        
        return {
            "status": "success",
            "message": f"Acceso revocado permanentemente para el operador {user[0]}."
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error en la base de datos al purgar registro: {str(e)}")

# --- ENDPOINTS 2FA ---
@app.post("/auth/verify-2fa")
async def verify_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    import pyotp
    try:
        query = text('SELECT two_factor_secret, role FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="Este operador no tiene configurada una clave TOTP.")
            
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            await registrar_log(db, data.username, "2FA_FAILED", "WARN", detalles="Fallo de código de verificación 2FA.")
            raise HTTPException(status_code=400, detail="Código de seguridad inválido o expirado.")
            
        await registrar_log(db, data.username, "2FA_SUCCESS", "INFO", detalles="Doble factor validado.")
        return {
            "status": "success",
            "username": data.username,
            "role": (user_record[1].upper() + "_ROLE") if user_record[1] else "OPERADOR_ROLE"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo en verificación perimetral: {str(e)}")

@app.post("/auth/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(username: str, db: Session = Depends(get_db)):
    import pyotp
    try:
        secret = pyotp.random_base32()
        totp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, 
            issuer_name="Hyperion Core"
        )
        
        query = text('UPDATE usuarios SET two_factor_secret = :secret, two_factor_enabled = FALSE WHERE email = :email')
        db.execute(query, {"secret": secret, "email": username})
        db.commit()
        
        return {"secret": secret, "qr_uri": totp_auth_url}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al generar semilla TOTP: {str(e)}")

@app.post("/auth/activate-2fa")
async def activate_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    import pyotp
    try:
        query = text('SELECT two_factor_secret FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="Semilla TOTP no inicializada para esta cuenta.")
            
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="El código de confirmación no coincide con el autenticador.")
            
        query_update = text('UPDATE usuarios SET two_factor_enabled = TRUE WHERE email = :email')
        db.execute(query_update, {"email": data.username})
        db.commit()
        
        await registrar_log(db, data.username, "2FA_ACTIVATED", "INFO", detalles="El operador activó el resguardo por token TOTP.")
        return {"status": "activated", "message": "Autenticación de Dos Factores vinculada correctamente al sistema."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error en activación de seguridad: {str(e)}")
    
@app.get("/auth/status-2fa")
async def get_2fa_status(username: str, db: Session = Depends(get_db)):
    try:
        query = text('SELECT two_factor_enabled FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()
        return {"two_factor_enabled": bool(user_record[0]) if user_record else False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/deactivate-2fa")
async def deactivate_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    import pyotp
    try:
        query = text('SELECT two_factor_secret FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="No hay una configuración 2FA activa en este usuario.")
            
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="Código de desactivación incorrecto.")
            
        query_update = text('UPDATE usuarios SET two_factor_enabled = FALSE, two_factor_secret = NULL WHERE email = :email')
        db.execute(query_update, {"email": data.username})
        db.commit()
        
        await registrar_log(db, data.username, "2FA_DEACTIVATED", "CRITICAL", detalles="Doble factor removido por el operador.")
        return {"status": "deactivated", "message": "Autenticación de dos factores removida."}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

app.include_router(router)

# --- WEBSOCKET CANAL DE VIGILANCIA EN VIVO ---
@app.websocket("/api/vigilancia/ws/live")
async def websocket_vigilancia(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Escucha latidos o eventos desde el front si los hay
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Endpoint tradicional para consultar el historial de eventos guardados
@app.get("/api/vigilancia/historial")
def obtener_historial_vigilancia(db: Session = Depends(get_db)):
    # Nota: Si estás usando logs_auditoria directo mediante raw queries, podemos leer de ahí.
    # Para consistencia con tu sistema, jalamos los últimos 50 logs directamente:
    try:
        query = text("SELECT timestamp, operador, accion, categoria, detalles FROM logs_auditoria ORDER BY timestamp DESC LIMIT 50")
        result = db.execute(query)
        rows = result.fetchall()
        return [
            {
                "fecha": r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "operador": r[1],
                "accion": r[2],
                "severidad": r[3],
                "detalles": r[4]
            } for r in rows
        ]
    except Exception as e:
        return []

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)