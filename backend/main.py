from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from datetime import datetime
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
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

# Nuevos modelos para soportar el flujo 2FA Voluntario
class TokenVerifyRequest(BaseModel):
    username: str
    token: str

class Setup2FAResponse(BaseModel):
    secret: str
    qr_uri: str

# --- ENDPOINTS ---
@app.get("/health/deep")
def deep_health():
    return {"status": "healthy", "has_db_url": bool(RAW_DB_URL), "timestamp": datetime.now().isoformat()}

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

async def _crear_operador_en_bd(payload: "NuevoOperador", db: Session):
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

# =====================================================================
# 🔐 MODIFICADO: LOGIN EN DOS PASOS VOLUNTARIO (MFA OPCIONAL)
# =====================================================================
@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    
    try:
        # Obtenemos la contraseña hash y las flags de verificación 2FA desde Supabase
        query = text('SELECT password, role, two_factor_enabled FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()

        if not user_record or not verify_password(password, user_record[0]):
            raise HTTPException(status_code=400, detail="Credenciales incorrectas o usuario no registrado.")

        two_factor_enabled = bool(user_record[2])

        # FLUJO COMPORTAMIENTO: Si tiene el 2FA encendido, no le damos el éxito directo, exigimos token.
        if two_factor_enabled:
            return {
                "status": "requires_2fa",
                "message": "Segundo factor de autenticación requerido para este operador.",
                "username": username
            }

        # COMPORTAMIENTO VOLUNTARIO: Si no lo tiene activo, pasa directo sin trabas a merced del usuario.
        return {
            "status": "success", 
            "username": username,
            "role": (user_record[1].upper() + "_ROLE") if user_record[1] else "OPERADOR_ROLE"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el proceso de autenticación: {str(e)}")

@app.post("/auth/verify-2fa")
async def verify_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    """Verifica el código de 6 dígitos introducido por el operador durante el Login."""
    import pyotp
    try:
        query = text('SELECT two_factor_secret, role FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="Este operador no tiene configurada una clave TOTP.")
            
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="Código de seguridad inválido o expirado.")
            
        return {
            "status": "success",
            "username": data.username,
            "role": (user_record[1].upper() + "_ROLE") if user_record[1] else "OPERADOR_ROLE"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo en verificación perimetral: {str(e)}")

# =====================================================================
# ⚙️ NUEVOS ENDPOINTS PERFIL: GENERACIÓN Y ACTIVACIÓN DESDE CONFIGURACIÓN
# =====================================================================
@app.post("/auth/setup-2fa", response_model=Setup2FAResponse)
async def setup_2fa(username: str, db: Session = Depends(get_db)):
    """Inicializa la configuración del 2FA. Devuelve la llave y la uri para el QR."""
    import pyotp
    try:
        secret = pyotp.random_base32()
        totp_auth_url = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, 
            issuer_name="Hyperion Core"
        )
        
        # Guardamos el secreto en estado inactivo hasta que el usuario lo verifique con éxito
        query = text('UPDATE usuarios SET two_factor_secret = :secret, two_factor_enabled = FALSE WHERE email = :email')
        db.execute(query, {"secret": secret, "email": username})
        db.commit()
        
        return {"secret": secret, "qr_uri": totp_auth_url}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error al generar semilla TOTP: {str(e)}")

@app.post("/auth/activate-2fa")
async def activate_2fa(data: TokenVerifyRequest, db: Session = Depends(get_db)):
    """Confirma el escaneo exitoso del código. Si es válido, blinda la cuenta activando el flag."""
    import pyotp
    try:
        query = text('SELECT two_factor_secret FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": data.username}).fetchone()
        
        if not user_record or not user_record[0]:
            raise HTTPException(status_code=400, detail="Semilla TOTP no inicializada para esta cuenta.")
            
        totp = pyotp.TOTP(user_record[0])
        if not totp.verify(data.token):
            raise HTTPException(status_code=400, detail="El código de confirmación no coincide con el autenticador.")
            
        # Activamos definitivamente el flag para exigir 2FA en los siguientes inicios de sesión
        query_update = text('UPDATE usuarios SET two_factor_enabled = TRUE WHERE email = :email')
        db.execute(query_update, {"email": data.username})
        db.commit()
        
        return {"status": "activated", "message": "Autenticación de Dos Factores vinculada correctamente al sistema."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error en activación de seguridad: {str(e)}")
    
# 2. Agrega este nuevo endpoint para obtener el estado actual (por si refrescan la pestaña)
@app.get("/auth/status-2fa")
async def get_2fa_status(username: str, db: Session = Depends(get_db)):
    try:
        query = text('SELECT two_factor_enabled FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()
        return {"two_factor_enabled": bool(user_record[0]) if user_record else False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 3. Agrega el endpoint para DESACTIVAR el 2FA pidiendo confirmación de token
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
            
        # Limpiamos los campos para remover el 2FA
        query_update = text('UPDATE usuarios SET two_factor_enabled = FALSE, two_factor_secret = NULL WHERE email = :email')
        db.execute(query_update, {"email": data.username})
        db.commit()
        
        return {"status": "deactivated", "message": "Autenticación de dos factores removida."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)