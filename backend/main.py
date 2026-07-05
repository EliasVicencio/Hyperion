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

# Reparar el string por si viene de Supabase con postgres:// o postgresql://
# Forzamos el dialecto pg8000 (driver 100% Python, sin libpq nativo) porque
# psycopg2-binary crashea la función serverless en Vercel con
# "libpq.so.5: cannot open shared object file" (FUNCTION_INVOCATION_FAILED).
if RAW_DB_URL:
    if RAW_DB_URL.startswith("postgres://"):
        RAW_DB_URL = RAW_DB_URL.replace("postgres://", "postgresql+pg8000://", 1)
    elif RAW_DB_URL.startswith("postgresql://"):
        RAW_DB_URL = RAW_DB_URL.replace("postgresql://", "postgresql+pg8000://", 1)

# IMPORTANTE: Desactivamos el pooling estático usando NullPool. 
# Esto evita que Vercel Serverless aborte la ejecución al iniciar.
if RAW_DB_URL:
    from sqlalchemy.pool import NullPool
    engine = create_engine(
        RAW_DB_URL,
        poolclass=NullPool,
        connect_args={"ssl_context": True},  # Supabase exige SSL
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
else:
    # Respaldo temporal si no se detecta la variable
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- HASHING DE CONTRASEÑAS ---
# Usamos bcrypt directo (no passlib): passlib + bcrypt>=4.1 tienen un bug de
# compatibilidad conocido (passlib está sin mantenimiento) que revienta al
# hashear con "password cannot be longer than 72 bytes".
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        # hash corrupto o no-bcrypt (p. ej. quedó texto plano de una fila antigua)
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

# --- ENDPOINTS ---
@app.get("/health/deep")
def deep_health():
    return {"status": "healthy", "has_db_url": bool(RAW_DB_URL), "timestamp": datetime.now().isoformat()}

@app.get("/api/v1/operadores")
async def get_operadores_database(db: Session = Depends(get_db)):
    """Trae los usuarios reales de Supabase de manera asíncrona compatible con Vercel"""
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
        # Devolvemos el error real en texto para saber exactamente qué tabla o permiso falló
        raise HTTPException(status_code=500, detail=f"Excepción en la base de datos: {str(e)}")

async def _crear_operador_en_bd(payload: "NuevoOperador", db: Session):
    """Lógica compartida de alta de operador: hashea password e inserta en Supabase."""
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
    """Endpoint público de auto-registro, usado por la pantalla de Login."""
    return await _crear_operador_en_bd(payload, db)

@app.post("/api/v1/operadores", status_code=status.HTTP_201_CREATED)
async def crear_operador(payload: NuevoOperador, db: Session = Depends(get_db)):
    """Alta de operador desde el gestor de usuarios (Mission Control)."""
    return await _crear_operador_en_bd(payload, db)

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    
    try:
        query = text('SELECT password, role FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()

        if not user_record or not verify_password(password, user_record[0]):
            raise HTTPException(status_code=400, detail="Credenciales incorrectas o usuario no registrado.")

        return {"status": "verified_credentials", "username": username}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el proceso de autenticación: {str(e)}")

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)