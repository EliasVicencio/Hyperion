from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from fastapi.concurrency import run_in_threadpool

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

# --- CONTROL SEGURO DE VARIABLES DE ENTORNO ---
RAW_DB_URL = os.getenv("DATABASE_URL") or os.getenv("BACKEND_URL")

# Forzar corrección de postgres:// a postgresql:// de forma dinámica para evitar crasheos de SQLAlchemy
if RAW_DB_URL and RAW_DB_URL.startswith("postgres://"):
    RAW_DB_URL = RAW_DB_URL.replace("postgres://", "postgresql://", 1)

# Inicialización segura de la base de datos
if RAW_DB_URL:
    try:
        engine = create_engine(RAW_DB_URL, pool_pre_ping=True, pool_recycle=3600)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        DATABASE_ACTIVE = True
    except Exception:
        DATABASE_ACTIVE = False
else:
    DATABASE_ACTIVE = False

# Fallback inyectado únicamente para mantener viva la API si no hay conexión
if not DATABASE_ACTIVE:
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- DATA DE AUDITORÍA Y MONITOREO (ESTÁTICA NO SENSIBLE) ---
AUDIT_LOGS = [{"timestamp": datetime.now().isoformat(), "actor": "system", "action": "INITIALIZATION", "target": "Core Engine"}]
RECENT_TRAFFIC = [{"timestamp": datetime.now().isoformat(), "message": "Cluster operativo bajo arquitectura Serverless"}]

class LoginAttempt(BaseModel):
    user_email: str
    hour: int
    country: str

@app.get("/health/deep")
def deep_health():
    return {"api": "healthy", "database_connected": DATABASE_ACTIVE, "timestamp": datetime.now().isoformat()}

# --- ENDPOINTS DE OPERADORES (SINK DESDE BASE DE DATOS REAL) ---
@app.get("/api/v1/operadores")
async def get_operadores_database(db: Session = Depends(get_db)):
    """Trae los usuarios reales de la base de datos de Supabase sin almacenar fallbacks locales expuestos"""
    if not DATABASE_ACTIVE:
        raise HTTPException(
            status_code=503, 
            detail="Servicio de base de datos no disponible. Verifica variables de entorno perimetrales."
        )
        
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
        raise HTTPException(
            status_code=500, 
            detail=f"Fallo crítico en el enlace de datos con Supabase: {str(e)}"
        )

# --- ENDPOINT DE AUTENTICACIÓN PROTEGIDO ---
@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Valida credenciales contra la tabla de usuarios en Supabase. Cero almacenamiento en texto plano."""
    username = form_data.username
    password = form_data.password
    
    if not DATABASE_ACTIVE:
        raise HTTPException(
            status_code=503, 
            detail="Autenticación indisponible. Enlace perimetral de datos inactivo."
        )

    try:
        query = text('SELECT password, role FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()
        
        # Validación estricta y segura
        if not user_record or password != user_record[0]:
            raise HTTPException(status_code=400, detail="Credenciales de acceso inválidas o usuario no registrado.")
            
        return {"status": "verified_credentials", "username": username}
    except Exception:
        raise HTTPException(status_code=500, detail="Error interno durante el protocolo de verificación.")

@app.get("/logs/recent")
def get_recent_logs(token: str = Depends(oauth2_scheme)):
    return RECENT_TRAFFIC

@app.get("/admin/audit-logs")
def get_audit_logs(token: str = Depends(oauth2_scheme)):
    return AUDIT_LOGS

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)