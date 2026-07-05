from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
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

RAW_DB_URL = os.getenv("DATABASE_URL")

# Reparar el string: forzar dialecto pg8000 (puro Python, sin libpq nativo)
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

# --- MODELOS PYDANTIC ---
class LoginAttempt(BaseModel):
    user_email: str
    hour: int
    country: str

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

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    
    try:
        query = text('SELECT password, role FROM usuarios WHERE email = :email')
        user_record = db.execute(query, {"email": username}).fetchone()
        
        if not user_record or password != user_record[0]:
            raise HTTPException(status_code=400, detail="Credenciales incorrectas o usuario no registrado.")
            
        return {"status": "verified_credentials", "username": username}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el proceso de autenticación: {str(e)}")

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)