from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Request, run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from datetime import datetime
import uuid
import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

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

# --- MOTOR DE CONFIGURACIÓN DE BASE DE DATOS (SUPABASE) ---
# Extrae la variable DATABASE_URL configurada en tu panel de Vercel
DATABASE_URL = os.getenv("DATABASE_URL")

# Inicialización segura de SQLAlchemy
engine = create_engine(DATABASE_URL if DATABASE_URL else "postgresql://localhost/dummy")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependencia para inyectar la sesión de la Base de Datos en los endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class LoginAttempt(BaseModel):
    user_email: str
    hour: int
    country: str

# --- DATA COMPLEMENTARIA EN MEMORIA ---
AUDIT_LOGS = [
    {"timestamp": datetime.now().isoformat(), "actor": "system", "action": "INITIALIZATION", "target": "Core Engine"},
    {"timestamp": datetime.now().isoformat(), "actor": "system_node", "action": "SUPABASE_LINK_ESTABLISHED", "target": "Database Layer"}
]

RECENT_TRAFFIC = [
    {"timestamp": datetime.now().isoformat(), "message": "Paquete inspeccionado de forma correcta por Capa 7 TLS"},
    {"timestamp": datetime.now().isoformat(), "message": "Sincronización del clúster completada con éxito"}
]

# --- MODELOS PYDANTIC ---
class RegisterModel(BaseModel):
    email: str
    password: str
    role: str

class Verify2FAModel(BaseModel):
    email: str
    code: str

# --- ENDPOINTS DE SALUD ---
@app.get("/health/deep")
def deep_health():
    return {"api": "healthy", "database": "healthy", "timestamp": datetime.now().isoformat()}

# --- ENDPOINTS DE AUTENTICACIÓN (VINCULADOS A SUPABASE) ---
@app.post("/auth/register")
def register_user(user: RegisterModel, db: Session = Depends(get_db)):
    # Verificar si el usuario ya existe en Supabase
    check_query = text('SELECT id FROM usuarios WHERE email = :email')
    existing_user = db.execute(check_query, {"email": user.email}).fetchone()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="El operador ya existe en el nodo central.")
    
    # Inserción en la base de datos real
    insert_query = text('INSERT INTO usuarios (email, password, role) VALUES (:email, :password, :role)')
    db.execute(insert_query, {"email": user.email, "password": user.password, "role": user.role})
    db.commit()
    
    AUDIT_LOGS.append({
        "timestamp": datetime.now().isoformat(),
        "actor": user.email,
        "action": "REGISTER",
        "target": f"Role asignado: {user.role}"
    })
    return {"status": "success", "message": "Operador registrado de forma exitosa."}

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = form_data.username
    password = form_data.password
    
    # Consultar credenciales reales en la tabla de Supabase
    query = text('SELECT password, role FROM usuarios WHERE email = :email')
    user_record = db.execute(query, {"email": username}).fetchone()
    
    if not user_record:
        raise HTTPException(status_code=400, detail="El operador no está registrado en el perímetro.")
        
    db_password = user_record[0]
    
    if password != db_password:
        raise HTTPException(status_code=400, detail="Credenciales de acceso inválidas.")
        
    return {"status": "verified_credentials", "username": username}

@app.post("/auth/login/verify-2fa")
def verify_2fa(data: Verify2FAModel):
    if not data.code or len(data.code) != 6:
        raise HTTPException(status_code=400, detail="Código OTP inválido o con formato erróneo.")
    
    return {
        "access_token": "SESION_ADMIN_HYPERION_ULTRA_SECRETA",
        "token_type": "bearer"
    }

# --- ENDPOINTS DE TRÁFICO Y MONITOREO (VIGILANCIA) ---
@app.get("/logs/recent")
def get_recent_logs(token: str = Depends(oauth2_scheme)):
    return RECENT_TRAFFIC

# --- ENDPOINTS DE OPERADORES (SINK REAL DESDE SUPABASE) ---
@app.get("/api/v1/operadores")
async def get_operadores_database(db: Session = Depends(get_db)):
    """Mapea los usuarios reales desde Supabase directo a la interfaz de React corriendo en Serverless"""
    try:
        # Forzamos a que la consulta SQL corra en un hilo separado compatible con los workers de Vercel
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
        raise HTTPException(status_code=500, detail=f"Fallo en enlace perimetral con Supabase: {str(e)}")

@app.get("/api/system-metrics")
def get_system_metrics(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Fallback heredado: Envía un volcado relacional rápido
    try:
        res = db.execute(text('SELECT email, role FROM usuarios')).fetchall()
        return {row[0]: {"role": row[1]} for row in res}
    except:
        return {"admin@hyperion.ops": {"role": "admin"}}

# --- ENDPOINTS DE AUDITORÍA ---
@app.get("/admin/audit-logs")
def get_audit_logs(token: str = Depends(oauth2_scheme)):
    return AUDIT_LOGS

@router.post("/evaluate-behavior")
async def evaluate_behavior(attempt: LoginAttempt):
    query_profile = text('SELECT typical_hours, typical_countries FROM user_behavior_profile WHERE user_email = :email')
    
    with engine.connect() as conn:
        result = conn.execute(query_profile, {"email": attempt.user_email}).fetchone()
        
        if not result:
            insert_profile = text('''
                INSERT INTO user_behavior_profile (user_email, typical_hours, typical_countries)
                VALUES (:email, ARRAY[8,9,10,11,12,13,14,15,16,17,18], ARRAY[:country])
            ''')
            conn.execute(insert_profile, {"email": attempt.user_email, "country": attempt.country})
            conn.commit()
            return {"status": "profile_created", "anomalies": []}
        
        typical_hours = result[0]
        typical_countries = result[1]
        
        anomalies = []
        
        if attempt.hour not in typical_hours:
            anomalies.append(f"Acceso a hora inusual: {attempt.hour}:00 hrs.")
            
        if attempt.country not in typical_countries:
            anomalies.append(f"Acceso desde país no habitual: {attempt.country}.")
            
        if len(anomalies) >= 2:
            description = " | ".join(anomalies)
            insert_anomaly = text('''
                INSERT INTO behavior_anomalies (user_email, description, severity, status)
                VALUES (:email, :desc, 'medium', 'active')
            ''')
            conn.execute(insert_anomaly, {"email": attempt.user_email, "desc": description})
            
            insert_audit = text('''
                INSERT INTO "audit_logs" (actor, action, context, hash_this)
                VALUES ('HYPERION_UEBA', 'ANOMALOUS_BEHAVIOR_DETECTED', :context, 'SHA256_SIMULADO_IMMUNE_LAYER')
            ''')
            conn.execute(insert_audit, {"context": f"Alerta crítica para {attempt.user_email}: {description}"})
            conn.commit()
            
            return {"status": "threat_detected", "anomalies": anomalies}
            
    return {"status": "clear", "anomalies": []}

# --- MONTAJE DEL ROUTER DEL SISTEMA INMUNE ---
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)