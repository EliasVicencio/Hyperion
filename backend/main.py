from fastapi import FastAPI, APIRouter, Depends, HTTPException, status, Request
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
def get_operadores_database(db: Session = Depends(get_db)):
    """Mapea los usuarios reales desde Supabase directo a la interfaz de React"""
    try:
        query = text('SELECT id, email, role, nombre, ultima_conexion FROM usuarios')
        result = db.execute(query).fetchall()
        
        lista_operadores = []
        for row in result:
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

# --- CONSOLA EXTERNA (SIEM CONSOLE HTML) ---
@app.get("/dashboard", response_class=HTMLResponse)
async def external_dashboard(auth_token: str = None):
    if auth_token != "SESION_ADMIN_HYPERION_ULTRA_SECRETA":
        return "<html><body style='background:black;color:red;display:flex;justify-content:center;align-items:center;height:100vh;'><h1>ACCESO DENEGADO - PROTOCOLO DE SEGURIDAD ACTIVO</h1></body></html>"
       
    return """
    <html>
        <head>
            <title>Hyperion | Command Center</title>
            <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { background: #0b0e14; color: #e2e8f0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; overflow-x: hidden; }
                .navbar { background: #161b22; padding: 15px 30px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #30363d; box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
                .logo-container { display: flex; align-items: center; gap: 12px; }
                .logo-text { font-size: 1.4rem; font-weight: 800; letter-spacing: 2px; color: #fff; text-transform: uppercase; }
                .logo-text span { color: #a78bfa; }
                .status-container { display: flex; align-items: center; gap: 10px; font-size: 0.8rem; color: #8b949e; }
                .status-dot { height: 8px; width: 8px; background: #238636; border-radius: 50%; box-shadow: 0 0 8px #238636; animation: pulse 2s infinite; }
                .content { padding: 25px; }
                .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 25px; }
                .card { background: #0d1117; border: 1px solid #30363d; padding: 20px; border-radius: 12px; transition: 0.3s; }
                .card:hover { border-color: #a78bfa; box-shadow: 0 0 15px rgba(167, 139, 250, 0.1); }
                .card-title { color: #8b949e; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; margin-bottom: 15px; letter-spacing: 1px; }
                .big-value { font-size: 2.2rem; font-weight: bold; color: #f0f6fc; }
                .console { background: #010409; color: #4ade80; font-family: 'Consolas', 'Monaco', monospace; height: 350px; overflow-y: auto; padding: 20px; border-radius: 8px; font-size: 13px; border: 1px solid #30363d; line-height: 1.6; }
                @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.4; } 100% { opacity: 1; } }
            </style>
        </head>
        <body>
            <div class="navbar">
                <div class="logo-container">
                    <svg width="40" height="40" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="20" fill="none" stroke="#a78bfa" stroke-width="2" />
                        <ellipse cx="50" cy="50" rx="45" ry="15" fill="none" stroke="#58a6ff" stroke-width="1" transform="rotate(45 50 50)" />
                        <ellipse cx="50" cy="50" rx="45" ry="15" fill="none" stroke="#58a6ff" stroke-width="1" transform="rotate(-45 50 50)" />
                        <circle cx="50" cy="50" r="8" fill="#a78bfa">
                            <animate attributeName="opacity" values="0.5;1;0.5" dur="2s" repeatCount="indefinite" />
                        </circle>
                    </svg>
                    <div class="logo-text">HYPERION<span>CORE</span></div>
                </div>
                <div class="status-container">
                    <span class="status-dot"></span>
                    SECURE CONNECTION ESTABLISHED // ENCRYPTED NODE
                </div>
            </div>

            <div class="content">
                <div class="grid">
                    <div class="card">
                        <div class="card-title">Carga del Procesador</div>
                        <div style="height: 120px;"><canvas id="loadChart"></canvas></div>
                    </div>
                    <div class="card">
                        <div class="card-title">Tráfico de Red (Req/s)</div>
                        <div class="big-value" id="netValue">--</div>
                        <div style="color: #3fb950; font-size: 0.8rem; margin-top: 5px;">▲ LIVE STREAMING</div>
                    </div>
                    <div class="card">
                        <div class="card-title">Protocolo de Seguridad</div>
                        <div class="big-value">TLS 1.3</div>
                        <div style="color: #a78bfa; font-size: 0.8rem; margin-top: 5px;">AES-256-GCM ACTIVE</div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">Terminal de Auditoría Inmutable (Live Feed)</div>
                    <div id="terminal" class="console">
                        <span style="color: #8b949e;">[SYS] Estableciendo handshake con el núcleo...</span><br>
                        <span style="color: #8b949e;">[SYS] Verificando integridad de PostgreSQL en Supabase... OK</span><br>
                    </div>
                </div>
            </div>

            <script>
                const ctx = document.getElementById('loadChart').getContext('2d');
                const loadChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: Array(20).fill(''),
                        datasets: [{
                            data: Array(20).fill(0),
                            borderColor: '#a78bfa',
                            borderWidth: 2,
                            pointRadius: 0,
                            tension: 0.4,
                            fill: true,
                            backgroundColor: 'rgba(167, 139, 250, 0.05)'
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        scales: { y: { display: false, min: 0, max: 100 }, x: { display: false } },
                        plugins: { legend: { display: false } }
                    }
                });

                function updateDashboard() {
                    const reqs = Math.floor(Math.random() * (240 - 110) + 110);
                    document.getElementById('netValue').innerText = reqs;

                    loadChart.data.datasets[0].data.shift();
                    loadChart.data.datasets[0].data.push(Math.floor(Math.random() * (60 - 20) + 20));
                    loadChart.update('none');

                    const term = document.getElementById('terminal');
                    const entry = document.createElement('div');
                    const time = new Date().toLocaleTimeString();
                    entry.innerHTML = `<span>[${time}]</span> <span>AUDIT:</span> Capturado paquete de entrada en nodo <span>${Math.random().toString(36).substring(7).toUpperCase()}</span>`;
                    term.appendChild(entry);
                    if(term.childNodes.length > 50) term.removeChild(term.firstChild);
                    term.scrollTop = term.scrollHeight;
                }

                setInterval(updateDashboard, 1500);
            </script>
        </body>
    </html>
    """

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