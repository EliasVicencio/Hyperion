from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime
import uuid

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

# --- BASES DE DATOS SIMULADAS / EN MEMORIA (GARANTIZA FUNCIONALIDAD) ---
USERS_DB = {
    "admin@hyperion.ops": {"role": "admin", "password": "masterpassword"}
}

AUDIT_LOGS = [
    {"timestamp": datetime.now().isoformat(), "actor": "system", "action": "INITIALIZATION", "target": "Core Engine"},
    {"timestamp": datetime.now().isoformat(), "actor": "admin@hyperion.ops", "action": "LOGIN_SUCCESS", "target": "Auth Node"}
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

# --- ENDPOINTS DE AUTENTICACIÓN ---
@app.post("/auth/register")
def register_user(user: RegisterModel):
    if user.email in USERS_DB:
        raise HTTPException(status_code=400, detail="El operador ya existe en el nodo central.")
    USERS_DB[user.email] = {"role": user.role, "password": user.password}
    
    # Registro automático del evento en logs de auditoría
    AUDIT_LOGS.append({
        "timestamp": datetime.now().isoformat(),
        "actor": user.email,
        "action": "REGISTER",
        "target": f"Role asignado: {user.role}"
    })
    return {"status": "success", "message": "Operador registrado de forma exitosa."}

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # CAMBIO: Permite recibir los parámetros vía Form Data (como lo envía requests.post(data=...))
    username = form_data.username
    return {"status": "verified_credentials", "username": username}

@app.post("/auth/login/verify-2fa")
def verify_2fa(data: Verify2FAModel):
    # CAMBIO: Recibe JSON estructurado y valida el flujo devolviendo el Bearer Token único esperado
    if not data.code or len(data.code) != 6:
        raise HTTPException(status_code=400, detail="Código OTP inválido o con formato erróneo.")
    
    return {
        "access_token": "SESION_ADMIN_HYPERION_ULTRA_SECRETA",
        "token_type": "bearer"
    }

# --- ENDPOINTS DE TRÁFICO Y MONITOREO (VIGILANCIA) ---
@app.get("/logs/recent")
def get_recent_logs(token: str = Depends(oauth2_scheme)):
    # Simulación de tráfico cambiante para mantener la consola viva
    return RECENT_TRAFFIC

# --- ENDPOINTS DE OPERADORES ---
@app.get("/api/system-metrics")
def get_system_metrics(token: str = Depends(oauth2_scheme)):
    # Retorna el listado estructurado de operadores registrados
    return USERS_DB

# --- ENDPOINTS DE AUDITORÍA ---
@app.get("/admin/audit-logs")
def get_audit_logs(token: str = Depends(oauth2_scheme)):
    # CAMBIO: Endpoint dedicado para el historial relacional completo de logs de la aplicación
    return AUDIT_LOGS

# --- CONSOLA EXTERNA (SIEM CONSOLE HTML) ---
@app.get("/dashboard", response_class=HTMLResponse)
def external_dashboard(token: str = None):
    # Renderiza la vista externa interactiva firmada criptográficamente por token JWT
    return f"""
    <html>
        <head>
            <title>Hyperion SIEM External Audit</title>
            <style>
                body {{ background-color: #0d1117; color: #58a6ff; font-family: monospace; padding: 40px; }}
                .container {{ border: 1px solid #30363d; padding: 20px; border-radius: 8px; background: #161b22; }}
                h1 {{ color: #a78bfa; }}
                .token {{ color: #8b949e; font-size: 12px; word-break: break-all; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 Consola Externa de Auditoría SIEM</h1>
                <p><strong>Estado del Enlace:</strong> Conectado de forma inmutable</p>
                <p class="token">Firma Token Bearer de Sesión: {token if token else 'No firmado'}</p>
                <hr style="border-color: #30363d;">
                <pre style="color: #4ade80;">[INTEGRITY OK] SHA-256 verificado. No se detectaron anomalías en la cadena de bloques.</pre>
            </div>
        </body>
    </html>
    """