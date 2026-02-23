from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json
import os
import subprocess  # Para ejecutar Bandit
import pyotp # <--- Añade esto al inicio
import psutil

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

TOTP_SECRET = "JBSWY3DPEHPK3PXP"

# --- VARIABLES GLOBALES DE MEMORIA ---
ip_blacklist = {} 
scan_history = []  # Almacena resultados de Bandit
MAX_ATTEMPTS = 5
TOKEN_MAESTRO = "SESION_ADMIN_HYPERION"
ADMIN_IPS = ["127.0.0.1", "172.18.0.1", "localhost"]

# --- GESTIÓN DE USUARIOS ---
def get_users():
    path = "users.json"
    if not os.path.exists(path):
        with open(path, "w") as f: json.dump({}, f)
    with open(path, "r") as f:
        try: return json.load(f)
        except: return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# --- ENDPOINTS DE AUTENTICACIÓN ---
@app.post("/auth/register")
async def register(data: dict):
    users = get_users()
    email = data.get("email")
    if email in users: raise HTTPException(status_code=400, detail="Usuario existe")
    users[email] = {"password": pwd_context.hash(data.get("password")), "role": "admin"}
    save_users(users)
    return {"status": "ok"}

@app.post("/auth/login")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    client_ip = request.client.host
    now = datetime.now()
    
    if client_ip in ip_blacklist:
        if ip_blacklist[client_ip]["blocked_until"] and now < ip_blacklist[client_ip]["blocked_until"]:
            raise HTTPException(status_code=429, detail="IP Bloqueada")

    users = get_users()
    user = users.get(form_data.username)

    if not user or not pwd_context.verify(form_data.password, user["password"]):
        if client_ip not in ip_blacklist:
            ip_blacklist[client_ip] = {"attempts": 0, "blocked_until": None}
        ip_blacklist[client_ip]["attempts"] += 1
        if client_ip not in ADMIN_IPS and ip_blacklist[client_ip]["attempts"] >= MAX_ATTEMPTS:
            ip_blacklist[client_ip]["blocked_until"] = now + timedelta(minutes=15)
        raise HTTPException(status_code=401, detail="Error de acceso")

    if client_ip in ip_blacklist: del ip_blacklist[client_ip]
    return {"access_token": TOKEN_MAESTRO, "requires_2fa": True}

@app.post("/auth/login/verify-2fa")
async def verify_2fa(data: dict):
    user_code = data.get("code")
    
    # 1. Creamos el verificador con el secreto
    totp = pyotp.TOTP(TOTP_SECRET)
    
    # 2. Verificamos si el código es el del Authenticator 
    # O si es nuestro código de auxilio 123456
    if totp.verify(user_code) or user_code == "123456":
        return {"access_token": TOKEN_MAESTRO}
    
    raise HTTPException(status_code=400, detail="Código OTP incorrecto o expirado")
# --- ENDPOINTS DEL DASHBOARD ---
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(token: str = None):
    if token != TOKEN_MAESTRO:
        return "<h1>Acceso Denegado</h1>", 403
    file_path = os.path.join("templates", "dashboard.html")
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/security-status")
async def get_status(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    now = datetime.now()
    output = []
    for ip, data in ip_blacklist.items():
        is_b = data["blocked_until"] and now < data["blocked_until"]
        output.append({
            "ip": ip,
            "attempts": data["attempts"],
            "status": "BLOQUEADO" if is_b else "SOSPECHOSO",
            "until": data["blocked_until"].strftime("%H:%M:%S") if is_b else "--"
        })
    return {"total_attempts": sum(d["attempts"] for d in ip_blacklist.values()), "blocked_ips": output}

@app.delete("/api/clear-ip/{ip}")
async def clear_ip(ip: str, token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    if ip in ip_blacklist:
        del ip_blacklist[ip]
        return {"msg": "OK"}
    raise HTTPException(status_code=404)

# --- DÍA 3: WEBHOOK & BANDIT ---
@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.json()
    repo_name = payload.get("repository", {}).get("full_name", "Hyperion-Repo")
    
    # Ejecutar Bandit sobre el código del proyecto
    # -r: recursivo, -f json: formato salida, -q: silencioso
    try:
        # En Docker, analizamos la carpeta /app que es donde vive el código
        result = subprocess.run(
            ["bandit", "-r", "/app", "-f", "json", "-q"], 
            capture_output=True, text=True
        )
        
        # Bandit devuelve código 1 si encuentra problemas, por eso no usamos check=True
        report = json.loads(result.stdout)
        
        # Extraer métricas de severidad (Alta y Media)
        high_severity = 0
        for issue in report.get("results", []):
            if issue["issue_severity"] == "HIGH":
                high_severity += 1

        summary = {
            "date": datetime.now().strftime("%H:%M:%S"),
            "repo": repo_name,
            "issues_found": high_severity,
            "severity": "CRÍTICA" if high_severity > 0 else "SEGURA"
        }
        
        scan_history.insert(0, summary)
        # Mantener solo los últimos 5 escaneos para no saturar memoria
        if len(scan_history) > 5: scan_history.pop()
        
        return {"status": "Escaneo completado", "data": summary}
    
    except Exception as e:
        print(f"Error en Bandit: {str(e)}")
        return {"status": "error", "detail": str(e)}

@app.get("/api/scan-results")
async def get_scans(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    return scan_history


@app.get("/api/system-metrics")
async def get_metrics(token: str = None):
    if token != TOKEN_MAESTRO: raise HTTPException(status_code=403)
    
    return {
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }