from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json
import os

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# MEMORIA GLOBAL
ip_blacklist = {} 
MAX_ATTEMPTS = 5
ADMIN_IPS = ["127.0.0.1", "172.18.0.1", "localhost"]
TOKEN_MAESTRO = "SESION_ADMIN_HYPERION"

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
    
    # Verificar si ya está bloqueado
    if client_ip in ip_blacklist:
        if ip_blacklist[client_ip]["blocked_until"] and now < ip_blacklist[client_ip]["blocked_until"]:
            raise HTTPException(status_code=429, detail="IP Bloqueada temporalmente")

    users = get_users()
    user = users.get(form_data.username)

    # Validar credenciales
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        if client_ip not in ip_blacklist:
            ip_blacklist[client_ip] = {"attempts": 0, "blocked_until": None}
        
        ip_blacklist[client_ip]["attempts"] += 1
        
        if client_ip not in ADMIN_IPS and ip_blacklist[client_ip]["attempts"] >= MAX_ATTEMPTS:
            ip_blacklist[client_ip]["blocked_until"] = now + timedelta(minutes=15)
            
        raise HTTPException(status_code=401, detail="Fallo de autenticación")

    # Éxito: Limpiar historial
    if client_ip in ip_blacklist: del ip_blacklist[client_ip]
    return {"access_token": TOKEN_MAESTRO, "requires_2fa": True}

@app.post("/auth/login/verify-2fa")
async def verify_2fa(data: dict):
    if data.get("code") == "123456":
        return {"access_token": TOKEN_MAESTRO}
    raise HTTPException(status_code=400, detail="OTP Incorrecto")

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(token: str = None):
    # VALIDACIÓN DE ACCESO AL HTML
    if token != TOKEN_MAESTRO:
        return "<h1>Acceso Denegado: Token Inválido</h1>", 403
    
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

# Eliminación de lista negra
@app.delete("/api/clear-ip/{ip}")
async def clear_ip(ip: str, token: str = None):
    # Verificación de seguridad
    if token != TOKEN_MAESTRO:
        raise HTTPException(status_code=403, detail="No autorizado")
    
    if ip in ip_blacklist:
        del ip_blacklist[ip]
        return {"message": f"IP {ip} desbloqueada"}
    
    raise HTTPException(status_code=404, detail="IP no encontrada")