from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime
import os
import httpx

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

# --- CREDENCIALES DESDE VARIABLES DE ENTORNO (BÓVEDA SEGURA) ---
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

AUDIT_LOGS = [{"timestamp": datetime.now().isoformat(), "actor": "system", "action": "INITIALIZATION", "target": "Core Engine"}]
RECENT_TRAFFIC = [{"timestamp": datetime.now().isoformat(), "message": "Cluster operativo bajo conexion HTTP nativa"}]

class LoginAttempt(BaseModel):
    user_email: str
    hour: int
    country: str

@app.get("/health/deep")
def deep_health():
    return {"api": "healthy", "supabase_configured": bool(SUPABASE_URL), "timestamp": datetime.now().isoformat()}

# --- ENDPOINT DE OPERADORES (HTTP DIRECTO A SUPABASE) ---
@app.get("/api/v1/operadores")
async def get_operadores_database():
    """Consulta la API REST nativa de Supabase. Rápido, seguro y sin crasheos en Vercel."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Variables de entorno de Supabase ausentes.")

    # Conectamos directamente con la tabla 'usuarios' vía REST
    url = f"{SUPABASE_URL}/rest/v1/usuarios?select=id,email,role,nombre,ultima_conexion"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                raise HTTPException(status_code=500, detail=f"Supabase respondió con error: {response.text}")
            
            rows = response.json()
            lista_operadores = []
            for row in rows:
                lista_operadores.append({
                    "id": row.get("id"),
                    "nombre": row.get("nombre") if row.get("nombre") else "Operador Corporativo",
                    "email": row.get("email"),
                    "rol": (row.get("role").upper() + "_ROLE") if row.get("role") else "OPERADOR_ROLE",
                    "activo": True,
                    "ultima_conexion": row.get("ultima_conexion") if row.get("ultima_conexion") else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
            return lista_operadores
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error en enlace perimetral: {str(e)}")

# --- ENDPOINT DE LOGIN ---
@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Valida credenciales haciendo un filtro directo en la API de Supabase"""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise HTTPException(status_code=500, detail="Variables de entorno no configuradas.")

    username = form_data.username
    password = form_data.password

    url = f"{SUPABASE_URL}/rest/v1/usuarios?email=eq.{username}&select=password"
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}"
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers)
            records = response.json()
            
            if not records or response.status_code != 200:
                raise HTTPException(status_code=400, detail="Operador no registrado en el perímetro.")
            
            db_password = records[0].get("password")
            if password != db_password:
                raise HTTPException(status_code=400, detail="Credenciales de acceso inválidas.")
                
            return {"status": "verified_credentials", "username": username}
        except Exception:
            raise HTTPException(status_code=500, detail="Error durante el protocolo de verificación.")

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