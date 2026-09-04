from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Routers SOC
from app.routers import logs, incidents, soar, health, auth

app = FastAPI(title="Hyperion Core - SOC Platform", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registro de rutas activas del SOC
app.include_router(health.router)
app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(incidents.router)
app.include_router(soar.router)

@app.get("/")
def root():
    return {"status": "ONLINE", "system": "Hyperion SOC Core", "engine": "FastAPI + Supabase"}