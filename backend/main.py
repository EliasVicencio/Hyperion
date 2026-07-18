from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import health, auth, operadores, logs, gobernanza, vigilancia, academia, riesgos, threat_intel, tickets

app = FastAPI(title="Hyperion Core Backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(operadores.router)
app.include_router(logs.router)
app.include_router(gobernanza.router)
app.include_router(vigilancia.router)
app.include_router(academia.router)
app.include_router(riesgos.router)
app.include_router(threat_intel.router)
app.include_router(tickets.router)