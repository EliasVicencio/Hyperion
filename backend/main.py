from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import (
    academia,
    auth,
    gobernanza,
    health,
    logs,
    operadores,
    riesgos,
    threat_intel,
    tickets,
    vigilancia,
)
from app.routers.auth import limiter

app = FastAPI(title="Hyperion Core Backend", version="2.0.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Agregamos el prefijo /api/v1 globalmente a los routers ---
API_PREFIX = "/api/v1"

app.include_router(health.router)  # Mantiene /health si lo necesitas en raíz
app.include_router(health.router, prefix=API_PREFIX) # Y también /api/v1/health

app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(operadores.router, prefix=API_PREFIX)
app.include_router(logs.router, prefix=API_PREFIX)
app.include_router(gobernanza.router, prefix=API_PREFIX)
app.include_router(vigilancia.router, prefix=API_PREFIX)
app.include_router(academia.router, prefix=API_PREFIX)
app.include_router(riesgos.router, prefix=API_PREFIX)
app.include_router(threat_intel.router, prefix=API_PREFIX)
app.include_router(tickets.router, prefix=API_PREFIX)