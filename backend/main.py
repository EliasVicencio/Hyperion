from fastapi import APIRouter, FastAPI
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
    threat_hunting,
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

# --- Router Central v1 ---
api_v1_router = APIRouter(prefix="/api/v1")

# Se incluyen los sub-routers dentro de /api/v1
api_v1_router.include_router(health.router)
api_v1_router.include_router(auth.router)
api_v1_router.include_router(operadores.router)
api_v1_router.include_router(logs.router)
api_v1_router.include_router(gobernanza.router)
api_v1_router.include_router(vigilancia.router)
api_v1_router.include_router(academia.router)
api_v1_router.include_router(riesgos.router)
api_v1_router.include_router(threat_intel.router)
api_v1_router.include_router(tickets.router)
api_v1_router.include_router(threat_hunting.router)

# Montamos el router unificado en la app
app.include_router(api_v1_router)

# Endpoint de verificación directo en raíz (opcional)
app.include_router(health.router)