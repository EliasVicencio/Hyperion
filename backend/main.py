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
from app.routers.auth import limiter  # Importas el limitador que creamos recién

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
