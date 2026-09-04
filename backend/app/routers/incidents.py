from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter(prefix="/api/v1/incidents", tags=["SOC Incidents"])

# Simulación en memoria / Conexión a Base de Datos
mock_incidents = [
    {
        "id": 101,
        "title": "Ataque de Fuerza Bruta SSH Detectado",
        "description": "Múltiples intentos fallidos de autenticación desde una IP externa no autorizada.",
        "severity": "CRITICAL",
        "status": "OPEN",
        "source_ip": "192.168.1.105",
        "assigned_to": "L1 Analyst",
        "created_at": datetime.utcnow().isoformat()
    },
    {
        "id": 102,
        "title": "Escaneo de Puertos Anómalo (Nmap)",
        "description": "Tráfico SYN flag excesivo hacia la interfaz perimetral de la API Gateway.",
        "severity": "HIGH",
        "status": "INVESTIGATING",
        "source_ip": "10.0.4.12",
        "assigned_to": "L2 Analyst",
        "created_at": datetime.utcnow().isoformat()
    }
]

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None

@router.get("", response_model=List[dict])
def get_incidents():
    return mock_incidents

@router.patch("/{incident_id}")
def update_incident(incident_id: int, update_data: IncidentUpdate):
    for inc in mock_incidents:
        if inc["id"] == incident_id:
            if update_data.status:
                inc["status"] = update_data.status
            if update_data.assigned_to:
                inc["assigned_to"] = update_data.assigned_to
            return inc
    raise HTTPException(status_code=404, detail="Incidente no encontrado")