import os
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..core import get_db, get_current_user, registrar_log

router = APIRouter(prefix="/api/vigilancia", tags=["Threat Intel"])

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


async def _geolocalizar_ip(client: httpx.AsyncClient, ip: str):
    """ip-api.com free tier: solo HTTP (no HTTPS), por eso esto vive siempre en el backend."""
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,lat,lon,query"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "pais": data.get("country"),
                    "pais_codigo": data.get("countryCode"),
                }
    except httpx.RequestError:
        pass
    return None


@router.get("/geolocate/{ip}")
async def geolocalizar(ip: str, current_user: dict = Depends(get_current_user)):
    """Endpoint liviano solo de geolocalización, usado por el mapa de amenazas del frontend."""
    async with httpx.AsyncClient(timeout=6.0) as client:
        geo = await _geolocalizar_ip(client, ip)
    if not geo:
        raise HTTPException(status_code=404, detail=f"No se pudo geolocalizar la IP {ip}.")
    return {"ip": ip, **geo}


@router.get("/threat-intel/ip/{ip}")
async def consultar_ip(
    ip: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Consulta reputación de una IP en VirusTotal y AbuseIPDB. Requiere sesión activa."""
    if not VT_API_KEY and not ABUSEIPDB_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="No hay API keys de Threat Intel configuradas (VIRUSTOTAL_API_KEY / ABUSEIPDB_API_KEY) en las variables de entorno del backend.",
        )

    resultado = {"ip": ip, "virustotal": None, "abuseipdb": None, "geo": None}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resultado["geo"] = await _geolocalizar_ip(client, ip)

        if VT_API_KEY:
            try:
                r = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": VT_API_KEY},
                )
                if r.status_code == 200:
                    data = r.json()["data"]["attributes"]
                    stats = data.get("last_analysis_stats", {})
                    resultado["virustotal"] = {
                        "maliciosos": stats.get("malicious", 0),
                        "sospechosos": stats.get("suspicious", 0),
                        "inofensivos": stats.get("harmless", 0),
                        "reputacion": data.get("reputation", 0),
                        "pais": data.get("country"),
                        "as_owner": data.get("as_owner"),
                    }
                elif r.status_code == 404:
                    resultado["virustotal"] = {"error": "IP no encontrada en VirusTotal"}
                else:
                    resultado["virustotal"] = {"error": f"VirusTotal respondió {r.status_code}"}
            except httpx.RequestError as e:
                resultado["virustotal"] = {"error": f"No se pudo contactar VirusTotal: {str(e)}"}

        if ABUSEIPDB_API_KEY:
            try:
                r = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                )
                if r.status_code == 200:
                    data = r.json()["data"]
                    resultado["abuseipdb"] = {
                        "score_abuso": data.get("abuseConfidenceScore"),
                        "total_reportes": data.get("totalReports"),
                        "pais": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "es_publica": data.get("isPublic"),
                        "uso": data.get("usageType"),
                    }
                else:
                    resultado["abuseipdb"] = {"error": f"AbuseIPDB respondió {r.status_code}"}
            except httpx.RequestError as e:
                resultado["abuseipdb"] = {"error": f"No se pudo contactar AbuseIPDB: {str(e)}"}

    vt_malicioso = bool(resultado["virustotal"]) and resultado["virustotal"].get("maliciosos", 0) > 0
    abuse_score = (resultado["abuseipdb"] or {}).get("score_abuso") or 0
    severidad = "CRITICAL" if (vt_malicioso or abuse_score >= 50) else "INFO"

    vt_mal = resultado["virustotal"].get("maliciosos") if resultado["virustotal"] else "N/A"
    await registrar_log(
        db,
        current_user["email"],
        "THREAT_INTEL_LOOKUP",
        severidad,
        detalles=f"Consulta de IP {ip} — VT maliciosos: {vt_mal}, AbuseIPDB score: {abuse_score}",
    )

    return resultado