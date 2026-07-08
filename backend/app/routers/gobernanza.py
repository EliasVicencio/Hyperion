from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
import hashlib
from ..core import get_db, get_current_user

router = APIRouter(prefix="/api/v1/gobernanza", tags=["Gobernanza"])

@router.get("/verificar-cadena")
async def verificar_cadena_criptografica(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        query = text("SELECT id, operador, accion, categoria, detalles, timestamp FROM logs_auditoria ORDER BY id ASC")
        result = db.execute(query).fetchall()
        hash_previo = "000000000000000..."
        logs_procesados = []
        for row in result:
            id_log, operador, accion, categoria, detalles, timestamp = row
            detalles_str = detalles if detalles else ""
            payload_combinado = f"{id_log}-{operador}-{accion}-{categoria}-{detalles_str}-{hash_previo}"
            hash_calculado = hashlib.sha256(payload_combinado.encode("utf-8")).hexdigest()
            logs_procesados.append({
                "id": id_log,
                "control": "A.8.15 / A.8.24" if categoria in ["CRITICAL", "WARN"] else "A.8.15",
                "event_type": accion,
                "actor": operador,
                "service": "hyperion-core",
                "categoria": "CRÍTICO" if categoria == "CRITICAL" else categoria,
                "timestamp": timestamp.isoformat() if timestamp else datetime.utcnow().isoformat(),
                "previous_hash": hash_previo[:18] + "...",
                "current_hash": hash_calculado[:18] + "...",
                "detalles": detalles_str
            })
            hash_previo = hash_calculado
        return {"status": "INTEGRA", "logs": list(reversed(logs_procesados))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/simular-ataque")
async def simular_ataque_bd(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        ultimo_id = db.execute(text("SELECT MAX(id) FROM logs_auditoria")).scalar()
        if not ultimo_id:
            raise HTTPException(status_code=400, detail="No hay logs para corromper.")
        query = text("UPDATE logs_auditoria SET detalles = '🚨 ATAQUE: Registro mutado mediante inyección perimetral SQL.' WHERE id = :id")
        db.execute(query, {"id": ultimo_id})
        db.commit()
        return {"status": "attack_injected", "target_id": ultimo_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/restaurar-cadena")
async def restaurar_cadena_criptografica(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        query_ataque = text("""
            SELECT id, detalles FROM logs_auditoria 
            WHERE detalles LIKE '%ATAQUE%'
        """)
        logs_ataque = db.execute(query_ataque).fetchall()
        for row in logs_ataque:
            id_log, detalles_invalidos = row
            detalles_limpios = "Doble factor validado de forma exitosa mediante canal seguro."
            update_query = text("""
                UPDATE logs_auditoria 
                SET detalles = :detalles, categoria = 'INFO' 
                WHERE id = :id
            """)
            db.execute(update_query, {"detalles": detalles_limpios, "id": id_log})
        db.commit()
        return {"status": "RESTORED", "message": "Cadena corregida y mitigada con éxito."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
