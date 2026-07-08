from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..core import get_db

router = APIRouter(prefix="/api/v1", tags=["Riesgos"])

@router.get("/riesgos/dashboard")
async def obtener_dashboard_activos_y_riesgos(db: Session = Depends(get_db)):
    try:
        query_activos = text("""
            SELECT id, nombre, tipo, criticidad_base, responsable, estado_salud, ultimo_control
            FROM activos_informacion ORDER BY id ASC
        """)
        activos_res = db.execute(query_activos).fetchall()
        activos = [{
            "id": r[0], "nombre": r[1], "tipo": r[2],
            "criticidad": r[3], "responsable": r[4],
            "estado": r[5], "ultimo_control": r[6].isoformat() if r[6] else None
        } for r in activos_res]
        query_riesgos = text("""
            SELECT r.id, a.nombre, r.amenaza, r.probabilidad, r.impacto, r.nivel_riesgo, r.estado_mitigacion
            FROM matriz_riesgos r
            JOIN activos_informacion a ON r.activo_id = a.id
            ORDER BY r.nivel_riesgo DESC
        """)
        riesgos_res = db.execute(query_riesgos).fetchall()
        riesgos = [{
            "id": r[0], "activo_name": r[1], "amenaza": r[2],
            "probabilidad": r[3], "impacto": r[4],
            "nivel": r[5], "estado": r[6]
        } for r in riesgos_res]
        return {"activos": activos, "matriz_riesgos": riesgos}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
