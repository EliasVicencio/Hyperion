from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime
from ..core import get_db, manager

router = APIRouter(prefix="/api/vigilancia", tags=["Vigilancia"])

@router.websocket("/ws/live")
async def websocket_vigilancia(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@router.get("/historial")
def obtener_historial_vigilancia(db: Session = Depends(get_db)):
    try:
        query = text("SELECT timestamp, operador, accion, categoria, detalles FROM logs_auditoria ORDER BY timestamp DESC LIMIT 50")
        result = db.execute(query)
        rows = result.fetchall()
        return [
            {
                "fecha": r[0].strftime("%Y-%m-%d %H:%M:%S") if r[0] else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "operador": r[1],
                "accion": r[2],
                "severidad": r[3],
                "detalles": r[4]
            } for r in rows
        ]
    except Exception as e:
        return []
