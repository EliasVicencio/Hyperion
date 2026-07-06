from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from backend.app.dependencies.database import Base
import datetime

class EventoVigilancia(Base):
    __tablename__ = "eventos_vigilancia"

    id = Column(Integer, primary_key=True, index=True)
    operador_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    accion = Column(String, nullable=False)  # Ej: "LOGIN_FALLIDO", "ACCESO_RECURSO"
    detalles = Column(String, nullable=True) # JSON o Texto con info extra
    ip_origen = Column(String, nullable=True)
    severidad = Column(String, default="INFO") # INFO, WARNING, CRITICAL
    fecha_creacion = Column(DateTime, default=datetime.datetime.utcnow)