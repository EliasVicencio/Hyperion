from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable # <--- Importante
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker # <--- Actualizado (SQA 2.0)
import json
import hashlib
import time
from datetime import datetime

# --- CONFIGURACIÓN DE BASE DE DATOS ---
DB_URL = "postgresql://admin:hyperion_secret@postgres_db:5432/hyperion_audit"
engine = create_engine(DB_URL)
Session = sessionmaker(bind=engine)
Base = declarative_base()

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    service = Column(String(50))
    event_type = Column(String(50))
    actor = Column(String(100))
    data = Column(Text)
    previous_hash = Column(String(64))
    current_hash = Column(String(64))

# Intentar crear tablas (esperando a la BD)
for _ in range(5):
    try:
        Base.metadata.create_all(engine)
        break
    except Exception:
        print("Esperando a la Base de Datos...")
        time.sleep(3)

# --- CONFIGURACIÓN DE KAFKA CONSUMER ---
consumer = None
print("Intentando conectar a kafka...")
while not consumer:
    try:
        consumer = KafkaConsumer(
            'hyperion.audit.logs',
            bootstrap_servers=['kafka:9092'],
            auto_offset_reset='earliest',
            group_id='hyperion-ingestors',
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
    except NoBrokersAvailable:
        print("Kafka aún no está disponible. Reintentando en 5 segundos...")
        time.sleep(5)

def get_last_hash(session):
    last_log = session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    return last_log.current_hash if last_log else "0" * 64

print("🚀 Worker Ingestor iniciado. Esperando eventos de Kafka...")

session = Session()
try:
    for message in consumer:
        log_data = message.value
        prev_hash = get_last_hash(session)
        
        # Crear firma inmutable (SHA-256)
        now = datetime.utcnow()
        raw_content = f"{prev_hash}{log_data.get('event_type')}{log_data.get('user', 'system')}{now}"
        curr_hash = hashlib.sha256(raw_content.encode()).hexdigest()
        
        # Guardar en PostgreSQL
        new_log = AuditLog(
            service=log_data.get('service', 'unknown'),
            event_type=log_data.get('event_type', 'INFO'),
            actor=log_data.get('user', 'system'),
            data=json.dumps(log_data),
            previous_hash=prev_hash,
            current_hash=curr_hash,
            timestamp= now
        )
        
        session.add(new_log)
        session.commit()
        print(f"Log anclado: {curr_hash[:16]}... [Prev: {prev_hash[:8]}]")
except Exception as e:
    print(f"Error crítico en el loop: {e}")
    session.rollback()