from kafka import KafkaConsumer
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import json
import hashlib
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

Base.metadata.create_all(engine)

# --- CONFIGURACIÓN DE KAFKA CONSUMER ---
consumer = KafkaConsumer(
    'hyperion.audit.logs',
    bootstrap_servers=['kafka:9092'],
    auto_offset_reset='earliest',
    group_id='hyperion-ingestors',
    value_deserializer=lambda x: json.loads(x.decode('utf-8'))
)

def get_last_hash(session):
    last_log = session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    return last_log.current_hash if last_log else "0" * 64

print("🚀 Worker Ingestor iniciado. Esperando eventos de Kafka...")

session = Session()
for message in consumer:
    log_data = message.value
    prev_hash = get_last_hash(session)
    
    # Crear firma inmutable (SHA-256)
    raw_content = f"{prev_hash}{log_data['event_type']}{log_data['user']}{datetime.utcnow()}"
    curr_hash = hashlib.sha256(raw_content.encode()).hexdigest()
    
    # Guardar en PostgreSQL
    new_log = AuditLog(
        service=log_data.get('service', 'unknown'),
        event_type=log_data['event_type'],
        actor=log_data['user'],
        data=json.dumps(log_data),
        previous_hash=prev_hash,
        current_hash=curr_hash
    )
    
    session.add(new_log)
    session.commit()
    print(f"✅ Log procesado y anclado en DB: {curr_hash[:16]}...")