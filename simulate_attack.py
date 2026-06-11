import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import pandas as pd
from sqlalchemy import create_engine
from security.analyzer import HyperionNTAEngine

# 1. Instanciar la conexión a tu base de datos real
db_url = "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
engine = create_engine(db_url)

# 2. Inicializar el motor de inspección profunda
nta_engine = HyperionNTAEngine(engine)

print("[*] Generando ráfagas de tráfico malicioso simulado para inspección profunda...")

# Crear logs crudos de red que activarán las 3 reglas del motor de Hyperion
mock_logs = pd.DataFrame([
    # Tráfico cruzando con IP en Threat Intel (185.220.101.5 es C2 de AlienVault)
    {"source_ip": "192.168.1.15", "dest_ip": "185.220.101.5", "dest_port": 443, "bytes_sent": 512, "timestamp": "2026-06-10 12:00:00"},
    
    # Simulación de Exfiltración masiva (>100MB enviados por una sola IP de origen)
    {"source_ip": "192.168.1.110", "dest_ip": "203.0.113.50", "dest_port": 80, "bytes_sent": 110000000, "timestamp": "2026-06-10 12:01:00"},
    
    # Simulación de Escaneo de Puertos (Una IP atacando más de 10 puertos distintos en ráfaga)
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 21, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:00"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 22, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:01"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 23, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:02"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 25, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:03"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 80, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:04"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 110, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:05"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 443, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:06"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 445, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:07"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 1433, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:08"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 3306, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:09"},
    {"source_ip": "45.227.254.12", "dest_ip": "192.168.1.1", "dest_port": 8080, "bytes_sent": 64, "timestamp": "2026-06-10 12:02:10"},
])

# 3. Procesar logs con las reglas analíticas autónomas
nta_engine.analyze_traffic_packet(mock_logs)

print("[+] Análisis completado. Revisa tu panel Streamlit en la pestaña Darktrace.")