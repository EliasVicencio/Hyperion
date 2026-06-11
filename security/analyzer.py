import pandas as pd
from sqlalchemy import text
from security.soar_core import HyperionSOARCore

class HyperionNTAEngine:
    def __init__(self, db_engine):
        self.engine = db_engine
        self.soar = HyperionSOARCore(db_engine) # Inyección de la Capa 3 Avanzada

    def fetch_threat_intel(self):
        """Obtiene las IPs reputacionales en lista negra de la Semana 2."""
        query = 'SELECT indicator, type, severity FROM threat_intel'
        try:
            with self.engine.connect() as conn:
                dbapi_conn = conn.connection
                return pd.read_sql_query(query, con=dbapi_conn)
        except Exception as e:
            print(f"[-] Error al leer Threat Intel: {e}")
            return pd.DataFrame()

    def analyze_traffic_packet(self, raw_packet_logs):
        """Analiza logs crudos de red (DPI) y gatilla playbooks según severidad."""
        intel_df = self.fetch_threat_intel()
        blacklisted_ips = intel_df['indicator'].tolist() if not intel_df.empty else []
        
        threats_to_persist = []

        # --- REGLA 1: DETECCIÓN DE COMUNICACIÓN C2 ---
        for idx, log in raw_packet_logs.iterrows():
            if log['dest_ip'] in blacklisted_ips:
                intel_match = intel_df[intel_df['indicator'] == log['dest_ip']].iloc[0]
                threat = {
                    "source_ip": log['source_ip'],
                    "dest_ip": log['dest_ip'],
                    "threat_type": f"Conexión activa a C2 conocido ({intel_match['type']})",
                    "mitre_tactic": "Command and Control (TA0011)",
                    "severity": "critical", # Escalado a crítico por política de la Semana 3
                    "latitude": 40.7128, "longitude": -74.0060, "country_code": "US",
                    "user_email": "atila_hacker@hyperion.com" # Simulación de usuario comprometido usando la IP
                }
                # Ejecución automatizada del Playbook Crítico
                self.soar.execute_playbook('critical', threat)
                threats_to_persist.append(threat)

        # --- REGLA 2: DETECCIÓN DE EXFILTRACIÓN DE DATOS ---
        traffic_volume = raw_packet_logs.groupby('source_ip')['bytes_sent'].sum().reset_index()
        for idx, row in traffic_volume.iterrows():
            if row['bytes_sent'] > 104857600: # > 100MB
                last_dest = raw_packet_logs[raw_packet_logs['source_ip'] == row['source_ip']].iloc[-1]['dest_ip']
                threat = {
                    "source_ip": row['source_ip'],
                    "dest_ip": last_dest,
                    "threat_type": f"Anomalía de volumen: Exfiltración de {round(row['bytes_sent']/1024/1024, 2)} MB",
                    "mitre_tactic": "Exfiltration (TA0010)",
                    "severity": "high",
                    "latitude": -33.4489, "longitude": -70.6693, "country_code": "CL",
                    "user_email": "exfil_user@hyperion.com"
                }
                # Ejecución automatizada del Playbook Alto
                self.soar.execute_playbook('high', threat)
                threats_to_persist.append(threat)

        # --- REGLA 3: ESCANEO DE PUERTOS (PORT SCANNING) ---
        port_scans = raw_packet_logs.groupby(['source_ip', 'dest_ip'])['dest_port'].nunique().reset_index()
        for idx, row in port_scans.iterrows():
            if row['dest_port'] > 10:
                threat = {
                    "source_ip": row['source_ip'],
                    "dest_ip": row['dest_ip'],
                    "threat_type": f"Escaneo horizontal detectado ({row['dest_port']} puertos)",
                    "mitre_tactic": "Discovery (TA0007)",
                    "severity": "medium",
                    "latitude": 51.5074, "longitude": -0.1278, "country_code": "UK"
                }
                # Ejecución automatizada del Playbook Medio
                self.soar.execute_playbook('medium', threat)
                threats_to_persist.append(threat)

        if threats_to_persist:
            self.persist_threats(threats_to_persist)

    def persist_threats(self, threats):
        query = """
            INSERT INTO darktrace_network_threats 
            (source_ip, dest_ip, threat_type, mitre_tactic, severity, latitude, longitude, country_code)
            VALUES (:source_ip, :dest_ip, :threat_type, :mitre_tactic, :severity, :latitude, :longitude, :country_code)
        """
        try:
            with self.engine.connect() as conn:
                with conn.begin():
                    for t in threats:
                        conn.execute(text(query), {
                            "source_ip": t["source_ip"], "dest_ip": t["dest_ip"],
                            "threat_type": t["threat_type"], "mitre_tactic": t["mitre_tactic"],
                            "severity": t["severity"], "latitude": t["latitude"],
                            "longitude": t["longitude"], "country_code": t["country_code"]
                        })
        except Exception as e:
            print(f"[-] Error al guardar amenazas perimetrales: {e}")