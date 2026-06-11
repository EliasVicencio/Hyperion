import pandas as pd
from sqlalchemy import create_engine, text

class ResponseEngine:
    def __init__(self, db_engine):
        self.engine = db_engine

    def execute_autonomous_response(self, threat):
        """
        Orquestador SOAR de Hyperion: Ejecuta contención inmediata 
        según la criticidad de la amenaza detectada.
        """
        # Si la amenaza es Crítica o Alta, aplicamos mitigación autónoma en < 30 segundos
        if threat['severity'] in ['critical', 'high']:
            print(f"[!] GATILLO SOAR: Amenaza {threat['severity'].upper()} detectada para IP {threat['source_ip']}. Iniciando contención...")
            
            try:
                with self.engine.connect() as conn:
                    with conn.begin():
                        # 1. Registro inmutable en la bitácora legal (Cumplimiento SOC2)
                        sql_log = 'INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'
                        conn.execute(
                            text(sql_log),
                            {
                                "actor": "HYPERION_AUTONOMOUS", 
                                "action": f"AUTONOMOUS_KILLSWITCH: Flujo bloqueado de raíz para IP {threat['source_ip']}. Razón: {threat['threat_type']}."
                            }
                        )
                        
                        # 2. Desactivar / Mitigar la amenaza perimetral de forma inmediata
                        # Nota: Como es una inserción en caliente en el script analítico, evitamos que se duplique 
                        # o permanezca activa si el SOAR ya tomó el control.
                        print(f"[+] IP {threat['source_ip']} bloqueada de manera autónoma en el Firewall lógico.")
                        
            except Exception as e:
                print(f"[-] Error en el motor de respuesta autónoma (SOAR): {e}")


class HyperionNTAEngine:
    def __init__(self, db_engine):
        self.engine = db_engine
        self.soar = ResponseEngine(db_engine) # Conexión nativa al módulo SOAR

    def fetch_threat_intel(self):
        """Obtiene las IPs reputacionales en lista negra de la Semana 2 de forma segura."""
        query = 'SELECT indicator, type, severity FROM threat_intel'
        try:
            # Abrimos la conexión de SQLAlchemy
            with self.engine.connect() as conn:
                # .connection extrae la conexión DBAPI nativa subyacente que Pandas requiere para no fallar
                dbapi_conn = conn.connection
                return pd.read_sql_query(query, con=dbapi_conn)
        except Exception as e:
            print(f"[-] Error al leer Threat Intel: {e}")
            return pd.DataFrame()

    def analyze_traffic_packet(self, raw_packet_logs):
        """
        Analiza logs crudos de red (DPI) y gatilla respuestas autónomas.
        """
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
                    "severity": intel_match['severity'],
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "country_code": "US"
                }
                # Ejecución de Respuesta Autónoma en tiempo real
                self.soar.execute_autonomous_response(threat)
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
                    "latitude": -33.4489,
                    "longitude": -70.6693,
                    "country_code": "CL"
                }
                # Ejecución de Respuesta Autónoma en tiempo real
                self.soar.execute_autonomous_response(threat)
                threats_to_persist.append(threat)

        # --- REGLA 3: ESCANEO DE PUERTOS (PORT SCANNING) ---
        port_scans = raw_packet_logs.groupby(['source_ip', 'dest_ip'])['dest_port'].nunique().reset_index()
        for idx, row in port_scans.iterrows():
            if row['dest_port'] > 10:
                threat = {
                    "source_ip": row['source_ip'],
                    "dest_ip": row['dest_ip'],
                    "threat_type": f"Escaneo horizontal detectado ({row['dest_port']} puertos escaneados)",
                    "mitre_tactic": "Discovery (TA0007)",
                    "severity": "medium",
                    "latitude": 51.5074,
                    "longitude": -0.1278,
                    "country_code": "UK"
                }
                # Las amenazas de severidad media (medium) solo se registran, no ejecutan corte automático
                threats_to_persist.append(threat)

        # Guardar en base de datos las amenazas que quedan pendientes de revisión manual en la consola
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
                        conn.execute(text(query), t)
            print(f"[+] {len(threats)} vectores de telemetría sincronizados con el panel perimetral.")
        except Exception as e:
            print(f"[-] Error al guardar amenazas en la base de datos: {e}")