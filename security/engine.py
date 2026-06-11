import pandas as pd
from sqlalchemy import create_engine, text

def analyze_perimeter_traffic(engine):
    """
    Motor NTA de Hyperion: Cruza las amenazas activas con el feed de Threat Intelligence
    y analiza patrones de exfiltración o escaneo profundo.
    """
    try:
        with engine.connect() as conn:
            # 1. Obtener la lista negra de Threat Intelligence
            intel_df = pd.read_sql(text("SELECT indicator, type, severity FROM threat_intel"), conn)
            
            # 2. Consultar el tráfico de red actual en Darktrace
            darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats"), conn)
            
            if darktrace_df.empty or intel_df.empty:
                return []
                
            # 3. Algoritmo de Cruce Adaptativo
            alertas_detectadas = []
            lista_negra_ips = intel_df['indicator'].tolist()
            
            for idx, row in darktrace_df.iterrows():
                # Regla C2: Si el destino o el origen están en Threat Intel
                if row['source_ip'] in lista_negra_ips or row['dest_ip'] in lista_negra_ips:
                    intel_match = intel_df[intel_df['indicator'] == row['source_ip']].to_dict('records')
                    tipo_amenaza = intel_match[0]['type'] if intel_match else "Conexión C2 Sospechosa"
                    
                    alertas_detectadas.append({
                        "id": row['id'],
                        "origen": row['source_ip'],
                        "destino": row['dest_ip'],
                        "tactica": row['mitre_tactic'],
                        "tipo": f"🚨 [MATCH INTEL] - {tipo_amenaza.upper()}",
                        "severidad": "critical"
                    })
            
            return alertas_detectadas
    except Exception as e:
        print(f"[-] Error en el motor NTA: {e}")
        return []