import streamlit as st
import pandas as pd
import numpy as np
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

# Configuración de página con la estética Hyperion original
st.set_page_config(
    page_title="Hyperion | Bitácora Legal Inmutable",
    page_icon="📜",
    layout="wide"
)

# Estilo CSS personalizado oscuro y profesional (Estilo Darktrace / Hyperion Core)
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; }
    h3 { color: #cbd5e1 !important; }
    .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
    .metric-card { background-color: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 10px; text-align: center; }
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# Parámetros URL transferidos
query_params = st.query_params
operador_transferido = query_params.get("operator", "Sistema Automático")

# 1. Conexión Directa y Segura a la Base de Datos
try:
    if "URI_SUPABASE" in st.secrets:
        db_url = st.secrets["URI_SUPABASE"]
    else:
        db_url = "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
        
    engine = create_engine(db_url)
except Exception as e:
    st.error(f"❌ Error crítico de conexión a la Base de Datos de Auditoría: {e}")
    st.stop()

# Encabezado del Sistema
st.title("📜 Bitácora Legal Hyperion")
st.markdown(f"👤 **Operador en Consola:** `{operador_transferido}` | **Firma de Enlace:** Verified SHA-256")
st.caption("CORE SECURITY NODE // SEMANA 2: DETECCIÓN DE TRÁFICO MALICIOSO (NTA & THREAT INTEL)")

st.markdown("---")

# 2. Filtros e Interfaz de Usuario
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    fecha_desde = st.date_input("Rango de Auditoría: Desde", datetime.now() - timedelta(days=7))
with col2:
    fecha_hasta = st.date_input("Rango de Auditoría: Hasta", datetime.now())
with col3:
    actor_filter = st.text_input("Filtrar por Actor / Operador (Opcional)", "").strip()

# Query Estructurada Histórica
query_str = """
    SELECT * FROM "audit_logs" 
    WHERE timestamp >= :desde AND timestamp <= :hasta
"""
params = {
    "desde": datetime.combine(fecha_desde, datetime.min.time()),
    "hasta": datetime.combine(fecha_hasta, datetime.max.time())
}
if actor_filter:
    query_str += " AND actor ILIKE :actor"
    params["actor"] = f"%{actor_filter}%"
query_str += " ORDER BY timestamp DESC"

# Inicialización de variables de control
total_recs, usuarios_unicos, total_anomalias = 0, 0, 0
df = pd.DataFrame()

# Ejecución Controlada de Datos Históricos
try:
    with engine.connect() as conn:
        df = pd.read_sql(text(query_str), conn, params=params)
    if not df.empty:
        total_recs = len(df)
        col_actor = 'actor' if 'actor' in df.columns else df.columns[1]
        usuarios_unicos = df[col_actor].nunique()
except Exception as e:
    st.error(f"❌ Error al consultar la tabla 'audit_logs': {e}")

# Consultas en Vivo para Nodos Inmunológicos (Semanas 1 y 2)
anomalies_live_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
    total_anomalias += len(anomalies_live_df)
except: pass

darktrace_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats ORDER BY timestamp DESC"), conn)
    total_anomalias += len(darktrace_df)
except: pass

# Consulta de Threat Intel de la Semana 2
threat_intel_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        threat_intel_df = pd.read_sql(text("SELECT * FROM threat_intel ORDER BY created_at DESC"), conn)
except: pass

# 5. RENDERIZADO DE KPI's GENERALES
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="📊 Volumen de Eventos", value=f"{total_recs} registros", delta="Filtro Activo")
with m2:
    st.metric(label="👤 Operadores Activos", value=f"{usuarios_unicos} usuarios", delta="Bajo Auditoría", delta_color="off")
with m3:
    color_alerta = "inverse" if total_anomalias > 0 else "normal"
    st.metric(label="🚨 Alertas Activas (C1 + C2)", value=f"{total_anomalias} críticas", delta="Acción Requerida" if total_anomalias > 0 else "Estable", delta_color=color_alerta)
with m4:
    st.metric(label="🎯 Feeds Threat Intel", value=f"{len(threat_intel_df)} IoCs activos", delta="Semana 2 Sincronizada")

st.write("---")

tab_logs, tab_immune, tab_darktrace = st.tabs([
    "📋 Bitácora de Logs Estructurada", 
    "🛡️ Hyperion Immune Gateway (UEBA)", 
    "🌐 Darktrace Cyber AI Node & Threat Intel"
])

# PESTAÑA 1: LOGS HISTÓRICOS
with tab_logs:
    st.subheader("Registros Totales del Sistema")
    if not df.empty:
        st.dataframe(df, use_container_width=True)
    else:
        st.warning("⚠️ No se encontraron eventos de seguridad históricos en el rango de fechas seleccionado.")

# PESTAÑA 2: UEBA (CAPA 1)
with tab_immune:
    st.subheader("🕵️ Análisis de Comportamiento de Usuarios (User Behavior Analytics)")
    if not anomalies_live_df.empty:
        for idx, row in anomalies_live_df.iterrows():
            with st.container():
                c_info, c_action = st.columns([3, 1])
                with c_info:
                    st.markdown(f"**🔔 Operador:** `{row['user_email']}` | **Severidad:** `{row['severity'].upper()}`")
                    st.warning(f"⚠️ **Incidente:** {row['description']}")
                with c_action:
                    st.write("")
                    if st.button("🚫 Aislar e Inhabilitar", key=f"block_{row['id']}"):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'),
                                        {"actor": "HYPERION_SOAR", "action": f"USER_ISOLATED: Mitigación contra {row['user_email']}"})
                                    conn.execute(text("DELETE FROM behavior_anomalies WHERE id = :id"), {"id": row['id']})
                            st.toast(f"🔒 Operador {row['user_email']} mitigado con éxito.", icon="🛡️")
                            st.rerun()
                        except Exception as e: st.error(f"Error: {e}")
                st.markdown("---")
    else:
        st.success("🟢 Matriz UEBA estable. No se registran desvíos de operadores.")

# PESTAÑA 3: DARKTRACE & THREAT INTEL (CAPA 2 - SEMANA 2 COMPLETA)
with tab_darktrace:
    st.subheader("🌐 Darktrace Threat Visualization Platform")
    st.caption("TELEMETRÍA NTA POR INTELIGENCIA ADAPTATIVA CRUZADA CON FEEDS DE COMPROMISO")
    
    # Renderizar el panel interactivo si hay amenazas
    if not darktrace_df.empty:
        col_mapa, col_stats = st.columns([2, 1])
        
        with col_mapa:
            st.markdown("#### 🗺️ Mapa de Amenazas Activas (C2 / Exfiltración)")
            map_data = darktrace_df[['latitude', 'longitude']].dropna()
            map_data.columns = ['lat', 'lon']
            st.map(map_data, zoom=1, use_container_width=True)
            
            # Sub-sección para visualizar la base de conocimiento de la Semana 2
            st.markdown("#### 📑 Repositorio Activo de Threat Intelligence (IoC)")
            st.dataframe(threat_intel_df, use_container_width=True, hide_index=True)
            
        with col_stats:
            st.markdown("#### 🚨 Tácticas Mitre Procesadas")
            lista_negra_ips = threat_intel_df['indicator'].tolist() if not threat_intel_df.empty else []
            
            for idx, row in darktrace_df.iterrows():
                # Detección dinámica Semana 2: ¿La IP está en nuestra lista negra de Threat Intel?
                es_intel_match = row['source_ip'] in lista_negra_ips or row['dest_ip'] in lista_negra_ips
                badge_color = "🔴 CRÍTICO" if es_intel_match else "🟡 SOSPECHOSO"
                
                with st.container():
                    st.markdown(f"**{badge_color}** | Táctica: `{row['mitre_tactic']}`")
                    st.caption(f"Origen: `{row['source_ip']}` ➔ Destino: `{row['dest_ip']}`")
                    
                    if es_intel_match:
                        st.error(f"⚠️ **ALERTA CAPA 2:** Tráfico detectado contra servidor C2 registrado en Threat Intel Feed.")
                    else:
                        st.info(f"Inspección de paquete estándar: {row['threat_type']}")
                    
                    # El Killswitch infalible de Hyperion SOAR
                    if st.button("✂️ Cortar Conexión (Killswitch)", key=f"dt_{row['id']}"):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'DARKTRACE_SOAR\', :action)'),
                                        {"action": f"KILLSWITCH_ACTIVATED: Socket IP {row['source_ip']} terminado de raíz."})
                                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                            st.toast(f"💥 Killswitch activado para la IP {row['source_ip']}", icon="🚫")
                            st.rerun()
                        except Exception as tx_err:
                            st.error(f"Error en Killswitch: {tx_err}")
                st.markdown("---")
    else:
        st.success("🟢 Darktrace Analysis Node clear: No se han identificado firmas C2 en el tráfico perimetral.")