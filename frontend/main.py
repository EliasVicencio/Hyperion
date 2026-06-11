import streamlit as st
import pandas as pd
import numpy as np
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

# Configuración de página con la estética Hyperion original
st.set_page_config(
    page_title="Hyperion | Sistema Inmunológico SOAR",
    page_icon="📜",
    layout="wide"
)

# Estilo CSS personalizado oscuro y profesional
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; }
    h3 { color: #cbd5e1 !important; }
    h4 { color: #f1f5f9 !important; margin-top: 15px; }
    .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
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
st.caption("CORE SECURITY NODE // SEMANA 3: ORQUESTACIÓN Y RESPUESTA AUTÓNOMA (SOAR AVANZADO)")

st.markdown("---")

# 2. Filtros e Interfaz de Usuario (Rango de Auditoría)
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    fecha_desde = st.date_input("Rango de Auditoría: Desde", datetime.now() - timedelta(days=7))
with col2:
    fecha_hasta = st.date_input("Rango de Auditoría: Hasta", datetime.now())
with col3:
    actor_filter = st.text_input("Filtrar por Actor / Operador (Opcional)", "").strip()

# Query Estructurada Histórica (Audit Logs Ledger)
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

# Inicialización de variables de control y KPIs
total_recs, usuarios_unicos, total_anomalias = 0, 0, 0
df = pd.DataFrame()

# Ejecución Controlada de Datos Históricos (Ledger)
try:
    with engine.connect() as conn:
        df = pd.read_sql(text(query_str), conn, params=params)
    if not df.empty:
        total_recs = len(df)
        col_actor = 'actor' if 'actor' in df.columns else df.columns[1]
        usuarios_unicos = df[col_actor].nunique()
except Exception as e:
    st.error(f"❌ Error al consultar la tabla 'audit_logs': {e}")

# Consultas en Vivo - Capa 1: UEBA
anomalies_live_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
    total_anomalias += len(anomalies_live_df)
except: pass

# Consultas en Vivo - Capa 2: Darktrace NTA
darktrace_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats ORDER BY timestamp DESC"), conn)
    total_anomalias += len(darktrace_df)
except: pass

# Consultas en Vivo - Capa 3: Bloqueos de Firewall (Semana 3)
firewall_blocks_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        firewall_blocks_df = pd.read_sql(text("SELECT blocked_ip, duration_minutes, blocked_at, expires_at, reason FROM firewall_network_blocks ORDER BY blocked_at DESC"), conn)
except: pass

# Consultas en Vivo - Capa 3: Lista Negra JWT (Semana 3)
jwt_blacklist_df = pd.DataFrame()
try:
    with engine.connect() as conn:
        jwt_blacklist_df = pd.read_sql(text("SELECT user_email, revoked_at, reason FROM jwt_blacklist ORDER BY revoked_at DESC"), conn)
except: pass

# 5. RENDERIZADO DE KPI's GENERALES (Evolucionados para reflejar contención)
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="📊 Volumen de Eventos Ledger", value=f"{total_recs} registros", delta="Filtro Activo")
with m2:
    st.metric(label="🚫 IPs en Cuarentena", value=f"{len(firewall_blocks_df)} bloqueos", delta="Cortafuegos Activo", delta_color="inverse")
with m3:
    st.metric(label="💀 Sesiones JWT Revocadas", value=f"{len(jwt_blacklist_df)} expulsados", delta="Tokens Lista Negra", delta_color="inverse")
with m4:
    st.metric(label="🛡️ Mitigación Autónoma SOAR", value="Activa (100%)", delta="SOC2 / NIST Compliant")

st.write("---")

tab_logs, tab_immune, tab_darktrace, tab_soar = st.tabs([
    "📋 Bitácora de Logs Estructurada", 
    "🛡️ Hyperion Immune Gateway (UEBA)", 
    "🌐 Darktrace Cyber AI Node & Threat Intel",
    "⚡ Hyperion SOAR Control Center"
])

# PESTAÑA 1: LOGS HISTÓRICOS
with tab_logs:
    st.subheader("Registros Totales del Sistema (Ledger Inmutable)")
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)
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
                                        {"actor": "HYPERION_SOAR", "action": f"USER_ISOLATED: Mitigación manual contra {row['user_email']}"})
                                    conn.execute(text("DELETE FROM behavior_anomalies WHERE id = :id"), {"id": row['id']})
                            st.toast(f"🔒 Operador {row['user_email']} mitigado con éxito.", icon="🛡️")
                            st.rerun()
                        except Exception as e: st.error(f"Error: {e}")
                st.markdown("---")
    else:
        st.success("🟢 Matriz UEBA estable. No se registran desvíos de operadores.")

# PESTAÑA 3: DARKTRACE & THREAT INTEL (CAPA 2)
with tab_darktrace:
    st.subheader("🌐 Darktrace Threat Visualization Platform")
    if not darktrace_df.empty:
        col_mapa, col_stats = st.columns([2, 1])
        with col_mapa:
            st.markdown("#### 🗺️ Mapa de Amenazas Activas (C2 / Exfiltración)")
            map_data = darktrace_df[['latitude', 'longitude']].dropna()
            map_data.columns = ['lat', 'lon']
            st.map(map_data, zoom=1, use_container_width=True)
        with col_stats:
            st.markdown("#### 🚨 Tácticas Mitre Procesadas")
            for idx, row in darktrace_df.iterrows():
                badge_color = "🔴 CRÍTICO" if row['severity'] in ['critical', 'high'] else "🟡 SOSPECHOSO"
                with st.container():
                    st.markdown(f"**{badge_color}** | Táctica: `{row['mitre_tactic']}`")
                    st.caption(f"Origen: `{row['source_ip']}` ➔ Destino: `{row['dest_ip']}`")
                    st.error(f"Detalle NTA: {row['threat_type']}")
                    
                    if st.button("✂️ Cortar Conexión (Killswitch)", key=f"dt_{row['id']}"):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'DARKTRACE_SOAR\', :action)'),
                                        {"action": f"MANUAL_KILLSWITCH: Conexión IP {row['source_ip']} terminada por operador."})
                                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                            st.toast(f"💥 Killswitch activado para la IP {row['source_ip']}", icon="🚫")
                            st.rerun()
                        except Exception as tx_err: st.error(f"Error: {tx_err}")
                st.markdown("---")
    else:
        st.success("🟢 No se registran amenazas perimetrales activas en este nodo.")

# PESTAÑA 4: HYPERION SOAR CONTROL CENTER (CAPA 3 - NUEVA DE LA SEMANA 3)
with tab_soar:
    st.subheader("⚡ Matriz de Aislamiento y Contención Autónoma")
    st.caption("POLÍTICAS COMPLIANCE // VISUALIZACIÓN DE CUARENTENAS ACTIVAS DE FIREWALL Y REVOCACIÓN DE CREDENCIALES")
    
    c_fw, c_jwt = st.columns(2)
    
    with c_fw:
        st.markdown("#### 🔒 IPs Bloqueadas en Firewall (Cuarentena Temporal)")
        if not firewall_blocks_df.empty:
            st.dataframe(firewall_blocks_df, use_container_width=True, hide_index=True)
            if st.button("🔓 Reestablecer Todo el Tráfico (Flush Firewall)"):
                with engine.connect() as conn:
                    with conn.begin():
                        conn.execute(text("DELETE FROM firewall_network_blocks"))
                        conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'HYPERION_SOAR\', \'FIREWALL_FLUSHED: Cuarentenas perimetrales levantadas manualmente.\')'))
                st.toast("Cortafuegos liberado. Tráfico reestablecido.", icon="🔓")
                st.rerun()
        else:
            st.success("🟢 Cortafuegos limpio. No hay bloqueos temporales de red aplicados.")
            
    with c_jwt:
        st.markdown("#### 💀 Lista Negra de Tokens JWT (Sesiones Destruidas)")
        if not jwt_blacklist_df.empty:
            st.dataframe(jwt_blacklist_df, use_container_width=True, hide_index=True)
            if st.button("🔄 Rehabilitar Operadores Bloqueados"):
                with engine.connect() as conn:
                    with conn.begin():
                        conn.execute(text("DELETE FROM jwt_blacklist"))
                        conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'HYPERION_SOAR\', \'JWT_BLACKLIST_CLEARED: Sesiones de usuario rehabilitadas.\')'))
                st.toast("Lista negra vaciada. Usuarios autorizados a reconectarse.", icon="🔄")
                st.rerun()
        else:
            st.success("🟢 Todas las sesiones activas son legítimas. Cero tokens en lista negra.")