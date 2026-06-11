import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

# Configuración de página de nivel Enterprise
st.set_page_config(
    page_title="Hyperion | Unified SOAR Platform",
    page_icon="🛡️",
    layout="wide"
)

# Estilo CSS personalizado oscuro, limpio y profesional
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
operador_transferido = query_params.get("operator", "Control Central")

# 1. Conexión de Datos Directa a Supabase
try:
    db_url = "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
    engine = create_engine(db_url)
except Exception as e:
    st.error(f"❌ Error crítico de conexión: {e}")
    st.stop()

# Encabezado de la Plataforma
st.title("🛡️ Hyperion Autonomous SOAR - Consola de Comando")
st.markdown(f"👤 **Operador Actual:** `{operador_transferido}` | **Nodo de Control:** Perimetral Integrado")
st.caption("CONSOLIDACIÓN FINAL // SEMANA 4: PLATAFORMA UNIFICADA DE AMENAZAS Y GESTIÓN DE FALSOS POSITIVOS")

st.markdown("---")

# Interfaz de Filtros Temporales para Auditoría
col1, col2 = st.columns(2)
with col1:
    fecha_desde = st.date_input("Auditar Desde", datetime.now() - timedelta(days=7))
with col2:
    fecha_hasta = st.date_input("Auditar Hasta", datetime.now())

# Consulta de Ledger Histórico CORREGIDA
query_str = """
    SELECT * FROM "audit_logs" 
    WHERE timestamp >= :desde AND timestamp <= :hasta 
    ORDER BY timestamp DESC
"""
params = {
    "desde": datetime.combine(fecha_desde, datetime.min.time()),
    "hasta": datetime.combine(fecha_hasta, datetime.max.time())
}

df_ledger = pd.DataFrame()
try:
    with engine.connect() as conn:
        df_ledger = pd.read_sql(text(query_str), conn, params=params)
except Exception as e:
    st.error(f"Error al leer Ledger: {e}")

# --- CONSULTAS EN CALIENTE PARA ALERTAS Y KPIs ---
anomalies_live_df = pd.DataFrame()
darktrace_df = pd.DataFrame()
firewall_blocks_df = pd.DataFrame()
jwt_blacklist_df = pd.DataFrame()
allowlist_df = pd.DataFrame()

try:
    with engine.connect() as conn:
        # Capa 1: UEBA Anomalías
        anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
        # Capa 2: Darktrace NTA
        darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats ORDER BY timestamp DESC"), conn)
        # Capa 3: Bloqueos SOAR
        firewall_blocks_df = pd.read_sql(text("SELECT blocked_ip, duration_minutes, blocked_at, expires_at, reason FROM firewall_network_blocks ORDER BY blocked_at DESC"), conn)
        jwt_blacklist_df = pd.read_sql(text("SELECT user_email, revoked_at, reason FROM jwt_blacklist ORDER BY revoked_at DESC"), conn)
        # Capa 4: Allowlist Exclusiones
        allowlist_df = pd.read_sql(text("SELECT target, target_type, authorized_by, reason, created_at FROM security_allowlist ORDER BY created_at DESC"), conn)
except Exception as e:
    st.sidebar.error(f"Error cargando telemetría en vivo: {e}")

# Cálculo del consolidado de alertas activas
total_alertas_activas = len(anomalies_live_df) + len(darktrace_df)

# --- RENDERIZADO DE KPI'S CORPORATIVOS ---
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="📊 Eventos Históricos (Ledger)", value=f"{len(df_ledger)} registros")
with m2:
    st.metric(label="🚨 Alertas Activas Consolidadas", value=f"{total_alertas_activas} incidentes", delta="Acción Requerida", delta_color="inverse")
with m3:
    st.metric(label="🔒 Cuarentenas de Red (Firewall)", value=f"{len(firewall_blocks_df)} IPs")
with m4:
    st.metric(label="💀 Sesiones JWT Invalidadas", value=f"{len(jwt_blacklist_df)} usuarios")

st.write("---")

# Estructura de Navegación por Pestañas Core Re-estructurada
tab_logs, tab_unified_threats, tab_soar, tab_falsos_positivos = st.tabs([
    "📋 Bitácora Legal Histórica",
    "🌐 Centro Unificado de Amenazas (UEBA + Darktrace)", 
    "⚡ Hyperion SOAR Control Center",
    "⚙️ Gestión de Falsos Positivos & Allowlist"
])

# PESTAÑA 1: BITÁCORA LEGAL Y REPORTE EJECUTIVO
with tab_logs:
    st.subheader("Registros del Ledger Inmutable (SOC2 / NIST Compliance)")
    if not df_ledger.empty:
        csv_data = df_ledger.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Descargar Reporte Ejecutivo de Auditoría (CSV)",
            data=csv_data,
            file_name=f"hyperion_audit_report_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )
        st.write("")
        st.dataframe(df_ledger, use_container_width=True, hide_index=True)
    else:
        st.warning("No se registran eventos de seguridad históricos en el intervalo seleccionado.")

# PESTAÑA 2: CENTRO UNIFICADO DE AMENAZAS (¡AQUÍ ESTÁ DE VUELTA TODO TU DARKTRACE + UEBA!)
with tab_unified_threats:
    st.subheader("📡 Monitoreo Perimetral e Interno en Tiempo Real")
    
    # Renderizado del mapa perimetral si hay datos de Darktrace
    if not darktrace_df.empty:
        col_mapa, col_stats = st.columns([2, 1])
        with col_mapa:
            st.markdown("#### 🗺️ Geolocalización de Amenazas NTA (Darktrace)")
            map_data = darktrace_df[['latitude', 'longitude']].dropna()
            map_data.columns = ['lat', 'lon']
            st.map(map_data, zoom=1, use_container_width=True)
            
        with col_stats:
            st.markdown("#### 🚨 Vectores Críticos Destacados")
            for idx, row in darktrace_df.head(3).iterrows():
                st.error(f"**{row['severity'].upper()}** | Táctica: `{row['mitre_tactic']}`\n\n{row['threat_type']}")
    else:
        st.info("💡 Sin coordenadas perimetrales activas para graficar en el mapa en este instante.")

    st.write("---")
    
    # Division en dos columnas para gestionar Alertas de Red (Darktrace) y Alertas de Usuario (UEBA)
    col_dt, col_ueba = st.columns(2)
    
    with col_dt:
        st.markdown("#### 🌐 Alertas Perimetrales Darktrace (NTA & Threat Intel)")
        if not darktrace_df.empty:
            for idx, row in darktrace_df.iterrows():
                with st.container():
                    st.markdown(f"**📍 Origen:** `{row['source_ip']}` ➔ **Destino:** `{row['dest_ip']}`")
                    st.caption(f"🛡️ Táctica Mitre: `{row['mitre_tactic']}` | Severidad: `{row['severity'].upper()}`")
                    st.markdown(f"**Detalle:** {row['threat_type']}")
                    
                    if st.button("✂️ Ejecutar Killswitch Manual", key=f"dt_uni_{idx}"):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'DARKTRACE_SOAR\', :action)'),
                                        {"action": f"MANUAL_KILLSWITCH: Flujo de la IP {row['source_ip']} terminado por el operador."})
                                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                            st.toast(f"💥 Killswitch inyectado para la IP {row['source_ip']}", icon="🚫")
                            st.rerun()
                        except Exception as tx_err: st.error(f"Error: {tx_err}")
                    st.markdown("---")
        else:
            st.success("🟢 No hay alertas perimetrales pendientes de mitigación.")

    with col_ueba:
        st.markdown("#### 🕵️ Alertas de Comportamiento Interno (UEBA)")
        if not anomalies_live_df.empty:
            for idx, row in anomalies_live_df.iterrows():
                with st.container():
                    st.markdown(f"**👤 Usuario Comprometido:** `{row['user_email']}`")
                    st.caption(f"⚠️ Severidad: `{row['severity'].upper()}` | Estado: `Activo`")
                    st.warning(f"**Desvío:** {row['description']}")
                    
                    if st.button("🚫 Aislar Usuario Manualmente", key=f"ueba_uni_{idx}"):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'),
                                        {"actor": "HYPERION_SOAR", "action": f"USER_ISOLATED: Mitigación manual aplicada contra {row['user_email']}"})
                                    conn.execute(text("DELETE FROM behavior_anomalies WHERE id = :id"), {"id": row['id']})
                            st.toast(f"🔒 Sesión de {row['user_email']} aislada con éxito.", icon="🛡️")
                            st.rerun()
                        except Exception as e: st.error(f"Error: {e}")
                    st.markdown("---")
        else:
            st.success("🟢 Matriz UEBA interna limpia. Comportamiento de operadores estable.")

# PESTAÑA 3: VISUALIZACIÓN DEL CORTE DE TRÁFICO SOAR (SEMANA 3)
with tab_soar:
    st.subheader("Estado Inmunológico del Sistema")
    c_fw, c_jwt = st.columns(2)
    
    with c_fw:
        st.markdown("#### 🔒 Aislamiento Perimetral Activo en Firewall")
        if not firewall_blocks_df.empty:
            st.dataframe(firewall_blocks_df, use_container_width=True, hide_index=True)
        else:
            st.success("🟢 Cortafuegos limpio. Cero bloqueos perimetrales aplicados.")
            
    with c_jwt:
        st.markdown("#### 💀 Sesiones JWT Revocadas / Lista Negra")
        if not jwt_blacklist_df.empty:
            st.dataframe(jwt_blacklist_df, use_container_width=True, hide_index=True)
        else:
            st.success("🟢 Cero tokens comprometidos en lista negra.")

# PESTAÑA 4: ADMINISTRACIÓN DE FALSOS POSITIVOS (SEMANA 4)
with tab_falsos_positivos:
    st.subheader("⚙️ Reglas de Exclusión de Confianza y Eventos Mutados")
    st.caption("Si un activo bajo ataque se encuentra listado aquí, Hyperion registrará un 'MUTED_EVENT' omitiendo el corte de servicio de forma segura.")
    
    with st.expander("➕ Añadir Nueva Exclusión (IP / Usuario Legitimo)"):
        with st.form("new_allowlist_form", clear_on_submit=True):
            f_target = st.text_input("Objetivo (IP o Email del Usuario)", placeholder="Ej: 192.168.1.50 / servicio_backup@hyperion.com").strip()
            f_type = st.selectbox("Tipo de Activo", ["ip", "user"])
            f_reason = st.text_input("Justificación de la Regla", placeholder="Ej: Escáner de seguridad aprobado por el área de TI")
            
            submit_btn = st.form_submit_button("Autorizar e Insertar Regla")
            if submit_btn and f_target:
                try:
                    with engine.connect() as conn:
                        with conn.begin():
                            conn.execute(text("""
                                INSERT INTO security_allowlist (target, target_type, authorized_by, reason)
                                VALUES (:target, :type, :auth, :reason)
                                ON CONFLICT (target) DO UPDATE SET reason = EXCLUDED.reason
                            """), {"target": f_target, "type": f_type, "auth": operador_transferido, "reason": f_reason})
                            
                            conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (:actor, :action)'), {
                                "actor": "HYPERION_POLICY_MANAGER",
                                "action": f"ALLOWLIST_MODIFIED: {operador_transferido} añadió exclusión para el {f_type.upper()} [{f_target}]."
                            })
                    st.toast(f"✅ Regla de exclusión inyectada con éxito para: {f_target}", icon="🛡️")
                    st.rerun()
                except Exception as ex:
                    st.error(f"Error al guardar la regla: {ex}")

    st.markdown("#### 📋 Listado Activo de Exclusiones Autorizadas")
    if not allowlist_df.empty:
        st.dataframe(allowlist_df, use_container_width=True, hide_index=True)
    else:
        st.info("No hay reglas de exclusión configuradas. Toda alerta analítica disparará contención automática.")