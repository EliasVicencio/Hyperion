import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"

# Configuración de página de nivel Enterprise
st.set_page_config(
    page_title="Hyperion | Enterprise SOAR Platform",
    page_icon=LOGO_SVG,
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
    [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #1f2937; }
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

# --- CONSULTAS EN CALIENTE PARA ALERTAS, LEDGER Y KPIs ---
fecha_desde = datetime.now() - timedelta(days=7)
fecha_hasta = datetime.now()

# Esto lo dejamos global para alimentar los contadores del Sidebar y del Header
df_ledger = pd.DataFrame()
anomalies_live_df = pd.DataFrame()
darktrace_df = pd.DataFrame()
firewall_blocks_df = pd.DataFrame()
jwt_blacklist_df = pd.DataFrame()
allowlist_df = pd.DataFrame()

try:
    with engine.connect() as conn:
        # Formateamos las fechas a string compatible con PostgreSQL estándar
        desde_str = fecha_desde.strftime('%Y-%m-%d 00:00:00')
        hasta_str = fecha_hasta.strftime('%Y-%m-%d 23:59:59')
        
        # Query directo sin parámetros bind que confundan a SQLAlchemy
        query_str = f"""
            SELECT * FROM "audit_logs" 
            WHERE timestamp >= '{desde_str}' AND timestamp <= '{hasta_str}' 
            ORDER BY timestamp DESC
        """
        df_ledger = pd.read_sql(text(query_str), conn)
        
        # Capa 1: UEBA Anomalías
        anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
        # Capa 2: Darktrace NTA
        darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats ORDER BY timestamp DESC"), conn)
        # Capa 3: Bloqueos SOAR
        firewall_blocks_df = pd.read_sql(text("SELECT * FROM firewall_network_blocks ORDER BY blocked_at DESC"), conn)
        jwt_blacklist_df = pd.read_sql(text("SELECT * FROM jwt_blacklist ORDER BY revoked_at DESC"), conn)
        # Capa 4: Allowlist Exclusiones
        allowlist_df = pd.read_sql(text("SELECT * FROM security_allowlist ORDER BY created_at DESC"), conn)
except Exception as e:
    st.error(f"❌ Error crítico cargando telemetría: {e}")

total_alertas_activas = len(anomalies_live_df) + len(darktrace_df)

# ==========================================
# 📊 MENÚ LATERAL ACCESIBLE (SIDEBAR NAV)
# ==========================================
with st.sidebar:
    # Encabezado de Marca / Isologo Corporativo CORREGIDO
    st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 32px; height: 32px;">{LOGO_SVG}</div>
            <h2 style="margin: 0; padding: 0; color: #a78bfa;">HYPERION SEC</h2>
        </div>
    """, unsafe_allow_html=True)
    st.caption("🤖 Autonomous Immune System")
    st.markdown("---")
    
    st.markdown("### 🎛️ Navegación Principal")
    # Nota: Dentro de 'with st.sidebar:', usa directamente 'st.radio' en vez de 'st.sidebar.radio' 
    # para evitar duplicaciones visuales o anidamientos extraños.
    menu_opcion = st.radio(
        label="Selecciona un Módulo:",
        options=[
            "📋 Bitácora Legal Histórica",
            "🌐 Centro Unificado de Amenazas",
            "⚡ SOAR Control Center",
            "⚙️ Falsos Positivos & Allowlist"
        ]
    )
    
    st.markdown("---")
    # Estado del Nodo en el Footer del Sidebar
    st.markdown("#### 🩺 Estado del Nodo")
    st.success("🟢 CORE_NODE_ONLINE")
    st.caption(f"**Operador:** `{operador_transferido}`")

# ==========================================
# 👑 ENCABEZADO CENTRAL DE LA PLATAFORMA
# ==========================================
st.title("🛡️ Hyperion Autonomous SOAR")
st.markdown(f"📊 **Consola de Comando** | **Filtro Automático:** Últimos 7 días")
st.caption("CONSOLIDACIÓN FINAL // SEMANA 4: MENÚ DE ACCESIBILIDAD LATERAL Y PLATAFORMA UNIFICADA")

# --- RENDERIZADO DE KPI'S CORPORATIVOS ---
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="📊 Eventos Históricos", value=f"{len(df_ledger)} logs")
with m2:
    st.metric(label="🚨 Incidentes Activos", value=f"{total_alertas_activas} alertas", delta="Acción Requerida", delta_color="inverse")
with m3:
    st.metric(label="🔒 Cortafuegos (Cuarentena)", value=f"{len(firewall_blocks_df)} IPs")
with m4:
    st.metric(label="💀 JWT Revocados", value=f"{len(jwt_blacklist_df)} tokens")

st.markdown("---")

# ==========================================
# 🔄 ENRUTAMIENTO DINÁMICO DE PÁGINAS
# ==========================================

# MÓDULO 1: BITÁCORA LEGAL
if menu_opcion == "📋 Bitácora Legal Histórica":
    st.subheader("📋 Registros del Ledger Inmutable (SOC2 / NIST Compliance)")
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

# MÓDULO 2: CENTRO UNIFICADO DE AMENAZAS (DARKTRACE + UEBA)
elif menu_opcion == "🌐 Centro Unificado de Amenazas":
    st.subheader("🌐 Monitoreo Perimetral e Interno en Tiempo Real")
    
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
        st.info("💡 Sin coordenadas perimetrales activas para graficar en el mapa.")

    st.write("---")
    
    col_dt, col_ueba = st.columns(2)
    with col_dt:
        st.markdown("#### 🌐 Alertas Perimetrales Darktrace (NTA & Threat Intel)")
        if not darktrace_df.empty:
            for idx, row in darktrace_df.iterrows():
                with st.container():
                    st.markdown(f"**📍 Origen:** `{row['source_ip']}` ➔ **Destino:** `{row['dest_ip']}`")
                    st.caption(f"🛡️ Táctica: `{row['mitre_tactic']}` | Severidad: `{row['severity'].upper()}`")
                    st.markdown(f"**Detalle:** {row['threat_type']}")
                    
                    if st.button("✂️ Ejecutar Killswitch Manual", key=f"dt_side_{idx}"):
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
            st.success("🟢 No hay amenazas perimetrales pendientes.")

    with col_ueba:
        st.markdown("#### 🕵️ Alertas de Comportamiento Interno (UEBA)")
        if not anomalies_live_df.empty:
            for idx, row in anomalies_live_df.iterrows():
                with st.container():
                    st.markdown(f"**👤 Usuario Comprometido:** `{row['user_email']}`")
                    st.caption(f"⚠️ Severidad: `{row['severity'].upper()}`")
                    st.warning(f"**Desvío:** {row['description']}")
                    
                    if st.button("🚫 Aislar Usuario Manualmente", key=f"ueba_side_{idx}"):
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
            st.success("🟢 Matriz UEBA limpia. Comportamiento estable.")

# MÓDULO 3: SOAR CONTROL CENTER
elif menu_opcion == "⚡ SOAR Control Center":
    st.subheader("⚡ Estado Inmunológico del Sistema")
    c_fw, c_jwt = st.columns(2)
    
    with c_fw:
        st.markdown("#### 🔒 Aislamiento Perimetral Activo en Firewall")
        if not firewall_blocks_df.empty:
            st.dataframe(firewall_blocks_df, use_container_width=True, hide_index=True)
        else:
            st.success("🟢 Cortafuegos limpio. Cero bloqueos perimetrales.")
            
    with c_jwt:
        st.markdown("#### 💀 Sesiones JWT Revocadas / Lista Negra")
        if not jwt_blacklist_df.empty:
            st.dataframe(jwt_blacklist_df, use_container_width=True, hide_index=True)
        else:
            st.success("🟢 Cero tokens en lista negra.")

# MÓDULO 4: FALSOS POSITIVOS Y ALLOWLIST
elif menu_opcion == "⚙️ Falsos Positivos & Allowlist":
    st.subheader("⚙️ Reglas de Exclusión de Confianza y Eventos Mutados")
    st.caption("Los activos registrados aquí generarán un 'MUTED_EVENT' en lugar de activar contenciones automáticas.")
    
    with st.expander("➕ Añadir Nueva Exclusión"):
        with st.form("new_allowlist_form", clear_on_submit=True):
            f_target = st.text_input("Objetivo (IP o Email)", placeholder="Ej: 192.168.1.50 / backup@hyperion.com").strip()
            f_type = st.selectbox("Tipo de Activo", ["ip", "user"])
            f_reason = st.text_input("Justificación de la Regla", placeholder="Ej: Escáner de vulnerabilidades aprobado")
            
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
                    st.toast(f"✅ Regla de exclusión inyectada con éxito: {f_target}", icon="🛡️")
                    st.rerun()
                except Exception as ex:
                    st.error(f"Error al guardar la regla: {ex}")

    st.markdown("#### 📋 Listado Activo de Exclusiones Autorizadas")
    if not allowlist_df.empty:
        st.dataframe(allowlist_df, use_container_width=True, hide_index=True)
    else:
        st.info("No hay reglas de exclusión configuradas.")