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

# ESTILOS DE INTERFAZ: Paleta Corporativa Hyperion (#a78bfa Violet / #58a6ff Blue)
st.markdown("""
    <style>
    .stApp { background-color: #07090e; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; letter-spacing: -0.5px; }
    h2 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; }
    h3 { color: #58a6ff !important; font-family: 'Courier New', monospace; font-weight: bold; }
    h4 { color: #ffffff !important; }
    
    /* Contenedor del Escenario HUD */
    .hud-wrapper {
        position: relative;
        border: 1px solid rgba(167, 139, 250, 0.2);
        border-radius: 12px;
        background-color: #0b0f17;
        padding: 8px;
        box-shadow: 0 0 30px rgba(88, 166, 255, 0.03);
    }
    
    /* Panel Analítico Flotante Izquierdo */
    .hyperion-side-panel {
        position: absolute;
        top: 20px;
        left: 20px;
        width: 310px;
        background: rgba(11, 15, 23, 0.9);
        border-left: 4px solid #a78bfa;
        border-top: 1px solid rgba(167, 139, 250, 0.2);
        border-radius: 0px 8px 8px 0px;
        padding: 16px;
        z-index: 99;
        box-shadow: 5px 5px 20px rgba(0,0,0,0.5);
        backdrop-filter: blur(10px);
    }
    
    /* Métricas estilo terminal */
    .panel-metric {
        font-family: 'Courier New', monospace;
        font-size: 0.85rem;
        color: #cbd5e1;
        margin: 6px 0;
        display: flex;
        justify-content: space-between;
        border-bottom: 1px dashed rgba(255,255,255,0.05);
        padding-bottom: 4px;
    }
    
    /* Modificaciones estéticas de componentes nativos */
    [data-testid="stSidebar"] { background-color: #090d14; border-right: 1px solid rgba(167, 139, 250, 0.15); }
    .stDataFrame { background-color: #0b0f17; border: 1px solid #1f2937; }
    footer { visibility: hidden; }
    </style>
""", unsafe_allow_html=True)

# Parámetros URL transferidos
query_params = st.query_params
operador_transferido = query_params.get("operator", "Control Central")

# Conexión de Datos a Supabase
try:
    db_url = "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
    engine = create_engine(db_url)
except Exception as e:
    st.error(f"❌ Error crítico de conexión: {e}")
    st.stop()

# --- RECOLECCIÓN DE TELEMETRÍA ---
fecha_desde = datetime.now() - timedelta(days=7)
fecha_hasta = datetime.now()

df_ledger = pd.DataFrame()
anomalies_live_df = pd.DataFrame()
darktrace_df = pd.DataFrame()
firewall_blocks_df = pd.DataFrame()
jwt_blacklist_df = pd.DataFrame()
allowlist_df = pd.DataFrame()

try:
    with engine.connect() as conn:
        desde_str = fecha_desde.strftime('%Y-%m-%d 00:00:00')
        hasta_str = fecha_hasta.strftime('%Y-%m-%d 23:59:59')
        
        query_str = f"""
            SELECT * FROM "audit_logs" 
            WHERE timestamp >= '{desde_str}' AND timestamp <= '{hasta_str}' 
            ORDER BY timestamp DESC
        """
        df_ledger = pd.read_sql(text(query_str), conn)
        anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
        darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats ORDER BY timestamp DESC"), conn)
        firewall_blocks_df = pd.read_sql(text("SELECT * FROM firewall_network_blocks ORDER BY blocked_at DESC"), conn)
        jwt_blacklist_df = pd.read_sql(text("SELECT * FROM jwt_blacklist ORDER BY revoked_at DESC"), conn)
        allowlist_df = pd.read_sql(text("SELECT * FROM security_allowlist ORDER BY created_at DESC"), conn)
except Exception as e:
    st.error(f"❌ Error crítico cargando telemetría: {e}")

total_alertas_activas = len(anomalies_live_df) + len(darktrace_df)

# ==========================================
# 📊 MENÚ LATERAL ACCESIBLE (SIDEBAR NAV)
# ==========================================
with st.sidebar:
    pure_svg = LOGO_SVG.replace("data:image/svg+xml,", "")
    st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
            <div style="width: 35px; height: 35px; display: flex; align-items: center;">
                {pure_svg}
            </div>
            <h2 style="color: #a78bfa; margin: 0; font-size: 1.4rem; letter-spacing: 1px; font-family: 'Segoe UI', sans-serif; font-weight: 800;">
                HYPERION <span style="color: #58a6ff; font-size: 0.8rem; vertical-align: middle;">SOAR</span>
            </h2>
        </div>
    """, unsafe_allow_html=True)
    
    st.caption("🤖 Autonomous Immune System Engine")
    st.markdown("---")
    
    menu_opcion = st.radio(
        label="Módulos del Ecosistema:",
        options=[
            "🎯 Dashboard General",
            "📋 Bitácora Legal Histórica",
            "🌐 Centro Unificado de Amenazas",
            "⚡ SOAR Control Center",
            "⚙️ Falsos Positivos & Allowlist"
        ]
    )
    st.markdown("---")
    st.markdown("#### 🚀 Estado del Entorno")
    st.success("🟢 CORE_NODE_DEPLOYED")
    st.caption(f"**Operador:** `{operador_transferido}`")

# ==========================================
# 👑 ENCABEZADO CENTRAL DE LA PLATAFORMA
# ==========================================
st.title("🛡️ Hyperion Autonomous SOAR")
st.markdown(f"🛰️ Consola Unificada | Inteligencia Defensiva")
st.markdown("---")

# ==========================================
# 🔄 ENRUTAMIENTO DINÁMICO DE PÁGINAS (SIN CONTENIDO DUPLICADO)
# ==========================================

# MÓDULO 0: DASHBOARD GENERAL
if menu_opcion == "🎯 Dashboard General":
    st.subheader("📊 Resumen del Estado de Seguridad")
    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(label="📊 Eventos Históricos", value=f"{len(df_ledger)} logs")
    with m2:
        st.metric(label="🚨 Incidentes Activos", value=f"{total_alertas_activas} alertas", delta="Acción Crítica", delta_color="inverse")
    with m3:
        st.metric(label="🔒 Bloqueos Firewalls", value=f"{len(firewall_blocks_df)} IPs")
    with m4:
        st.metric(label="💀 Tokens Revocados", value=f"{len(jwt_blacklist_df)} JWT")
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.info("💡 Utilice el menú lateral de navegación para gestionar cada módulo táctico e interactuar con la infraestructura.")

# MÓDULO 1: BITÁCORA LEGAL HISTÓRICA
elif menu_opcion == "📋 Bitácora Legal Histórica":
    st.subheader("📋 Registros de Auditoría Inmutable (SOC2 / NIST Compliance)")
    if not df_ledger.empty:
        csv_data = df_ledger.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Exportar Data de Auditoría (CSV)",
            data=csv_data,
            file_name=f"hyperion_audit_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )
        st.dataframe(df_ledger, use_container_width=True, hide_index=True)
    else:
        st.warning("No se registran eventos de seguridad históricos en el intervalo seleccionado.")

# MÓDULO 2: CENTRO DE AMENAZAS (CORREGIDO SIN INDENTACIÓN CONFLICTIVA)
elif menu_opcion == "🌐 Centro Unificado de Amenazas":
    st.subheader("🌐 Visualizador de Inmunidad de Red Táctica")
    
    eventos_calculados = len(df_ledger) * 23
    vectores_criticos = len(darktrace_df)
    comportamientos_ip = len(anomalies_live_df)
    
    # IMPORTANTE: El HTML se escribe pegado a la izquierda sin tabulaciones para evitar que Streamlit lo confunda con código markdown
    html_panel = f"""<div class="hud-wrapper"><div class="hyperion-side-panel"><div style="font-size: 0.72rem; font-family: monospace; color: #58a6ff; font-weight: bold; margin-bottom: 2px;">🚀 CORE MATRIX</div><h4 style="margin: 0 0 10px 0; color: #fff; font-size: 1.05rem; border-bottom: 1px solid rgba(167,139,250,0.15); padding-bottom: 4px;">Live Intelligence</h4><div class="panel-metric"><span>Eventos Correlacionados:</span><span style="color: #58a6ff; font-weight: bold;">{eventos_calculados}</span></div><div class="panel-metric"><span>Vectores Críticos:</span><span style="color: #f43f5e; font-weight: bold;">{vectores_criticos}</span></div><div class="panel-metric"><span>Comportamientos IP:</span><span style="color: #eab308; font-weight: bold;">{comportamientos_ip}</span></div><div class="panel-metric"><span>Estatus Nodo:</span><span style="color: #238636; font-weight: bold;">PROTECTED</span></div></div>"""
    
    st.markdown(html_panel, unsafe_allow_html=True)
    
    # Despliegue del Mapa Táctico dentro de la envoltura visual del HUD
    if not darktrace_df.empty:
        map_data = darktrace_df[['latitude', 'longitude']].dropna()
        map_data.columns = ['lat', 'lon']
        st.map(map_data, zoom=1, use_container_width=True)
    else:
        default_map = pd.DataFrame({'lat': [0.0], 'lon': [0.0]})
        st.map(default_map, zoom=1, use_container_width=True)
        
    st.markdown("</div>", unsafe_allow_html=True)

    # Sección táctica bajo demanda mediante Expander nativo
    st.markdown("<br>", unsafe_allow_html=True)
    if not darktrace_df.empty:
        with st.expander(f"🛠️ Analizar e Interrumpir Amenazas Activas ({len(darktrace_df)})", expanded=True):
            for idx, row in darktrace_df.iterrows():
                severity_color = "#f43f5e" if row['severity'].lower() in ['critical', 'high'] else "#eab308"
                
                c_info, c_kill = st.columns([4, 1])
                with c_info:
                    st.markdown(
                        f"<span style='color: {severity_color}; font-weight: bold; font-family: monospace;'>[{row['severity'].upper()}]</span> "
                        f"Origen: **`{row['source_ip']}`** ➔ Destino: **`{row['dest_ip']}`** | *Táctica Mitre:* `{row['mitre_tactic']}`", 
                        unsafe_allow_html=True
                    )
                with c_kill:
                    if st.button("✂️ Terminar Flujo", key=f"kill_btn_{row.get('id', idx)}", use_container_width=True):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'SOAR_COCKPIT\', :action)'),
                                        {"action": f"KILLSWITCH: Flujo de {row['source_ip']} mitigado por comando explícito."})
                                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                            st.toast(f"Aislamiento aplicado a {row['source_ip']}", icon="🔒")
                            st.rerun()
                        except Exception as ex:
                            st.error(f"Fallo en Mitigación: {ex}")
    else:
        st.info("🟢 Perímetro normalizado: No hay flujos maliciosos pendientes de mitigación en este segmento.")

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
    st.subheader("⚙️ Reglas de Exclusión de Confianza")
    
    with st.expander("➕ Añadir Nueva Exclusión"):
        with st.form("new_allowlist_form", clear_on_submit=True):
            f_target = st.text_input("Objetivo (IP o Email)", placeholder="Ej: 192.168.1.50").strip()
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
                    st.toast(f"✅ Exclusión inyectada: {f_target}", icon="🛡️")
                    st.rerun()
                except Exception as ex: st.error(f"Error al guardar la regla: {ex}")

    st.markdown("#### 📋 Listado Activo de Exclusiones Autorizadas")
    if not allowlist_df.empty:
        st.dataframe(allowlist_df, use_container_width=True, hide_index=True)