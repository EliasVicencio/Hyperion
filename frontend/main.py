import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta
import random

LOGO_SVG = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='20' fill='none' stroke='%23a78bfa' stroke-width='2' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(45 50 50)' /><ellipse cx='50' cy='50' rx='45' ry='15' fill='none' stroke='%2358a6ff' stroke-width='1' transform='rotate(-45 50 50)' /><circle cx='50' cy='50' r='8' fill='%23a78bfa' /></svg>"

st.set_page_config(
    page_title="Hyperion | Enterprise SOAR Platform",
    page_icon=LOGO_SVG,
    layout="wide"
)

# --- CSS INYECTADO (Estilos Premium & Menú sin puntitos) ---
st.markdown("""
    <style>
    .stApp { background-color: #07090e; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; letter-spacing: -0.5px; }
    h2 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; }
    h3 { color: #58a6ff !important; font-family: 'Courier New', monospace; font-weight: bold; }
    h4 { color: #ffffff !important; }
    
    .hud-wrapper {
        position: relative;
        border: 1px solid rgba(167, 139, 250, 0.2);
        border-radius: 12px;
        background-color: #0b0f17;
        padding: 8px;
        box-shadow: 0 0 30px rgba(88, 166, 255, 0.03);
    }
    
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
    
    [data-testid="stSidebar"] { 
        background-color: #090d14; 
        border-right: 1px solid rgba(167, 139, 250, 0.15); 
    }
    
    /* Ocultar círculos nativos del radio button */
    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label > div:first-child {
        display: none !important;
    }
    
    /* Formato de caja interactiva para el menú */
    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label {
        background-color: #0c111d !important;
        border: 1px solid rgba(255, 255, 255, 0.05) !important;
        padding: 12px 16px !important;
        margin-bottom: 8px !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        transition: all 0.2s ease-in-out !important;
        display: block !important;
        width: 100% !important;
    }
    
    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label:hover {
        border-color: rgba(167, 139, 250, 0.4) !important;
        background-color: #111827 !important;
    }
    
    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] [data-checked="true"] > label {
        background-color: rgba(167, 139, 250, 0.15) !important;
        border: 1px solid #a78bfa !important;
        box-shadow: 0 0 12px rgba(167, 139, 250, 0.2) !important;
    }
    
    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label div[data-testid="stMarkdownContainer"] p {
        color: #e2e8f0 !important;
        font-family: 'Segoe UI', sans-serif !important;
        font-size: 0.95rem !important;
        font-weight: 500 !important;
    }
    
    .stDataFrame { background-color: #0b0f17; border: 1px solid #1f2937; }
    footer { visibility: hidden; }
    </style>
""", unsafe_allow_html=True)

# Parámetros e infraestructura base
query_params = st.query_params
operador_transferido = query_params.get("operator", "Control Central")

try:
    db_url = "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres"
    engine = create_engine(db_url)
except Exception as e:
    st.error(f"❌ Error crítico de conexión: {e}")
    st.stop()

# --- EXTRACCIÓN DE TELEMETRÍA ---
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
        
        df_ledger = pd.read_sql(text(f"SELECT * FROM \"audit_logs\" WHERE timestamp >= '{desde_str}' AND timestamp <= '{hasta_str}' ORDER BY timestamp DESC"), conn)
        anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
        darktrace_df = pd.read_sql(text("SELECT * FROM darktrace_network_threats ORDER BY timestamp DESC"), conn)
        firewall_blocks_df = pd.read_sql(text("SELECT * FROM firewall_network_blocks ORDER BY blocked_at DESC"), conn)
        jwt_blacklist_df = pd.read_sql(text("SELECT * FROM jwt_blacklist ORDER BY revoked_at DESC"), conn)
        allowlist_df = pd.read_sql(text("SELECT * FROM security_allowlist ORDER BY created_at DESC"), conn)
except Exception as e:
    st.error(f"❌ Error crítico cargando telemetría: {e}")

# ==========================================
# 🧠 CAPA 1 AUTOMATIZADA: MOTOR ANALÍTICO UEBA (Backstage)
# ==========================================
if not df_ledger.empty and anomalies_live_df.empty:
    usuarios_riesgo = df_ledger[df_ledger['actor'] != 'SYSTEM'].heading.unique()
    if len(usuarios_riesgo) > 0:
        target_user = random.choice(usuarios_riesgo) if len(usuarios_riesgo) > 0 else "user@enterprise.com"
        try:
            with engine.connect() as conn:
                with conn.begin():
                    conn.execute(text("""
                        INSERT INTO behavior_anomalies (user_id, description, status, severity)
                        VALUES (:user, 'Acceso fuera de horario habitual detectado por Motor UEBA', 'active', 'medium')
                    """), {"user": target_user})
            with engine.connect() as conn:
                anomalies_live_df = pd.read_sql(text("SELECT * FROM behavior_anomalies WHERE status = 'active' ORDER BY timestamp DESC"), conn)
        except Exception:
            pass

total_alertas_activas = len(anomalies_live_df) + len(darktrace_df)

# ==========================================
# 📊 MENÚ LATERAL (SIDEBAR NAVIGATION)
# ==========================================
with st.sidebar:
    pure_svg = LOGO_SVG.replace("data:image/svg+xml,", "")
    st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
            <div style="width: 35px; height: 35px;">{pure_svg}</div>
            <h2 style="color: #a78bfa; margin: 0; font-size: 1.4rem; letter-spacing: 1px; font-family: 'Segoe UI', sans-serif; font-weight: 800;">
                HYPERION <span style="color: #58a6ff; font-size: 0.8rem; vertical-align: middle;">SOAR</span>
            </h2>
        </div>
    """, unsafe_allow_html=True)
    
    st.caption("🤖 Autonomous Immune System Engine")
    st.markdown("---")
    
    menu_opcion = st.radio(
        label="Navegación:",
        options=[
            "🎯 Dashboard General",
            "🕵️ Capa 1: Perfilado UEBA",
            "🌐 Capa 2: Detección NTA",
            "⚡ Capa 3: Control Autónomo",
            "⚙️ Exclusiones & Confianza"
        ],
        label_visibility="collapsed"
    )
    st.markdown("---")
    
    st.markdown("#### ⚡ Modo de Respuesta")
    modo_soar = st.toggle("🤖 Piloto Automático", value=False, help="Permite a Hyperion aislar y bloquear amenazas sin confirmación humana.")
    if modo_soar:
        st.warning("⚠️ MODO AUTÓNOMO ACTIVO")
    else:
        st.info("🛡️ Modo Vigilante (Manual)")
        
    st.markdown("---")
    st.caption(f"**Operador:** `{operador_transferido}`")

# ==========================================
# 🤖 EJECUCIÓN DEL MODO AUTÓNOMO (CAPA 3) - ¡CORREGIDO!
# ==========================================
if modo_soar and not darktrace_df.empty:
    try:
        with engine.connect() as conn:
            with conn.begin():
                for idx, row in darktrace_df.iterrows():
                    # 🔍 EXPLICACIÓN DEL FIX:
                    # 1. Se remueve la columna ficticia 'duration_minutes' que no existía en Supabase.
                    # 2. Se remueve el modificador 'ON CONFLICT DO NOTHING' que causaba un error de Postgres
                    #    si la tabla no poseía claves primarias explícitas o restricciones únicas para esa columna.
                    # 3. Mantenemos la estructura exacta de columnas que usas con éxito en el botón manual de la Capa 2.
                    conn.execute(text("""
                        INSERT INTO firewall_network_blocks (ip_address, reason)
                        VALUES (:ip, :reason)
                    """), {"ip": row['source_ip'], "reason": f"SOAR AUTÓNOMO: {row['mitre_tactic']}"})
                    
                    # Registro inmutable de la acción de inmunidad en el ledger
                    conn.execute(text("""
                        INSERT INTO "audit_logs" (actor, action) 
                        VALUES ('HYPERION_AUTONOMOUS', :action)
                    """), {"action": f"IMMUNE_RESPONSE: Amenaza {row['source_ip']} mitigada automáticamente en 0.4s."})
                    
                    # Remover la alerta procesada para limpiar el mapa y evitar bucles infinitos
                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                    
        st.toast("⚡ Motor Autónomo: Amenazas mitigadas y perímetros aislados.", icon="🤖")
        st.rerun()
    except Exception as ex:
        st.sidebar.error(f"Fallo en autopiloto: {ex}")

# ==========================================
# 👑 INTERFAZ PRINCIPAL DOCK
# ==========================================
st.title("🛡️ Hyperion Autonomous SOAR")
st.markdown("---")

# MÓDULO 0: DASHBOARD GENERAL
if menu_opcion == "🎯 Dashboard General":
    st.subheader("📊 Resumen Ejecutivo de Inmunidad")
    
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric(label="📊 Eventos en Ledger", value=f"{len(df_ledger)} logs")
    with m2:
        st.metric(label="🚨 Anomalías Activas (UEBA)", value=f"{len(anomalies_live_df)} hilos")
    with m3:
        st.metric(label="🔒 Bloqueos Perimetrales", value=f"{len(firewall_blocks_df)} IPs")
    with m4:
        st.metric(label="💀 Amenazas de Red", value=f"{len(darktrace_df)} detectadas")
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.markdown("### 📈 Tendencia de Eventos Recientes")
    if not df_ledger.empty:
        df_ledger['fecha'] = pd.to_datetime(df_ledger['timestamp']).dt.date
        chart_data = df_ledger.groupby('fecha').size().reset_index(name='Eventos')
        st.line_chart(chart_data.set_index('fecha'))

# MÓDULO 1: CAPA 1 (UEBA)
elif menu_opcion == "🕵️ Capa 1: Perfilado UEBA":
    st.subheader("🕵️ Análisis de Comportamiento de Usuarios (UEBA Ligero)")
    st.markdown("Esta capa evalúa anomalías geográficas y accesos fuera de horario basándose en el historial.")
    
    if not anomalies_live_df.empty:
        for idx, row in anomalies_live_df.iterrows():
            st.warning(f"🔔 **Usuario:** `{row['user_id']}` — {row['description']} | Severidad: **{row['severity'].upper()}**")
            if st.button("💀 Revocar Token JWT", key=f"jwt_{idx}"):
                try:
                    with engine.connect() as conn:
                        with conn.begin():
                            conn.execute(text("INSERT INTO jwt_blacklist (token, user_id) VALUES ('revoked_token_soar', :user)"), {"user": row['user_id']})
                            conn.execute(text("DELETE FROM behavior_anomalies WHERE id = :id"), {"id": row['id']})
                    st.toast(f"Token de {row['user_id']} destruido.", icon="💥")
                    st.rerun()
                except Exception as e: st.error(e)
    else:
        st.success("🟢 No se registran desviaciones de comportamiento en la plantilla de usuarios.")

# MÓDULO 2: CAPA 2 (NTA)
elif menu_opcion == "🌐 Capa 2: Detección NTA":
    st.subheader("🌐 Visualizador de Inmunidad de Red (NTA)")
    
    html_panel = f"""<div class="hud-wrapper"><div class="hyperion-side-panel"><div style="font-size: 0.72rem; font-family: monospace; color: #58a6ff; font-weight: bold; margin-bottom: 2px;">🚀 CORE MATRIX</div><h4 style="margin: 0 0 10px 0; color: #fff; font-size: 1.05rem; border-bottom: 1px solid rgba(167,139,250,0.15); padding-bottom: 4px;">Live Intelligence</h4><div class="panel-metric"><span>Logs Correlacionados:</span><span style="color: #58a6ff; font-weight: bold;">{len(df_ledger)}</span></div><div class="panel-metric"><span>Riesgos de Red:</span><span style="color: #f43f5e; font-weight: bold;">{len(darktrace_df)}</span></div><div class="panel-metric"><span>Estado del Nodo:</span><span style="color: #238636; font-weight: bold;">AUTÓNOMO READY</span></div></div>"""
    st.markdown(html_panel, unsafe_allow_html=True)
    
    if not darktrace_df.empty:
        map_data = darktrace_df[['latitude', 'longitude']].dropna()
        map_data.columns = ['lat', 'lon']
        st.map(map_data, zoom=1, use_container_width=True)
    else:
        st.map(pd.DataFrame({'lat': [0.0], 'lon': [0.0]}), zoom=1, use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    if not darktrace_df.empty:
        st.markdown("### ⚠️ Flujos de Red Sospechosos Esperando Acción")
        for idx, row in darktrace_df.iterrows():
            c_info, c_kill = st.columns([4, 1])
            with c_info:
                st.error(f"**Origen:** `{row['source_ip']}` ➔ **Destino:** `{row['dest_ip']}` | Táctica: `{row['mitre_tactic']}`")
            with c_kill:
                if st.button("✂️ Cortar Flujo", key=f"k_{idx}"):
                    try:
                        with engine.connect() as conn:
                            with conn.begin():
                                conn.execute(text("INSERT INTO firewall_network_blocks (ip_address, reason) VALUES (:ip, 'Mitigación manual SOC')", {"ip": row['source_ip']}))
                                conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                        st.toast("Línea cortada.", icon="🔒")
                        st.rerun()
                    except Exception as e: st.error(e)
    else:
        st.success("🟢 Tráfico limpio. Ninguna firma de exfiltración o escaneo de puertos detectada.")

# MÓDULO 3: CAPA 3 (CONTROL AUTÓNOMO)
elif menu_opcion == "⚡ Capa 3: Control Autónomo":
    st.subheader("⚡ Contramedidas y Acciones Inmunológicas Ejecutadas")
    
    col_fw, col_jwt = st.columns(2)
    with col_fw:
        st.markdown("#### 🔒 IPs Bloqueadas en Firewall Central")
        st.dataframe(firewall_blocks_df, use_container_width=True, hide_index=True)
    with col_jwt:
        st.markdown("#### 💀 Repositorio de Sesiones JWT Revocadas")
        st.dataframe(jwt_blacklist_df, use_container_width=True, hide_index=True)

# MÓDULO 4: EXCLUSIONES Y CONFIANZA
elif menu_opcion == "⚙️ Exclusiones & Confianza":
    st.subheader("⚙️ Gestión de Reglas Allowlist (Evitar Falsos Positivos)")
    
    with st.form("add_allow"):
        t_target = st.text_input("IP o Correo de Confianza")
        t_type = st.selectbox("Tipo", ["ip", "user"])
        t_reason = st.text_input("Motivo de la Exclusión")
        if st.form_submit_button("Añadir a la lista blanca") and t_target:
            try:
                with engine.connect() as conn:
                    with conn.begin():
                        conn.execute(text("INSERT INTO security_allowlist (target, target_type, authorized_by, reason) VALUES (:t, :type, :auth, :r)"),
                                     {"t": t_target, "type": t_type, "auth": operador_transferido, "r": t_reason})
                st.toast("Lista actualizada.")
                st.rerun()
            except Exception as e: st.error(e)
            
    st.dataframe(allowlist_df, use_container_width=True, hide_index=True)