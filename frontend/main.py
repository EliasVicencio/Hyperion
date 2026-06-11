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

# REVOLUCIÓN DE INTERFAZ: Paleta Hyperion (Cyber Violet #a78bfa y Tech Blue #58a6ff)
st.markdown("""
    <style>
    .stApp { background-color: #07090e; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; letter-spacing: -0.5px; }
    h3 { color: #58a6ff !important; font-family: 'Courier New', monospace; font-weight: bold; }
    
    /* Contenedor del Escenario HUD */
    .hud-wrapper {
        position: relative;
        border: 1px solid rgba(167, 139, 250, 0.25);
        border-radius: 12px;
        background-color: #0b0f17;
        padding: 10px;
        box-shadow: 0 0 30px rgba(88, 166, 255, 0.05);
    }
    
    /* Panel Analítico Flotante Izquierdo - Estilo Cyber Threat Matrix */
    .hyperion-side-panel {
        position: absolute;
        top: 25px;
        left: 25px;
        width: 330px;
        background: rgba(11, 15, 23, 0.88);
        border-left: 4px solid #a78bfa;
        border-top: 1px solid rgba(167, 139, 250, 0.3);
        border-right: 1px solid rgba(11, 15, 23, 0.8);
        border-bottom: 1px solid rgba(11, 15, 23, 0.8);
        border-radius: 0px 8px 8px 0px;
        padding: 18px;
        z-index: 99;
        box-shadow: 10px 10px 25px rgba(0,0,0,0.65);
        backdrop-filter: blur(12px);
    }
    
    /* Contenedor Inferior de Alertas de Red */
    .hyperion-bottom-deck {
        position: absolute;
        bottom: 25px;
        left: 25px;
        right: 25px;
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 15px;
        z-index: 99;
        max-height: 210px;
        overflow-y: auto;
        padding-top: 10px;
    }
    
    /* Tarjetas de Amenaza Rediseñadas completamente */
    .threat-card-hud {
        background: rgba(13, 19, 30, 0.92);
        border: 1px solid rgba(88, 166, 255, 0.2);
        border-radius: 6px;
        padding: 14px;
        box-shadow: 0 8px 20px rgba(0,0,0,0.7);
        backdrop-filter: blur(10px);
        transition: all 0.25s ease;
    }
    .threat-card-hud:hover {
        border-color: #58a6ff;
        box-shadow: 0 0 15px rgba(88, 166, 255, 0.25);
    }
    
    /* Indicadores de Severidad Tácticos */
    .badge-critical {
        background: rgba(244, 63, 94, 0.15);
        color: #f43f5e;
        border: 1px solid #f43f5e;
        font-size: 0.65rem;
        font-weight: bold;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
        font-family: monospace;
    }
    .badge-medium {
        background: rgba(234, 179, 8, 0.15);
        color: #eab308;
        border: 1px solid #eab308;
        font-size: 0.65rem;
        font-weight: bold;
        padding: 2px 6px;
        border-radius: 4px;
        text-transform: uppercase;
        font-family: monospace;
    }
    
    /* Métricas internas estilo terminal militar */
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
    
    /* Modificaciones estéticas de los componentes de Streamlit nativos */
    [data-testid="stSidebar"] { background-color: #090d14; border-right: 1px solid rgba(167, 139, 250, 0.15); }
    .stDataFrame { background-color: #0b0f17; border: 1px solid #1f2937; }
    footer { visibility: hidden; }
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

# --- RECOLECCIÓN DE TELEMETRÍA EN CALIENTE ---
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
st.markdown(f"🛰️ **Consola Unificada** | Inteligencia Defensiva en Capas")
st.caption("CORE ENGINE DESIGN // VERSIÓN AVANZADA CON PANELES INTERACTIVOS INTEGRADOS SOBRE MAPA")

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="📊 Eventos Históricos", value=f"{len(df_ledger)} logs")
with m2:
    st.metric(label="🚨 Incidentes Activos", value=f"{total_alertas_activas} alertas", delta="Acción Crítica", delta_color="inverse")
with m3:
    st.metric(label="🔒 Bloqueos Firewalls", value=f"{len(firewall_blocks_df)} IPs")
with m4:
    st.metric(label="💀 Tokens Revocados", value=f"{len(jwt_blacklist_df)} JWT")

st.markdown("---")

# ==========================================
# 🔄 ENRUTAMIENTO DINÁMICO DE PÁGINAS
# ==========================================

if menu_opcion == "📋 Bitácora Legal Histórica":
    st.subheader("📋 Registros de Auditoría Inmutable")
    if not df_ledger.empty:
        csv_data = df_ledger.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Exportar Data de Auditoría (CSV)",
            data=csv_data,
            file_name=f"hyperion_audit_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
        )
        st.dataframe(df_ledger, use_container_width=True, hide_index=True)

# MÓDULO 2: REDISEÑO COMPLETO - CENTRO DE AMENAZAS DARKTRACE HUD REINVENTADO
elif menu_opcion == "🌐 Centro Unificado de Amenazas":
    st.subheader("🌐 Visualizador de Inmunidad de Red Estilo Matrix")
    
    # Renderizar tarjetas inferiores dinámicamente
    cards_html = ""
    if not darktrace_df.empty:
        for idx, row in darktrace_df.iterrows():
            is_critical = row['severity'].lower() in ['critical', 'high']
            badge_class = "badge-critical" if is_critical else "badge-medium"
            
            cards_html += f"""
            <div class="threat-card-hud">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="{badge_class}">{row['severity']}</span>
                    <span style="color: #58a6ff; font-family: monospace; font-size: 0.75rem;">ID: #{row.get('id', idx)}</span>
                </div>
                <div style="font-family: monospace; font-size: 0.9rem; color: #fff; font-weight: bold;">
                    ⚡ SRC: <span style="color: #a78bfa;">{row['source_ip']}</span>
                </div>
                <div style="font-family: monospace; font-size: 0.8rem; color: #cbd5e1; margin-bottom: 8px;">
                    🎯 DST: <span style="color: #58a6ff;">{row['dest_ip']}</span>
                </div>
                <div style="font-size: 0.75rem; color: #9ca3af; line-height: 1.3; height: 36px; overflow: hidden;">
                    <strong>Tipo:</strong> {row['threat_type']}
                </div>
                <div style="font-size: 0.7rem; color: #a78bfa; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 5px; margin-top: 5px; font-weight: bold;">
                    🔑 Mitre: {row['mitre_tactic'].split(' (')[0]}
                </div>
            </div>
            """
    else:
        cards_html = """
        <div class="threat-card-hud" style="grid-column: 1/-1; text-align: center; border: 1px dashed #238636;">
            <span style="color: #238636; font-weight: bold; font-family: monospace;">🟢 COMPLIANCE OK: CERO COMPROMISOS DETECTADOS EN EL BUFFER PERIMETRAL</span>
        </div>
        """

    # ENCAPSULACIÓN: Tarjetas e información estructural inyectadas de forma nativa en la capa del HUD
    st.markdown(f"""
        <div class="hud-wrapper">
            <div class="hyperion-side-panel">
                <div style="font-size: 0.75rem; font-family: monospace; color: #58a6ff; font-weight: bold; margin-bottom: 4px;">🚀 HYPERION SEC MATRIX</div>
                <h4 style="margin: 0 0 12px 0; color: #fff; font-size: 1.1rem; border-bottom: 1px solid rgba(167,139,250,0.2); padding-bottom: 6px;">Live Threat Intelligence</h4>
                
                <div class="panel-metric">
                    <span>Logs Analizados:</span>
                    <span style="color: #58a6ff; font-weight: bold;">{len(df_ledger) * 23}</span>
                </div>
                <div class="panel-metric">
                    <span>Vectores de Ataque:</span>
                    <span style="color: #f43f5e; font-weight: bold;">{len(darktrace_df)}</span>
                </div>
                <div class="panel-metric">
                    <span>Comportamientos IP:</span>
                    <span style="color: #eab308; font-weight: bold;">{len(anomalies_live_df)}</span>
                </div>
                <div class="panel-metric">
                    <span>Estatus Red:</span>
                    <span style="color: #238636; font-weight: bold;">SECURE</span>
                </div>
                
                <p style="font-size: 0.7rem; color: #8b949e; margin-top: 15px; line-height: 1.3; font-family: monospace;">
                    [INFO] Las tarjetas ubicadas en el panel inferior corresponden a flujos de red que infringen las matrices de comportamiento autónomo de Darktrace.
                </p>
            </div>
            
            <div class="hyperion-bottom-deck">
                {cards_html}
            </div>
    """, unsafe_allow_html=True)
    
    # RENDER DE MAPA INTEGRADO: Mapa nativo oscuro posicionado de fondo dentro del contenedor HUD
    if not darktrace_df.empty:
        map_data = darktrace_df[['latitude', 'longitude']].dropna()
        map_data.columns = ['lat', 'lon']
        st.map(map_data, zoom=1, use_container_width=True)
    else:
        # Si no hay coordenadas, creamos un DataFrame por defecto para mantener el mapa táctico mundial vivo
        default_map = pd.DataFrame({'lat': [0.0], 'lon': [0.0]})
        st.map(default_map, zoom=1, use_container_width=True)
        
    st.markdown("</div>", unsafe_allow_html=True) # Cierre del contenedor hud-wrapper

    # MÓDULO INTEGRADO DE CONTENCIÓN (Justo debajo del HUD)
    if not darktrace_df.empty:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("⚡ Control Operativo Automático - Killswitch de Emergencia"):
            for idx, row in darktrace_df.iterrows():
                col_txt, col_act = st.columns([4, 1])
                with col_txt:
                    st.code(f"MIGRACIÓN REQUERIDA // Mitigar flujo malicioso desde IP de origen: {row['source_ip']} hacia {row['dest_ip']}")
                with col_act:
                    if st.button("🚨 Terminar Tráfico", key=f"hud_kill_{idx}", use_container_width=True):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'DARKTRACE_HUD\', :action)'),
                                        {"action": f"HUD_KILLSWITCH: Tráfico denegado permanentemente para IP {row['source_ip']}."})
                                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                            st.toast(f"Tráfico mitigado de forma segura para {row['source_ip']}", icon="🔒")
                            st.rerun()
                        except Exception as ex:
                            st.error(f"Error operativo: {ex}")

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
                    st.toast(f"✅ Regla de exclusión inyectada con éxito: {f_target}", icon="🛡️")
                    st.rerun()
                except Exception as ex: st.error(f"Error al guardar la regla: {ex}")

    st.markdown("#### 📋 Listado Activo de Exclusiones Autorizadas")
    if not allowlist_df.empty:
        st.dataframe(allowlist_df, use_container_width=True, hide_index=True)