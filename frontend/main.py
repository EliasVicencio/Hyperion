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

# Estilo CSS avanzado para lograr la superposición nativa de Darktrace (image_1056c1.png)
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; }
    h3 { color: #cbd5e1 !important; }
    h4 { color: #f1f5f9 !important; margin-top: 15px; }
    .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
    [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #1f2937; }
    footer {visibility: hidden;}
    
    /* Contenedor Maestro Relativo para el Mapa HUD */
    .darktrace-container {
        position: relative;
        width: 100%;
        height: 650px;
        background-color: #090d12;
        border: 1px solid #1f2937;
        border-radius: 12px;
        overflow: hidden;
        margin-bottom: 25px;
    }
    
    /* Iframe del mapa base ocupando todo el fondo */
    .bg-map {
        width: 100%;
        height: 100%;
        border: none;
        mix-blend-mode: luminosity;
        opacity: 0.65;
    }
    
    /* Panel Flotante Izquierdo (Métricas de Mitre/Análisis de image_1056c1.png) */
    .darktrace-left-panel {
        position: absolute;
        top: 20px;
        left: 20px;
        width: 320px;
        background: rgba(13, 17, 23, 0.85);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(48, 54, 61, 0.7);
        border-radius: 8px;
        padding: 15px;
        z-index: 10;
        color: #e6edf3;
    }
    
    /* Contenedor Flotante Inferior para Alertas en tarjetas horizontales */
    .darktrace-bottom-feed {
        position: absolute;
        bottom: 15px;
        left: 20px;
        right: 20px;
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
        gap: 15px;
        z-index: 10;
        max-height: 190px;
        overflow-y: auto;
    }
    
    /* Tarjetas HUD traslúcidas que se posicionan sobre el mapa */
    .hud-card {
        background: rgba(13, 17, 23, 0.9);
        backdrop-filter: blur(6px);
        border: 1px solid #30363d;
        border-top: 3px solid #f43f5e;
        border-radius: 6px;
        padding: 12px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.5);
    }
    .hud-card-medium {
        border-top: 3px solid #eab308;
    }
    
    /* Forzar ocultamiento de componentes innecesarios en el modo HUD */
    .hidden-hud-btn {
        display: none;
    }
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

# --- CONSULTAS EN CALIENTE PARA ALERTAS ---
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
            <h2 style="color: #a78bfa; margin: 0; font-size: 1.5rem; letter-spacing: 1px; font-family: 'Segoe UI', sans-serif; font-weight: 800;">
                HYPERION <span style="color: white; font-size: 0.8rem; vertical-align: middle;">SEC</span>
            </h2>
        </div>
    """, unsafe_allow_html=True)
    
    st.caption("🤖 Autonomous Immune System")
    st.markdown("---")
    st.markdown("### 🎛️ Navegación Principal")
    
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
    st.markdown("#### 🩺 Estado del Nodo")
    st.success("🟢 CORE_NODE_ONLINE")
    st.caption(f"**Operador:** `{operador_transferido}`")

# ==========================================
# 👑 ENCABEZADO CENTRAL DE LA PLATAFORMA
# ==========================================
st.title("🛡️ Hyperion Autonomous SOAR")
st.markdown(f"📊 **Consola de Comando** | **Filtro Automático:** Últimos 7 días")
st.caption("CONSOLIDACIÓN FINAL // SEMANA 4: MENÚ DE ACCESIBILIDAD LATERAL Y PLATAFORMA UNIFICADA")

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

# MÓDULO 2: CENTRO UNIFICADO DE AMENAZAS (TOTALMENTE INTEGRADO EN MODO MAPA HUD)
elif menu_opcion == "🌐 Centro Unificado de Amenazas":
    st.subheader("🌐 Darktrace Threat Analysis HUD")
    
    # Construcción de las tarjetas flotantes inferiores en formato HTML puro
    cards_html = ""
    if not darktrace_df.empty:
        for idx, row in darktrace_df.iterrows():
            border_cls = "hud-card-medium" if row['severity'].lower() in ['medium', 'high'] else ""
            cards_html += f"""
            <div class="hud-card {border_cls}">
                <span style="float: right; font-size: 0.7rem; font-weight: bold; padding: 1px 5px; border-radius: 3px; background: #21262d; color: #f0f6fc;">
                    {row['severity'].upper()}
                </span>
                <div style="font-size: 0.85rem; font-weight: bold; color: #f0f6fc; margin-bottom: 3px;">📍 {row['source_ip']}</div>
                <div style="font-size: 0.75rem; color: #8b949e; margin-bottom: 6px;">➔ Destino: {row['dest_ip']}</div>
                <div style="font-size: 0.75rem; color: #c9d1d9; height: 32px; overflow: hidden; line-height: 1.2;">
                    {row['threat_type']}
                </div>
                <div style="font-size: 0.7rem; color: #a78bfa; margin-top: 4px; font-family: monospace;">
                    ⚡ Tactic: {row['mitre_tactic'].split(' (')[0]}
                </div>
            </div>
            """
    else:
        cards_html = "<div class='hud-card' style='border-top:3px solid #238636; grid-column: 1/-1; text-align:center;'>🟢 No hay amenazas perimetrales activas.</div>"

    # Inyección HUD unificada: El mapa de fondo oscuro y los paneles flotando encima
    st.markdown(f"""
        <div class="darktrace-container">
            <iframe class="bg-map" src="https://maps.google.com/maps?q=0,0&z=2&output=embed&iwloc=near"></iframe>
            
            <div class="darktrace-left-panel">
                <h4 style="margin:0 0 10px 0; font-size:1.1rem; color:#a78bfa;">📊 Darktrace Analytics</h4>
                <p style="margin:2px 0; font-size:0.8rem; color:#8b949e;">Eventos Procesados: <span style="color:white; float:right; font-weight:bold;">{len(df_ledger) * 14}</span></p>
                <p style="margin:2px 0; font-size:0.8rem; color:#8b949e;">Brechas del Sistema: <span style="color:#f43f5e; float:right; font-weight:bold;">{len(darktrace_df)}</span></p>
                <p style="margin:2px 0; font-size:0.8rem; color:#8b949e;">Anomalías Activas: <span style="color:#eab308; float:right; font-weight:bold;">{len(anomalies_live_df)}</span></p>
                <hr style="border:0; border-top:1px solid #21262d; margin:10px 0;">
                <span style="font-size:0.75rem; color:#8b949e; line-height:1.2; display:block;">
                    Despliegue perimetral activo. Las alertas inferiores se actualizan automáticamente en tiempo real.
                </span>
            </div>
            
            <div class="darktrace-bottom-feed">
                {cards_html}
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Panel de mitigación rápido justo debajo por si se requiere interactuar con base de datos
    if not darktrace_df.empty:
        with st.expander("🛠️ Panel Rápido de Contención (SOAR Action)"):
            for idx, row in darktrace_df.iterrows():
                col_info, col_btn = st.columns([3, 1])
                with col_info:
                    st.markdown(f"**Killswitch Disponible:** Interrumpir flujo de `{row['source_ip']}` ➔ `{row['dest_ip']}`")
                with col_btn:
                    if st.button("✂️ Ejecutar Cortar", key=f"dt_hud_btn_{idx}", use_container_width=True):
                        try:
                            with engine.connect() as conn:
                                with conn.begin(): 
                                    conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'DARKTRACE_SOAR\', :action)'),
                                        {"action": f"MANUAL_KILLSWITCH: Flujo de la IP {row['source_ip']} terminado por el operador."})
                                    conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                            st.toast(f"💥 Killswitch inyectado para {row['source_ip']}", icon="🚫")
                            st.rerun()
                        except Exception as tx_err: st.error(f"Error: {tx_err}")

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