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

# Estilo CSS personalizado oscuro, limpio y profesional (Tarjetas unificadas añadidas)
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; }
    h3 { color: #cbd5e1 !important; }
    h4 { color: #f1f5f9 !important; margin-top: 15px; }
    .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
    [data-testid="stSidebar"] { background-color: #0d1117; border-right: 1px solid #1f2937; }
    footer {visibility: hidden;}
    
    /* Contenedor estilo caja táctica para alertas simétricas (Inspirado en image_1056c1.png) */
    .threat-card {
        background-color: #0d1117;
        border: 1px solid #21262d;
        border-top: 3px solid #ef4444;
        border-radius: 6px;
        padding: 15px;
        margin-bottom: 10px;
        height: 190px;
    }
    .threat-card-medium {
        border-top: 3px solid #f59e0b;
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

# --- CONSULTAS EN CALIENTE PARA ALERTAS, LEDGER Y KPIs ---
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
    else:
        st.warning("No se registran eventos de seguridad históricos en el intervalo seleccionado.")

# MÓDULO 2: CENTRO UNIFICADO DE AMENAZAS (MAPA GIGANTE + RECUADROS SIMÉTRICOS)
elif menu_opcion == "🌐 Centro Unificado de Amenazas":
    st.subheader("🌐 Visualizador de Inmunidad Perimetral y de Red")
    
    # 1. Mapa unificado a pantalla completa (Dominancia visual superior como en image_1056c1.png)
    if not darktrace_df.empty:
        map_data = darktrace_df[['latitude', 'longitude']].dropna()
        map_data.columns = ['lat', 'lon']
        st.map(map_data, zoom=1, use_container_width=True)
    else:
        st.info("💡 Sin coordenadas perimetrales activas para graficar en el mapa.")
        
    st.markdown("### 🚨 Tarjeta de Incidentes de Red Detectados (DPI Live Feed)")
    
    # 2. Renderizado en grilla de recuadros horizontales independientes abajo
    if not darktrace_df.empty:
        # Generamos dinámicamente filas de hasta 4 columnas/tarjetas para emular el pie de la imagen
        cols_tarjetas = st.columns(4)
        
        for idx, row in darktrace_df.iterrows():
            # Asignamos la tarjeta a una de las 4 columnas de forma cíclica
            col_actual = cols_tarjetas[idx % 4]
            
            with col_actual:
                # Determinar clase CSS por gravedad del incidente
                border_style = "threat-card-medium" if row['severity'].lower() in ['medium', 'high'] else ""
                
                # Render HTML estructurado del recuadro
                st.markdown(f"""
                    <div class="threat-card {border_style}">
                        <span style="float: right; font-size: 0.75rem; font-weight: bold; padding: 2px 6px; border-radius: 4px; background-color: #1f2937; color: #f3f4f6;">
                            {row['severity'].upper()}
                        </span>
                        <strong style="color: #f3f4f6; font-size: 0.95rem;">📍 Origen: {row['source_ip']}</strong><br>
                        <span style="color: #9ca3af; font-size: 0.85rem;">➔ Destino: {row['dest_ip']}</span>
                        <div style="margin-top: 8px; font-size: 0.8rem; color: #cbd5e1; line-height: 1.2; height: 40px; overflow: hidden;">
                            <strong>Detalle:</strong> {row['threat_type']}
                        </div>
                        <div style="margin-top: 4px; font-size: 0.75rem; color: #a78bfa;">
                            🏷️ Táctica: {row['mitre_tactic'].split(' (')[0]}
                        </div>
                    </div>
                """, unsafe_allow_html=True)
                
                # Botón de acción embebido abajo de cada tarjeta
                if st.button("🚫 Terminar Flujo", key=f"dt_box_{idx}", use_container_width=True):
                    try:
                        with engine.connect() as conn:
                            with conn.begin(): 
                                conn.execute(text('INSERT INTO "audit_logs" (actor, action) VALUES (\'DARKTRACE_SOAR\', :action)'),
                                    {"action": f"MANUAL_KILLSWITCH: Flujo de la IP {row['source_ip']} terminado por el operador."})
                                conn.execute(text("DELETE FROM darktrace_network_threats WHERE id = :id"), {"id": row['id']})
                        st.toast(f"💥 Killswitch inyectado para {row['source_ip']}", icon="🚫")
                        st.rerun()
                    except Exception as tx_err: 
                        st.error(f"Error: {tx_err}")
    else:
        st.success("🟢 No hay amenazas perimetrales pendientes en el buffer.")

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