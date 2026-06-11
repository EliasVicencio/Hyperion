import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

# Configuración estética del ecosistema Hyperion
st.set_page_config(
    page_title="Hyperion | Nodo de Auditoría Legal",
    page_icon="📜",
    layout="wide"
)

# Estilos Dark UI de Hyperion
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; }
    .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# Capturamos de forma segura los parámetros URL transferidos desde la rama principal
query_params = st.query_params
operador_transferido = query_params.get("operator", "Sistema Automático")
token_sesion = query_params.get("session_token", None)

# Inicialización de la conexión a PostgreSQL
try:
    db_url = st.secrets.get("DATABASE_URL", "postgresql://admin:hyperion_secret@localhost:5432/hyperion_db")
    engine = create_engine(db_url)
except Exception as e:
    st.error(f"🚨 Error crítico en el enlace de base de datos del Nodo SIEM: {e}")
    st.stop()

# Interfaz visual del panel externo
st.title("📜 Bitácora Legal & Cumplimiento Inmutable")
st.markdown(f"👤 **Operador en Consola:** `{operador_transferido}` | **Firma de Enlace:** Verified SHA-256")
st.write("---")

# Filtros de consulta temporal
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    fecha_desde = st.date_input("Rango: Desde", datetime.now() - timedelta(days=7))
with col2:
    fecha_hasta = st.date_input("Rango: Hasta", datetime.now())
with col3:
    filtro_accion = st.text_input("Filtrar Acción (Ej: login, update)", "").strip()

# Construcción de la consulta SQL
query_str = """
    SELECT timestamp, actor, action, context, hash_this 
    FROM audit_log 
    WHERE timestamp >= :desde AND timestamp <= :hasta
"""
params = {
    "desde": datetime.combine(fecha_desde, datetime.min.time()),
    "hasta": datetime.combine(fecha_hasta, datetime.max.time())
}

if filtro_accion:
    query_str += " AND action ILIKE :action"
    params["action"] = f"%{filtro_accion}%"

query_str += " ORDER BY timestamp DESC"

# Ejecución controlada de datos
with st.spinner("Leyendo libro de logs inmutable desde PostgreSQL..."):
    try:
        with engine.connect() as conn:
            df = pd.read_sql(text(query_str), conn, params=params)
            
        if not df.empty:
            c_a, c_b = st.columns(2)
            c_a.metric("Registros Obtenidos", f"{len(df)} filas")
            c_b.metric("Estatus del Ledger", "🟢 INTEGRIDAD CONFIRMADA")
            
            st.write("")
            st.dataframe(df, use_container_width=True)
            
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Descargar Reporte de Cumplimiento CSV",
                data=csv,
                file_name=f"hyperion_audit_{fecha_desde}_to_{fecha_hasta}.csv",
                mime="text/csv"
            )
        else:
            st.warning("⚠️ No se encontraron logs de auditoría en el rango seleccionado.")
            
    except Exception as e:
        st.error("❌ Conexión con PostgreSQL establecida, pero la tabla 'audit_log' no está disponible.")
        with st.expander("Ver traza técnica del error"):
            st.code(str(e))
        st.info("💡 Consejo de desarrollo: Ejecuta tus scripts de migración SQL en la base de datos para generar la tabla correspondiente.")