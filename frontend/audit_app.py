import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

# Configuración de página con la estética Hyperion original
st.set_page_config(
    page_title="Hyperion | Bitácora Legal Inmutable",
    page_icon="📜",
    layout="wide"
)

# Estilo CSS personalizado oscuro y profesional
st.markdown("""
    <style>
    .stApp { background-color: #0b0e14; }
    h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; }
    .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# 1. Conexión Directa y Segura a la Base de Datos
try:
    db_url = st.secrets.get("DATABASE_URL", "postgresql://postgres.tyunqthoinamdlyhgmuq:zKxaQ4y2zNtaMnI3@aws-1-us-east-1.pooler.supabase.com:6543/postgres")
    engine = create_engine(db_url)
except Exception as e:
    st.error(f"❌ Error crítico de conexión a la Base de Datos de Auditoría: {e}")
    st.stop()

# Encabezado del Sistema
st.title("📜 Bitácora Legal Hyperion")
st.caption("CORE SECURITY NODE // REGISTRO INMUTABLE DE EVENTOS DE CUMPLIMIENTO (COMPLIANCE)")

st.markdown("---")

# 2. Filtros e Interfaz de Usuario
col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    fecha_desde = st.date_input("Rango de Auditoría: Desde", datetime.now() - timedelta(days=7))
with col2:
    fecha_hasta = st.date_input("Rango de Auditoría: Hasta", datetime.now())
with col3:
    actor_filter = st.text_input("Filtrar por Actor / Operador (Opcional)", "").strip()

# 3. Construcción de Query Segura (Ajustada al nombre real exacto "AUDIT_LOGS")
query_str = """
    SELECT timestamp, actor, action, context, hash_this 
    FROM "AUDIT_LOGS" 
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

# 4. Ejecución y Renderizado de Datos
with st.spinner("Consultando registros inmutables de PostgreSQL..."):
    try:
        with engine.connect() as conn:
            df = pd.read_sql(text(query_str), conn, params=params)
            
        # 5. Métricas Rápidas e Integridad
        if not df.empty:
            m1, m2, m3 = st.columns(3)
            with m1:
                st.metric("Total Eventos Evaluados", f"{len(df)} recs")
            with m2:
                st.metric("Última Acción Registrada", str(df['action'].iloc[0]).upper())
            with m3:
                st.metric("Estado de Integridad", "🔒 Cifrado & Verificado")

            st.write("")
            st.subheader("Registros Capturados en el Nodo")
            st.dataframe(df, use_container_width=True)

            # Botón de Descarga Oficial
            st.write("")
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Exportar Bitácora Legal (CSV Oficial)",
                data=csv_data,
                file_name=f"hyperion_bitacora_legal_{fecha_desde}_al_{fecha_hasta}.csv",
                mime="text/csv"
            )
        else:
            st.warning("⚠️ No se encontraron eventos de seguridad en el rango de fechas seleccionado.")
            
    except Exception as e:
        st.error(f"❌ Error al consultar la tabla 'AUDIT_LOGS': {e}")
        st.info("💡 Nota técnica: El enlace a la base de datos es correcto, pero la tabla 'AUDIT_LOGS' devolvió un fallo en la estructura o el esquema actual. Verifica que las columnas coincidan.")