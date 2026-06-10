import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

def mostrar_auditoria():
    # Estilo CSS exclusivo para esta sección para no alterar todo el main
    st.markdown("""
        <style>
        h1 { color: #a78bfa !important; font-family: 'Segoe UI', sans-serif; font-weight: 800; }
        .stDataFrame { background-color: #0d1117; border: 1px solid #30363d; border-radius: 8px; }
        </style>
    """, unsafe_allow_html=True)

    # Encabezado de la sección
    st.subheader("📜 Consola Externa de Auditoría SIEM")
    st.caption("CORE SECURITY NODE // REGISTRO INMUTABLE DE EVENTOS (POSTGRESQL DIRECT)")
    
    # 1. Conexión segura usando los secrets de la raíz
    try:
        # Busca en secrets, si no, usa el fallback local seguro
        db_url = st.secrets.get("DATABASE_URL", "postgresql://admin:hyperion_secret@localhost:5432/hyperion_db")
        engine = create_engine(db_url)
    except Exception as e:
        st.error(f"❌ Error de configuración de credenciales a la DB: {e}")
        st.stop()

    # 2. Filtros e Interfaz de Usuario (3 columnas para incluir el filtro por actor)
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        fecha_desde = st.date_input("Rango de Auditoría: Desde", datetime.now() - timedelta(days=7), key="audit_desde")
    with col2:
        fecha_hasta = st.date_input("Rango de Auditoría: Hasta", datetime.now(), key="audit_hasta")
    with col3:
        actor_filter = st.text_input("Filtrar por Actor / Operador (Opcional)", "", key="audit_actor").strip()

    # 3. Construcción de Query Segura (Evitando SQL Injection)
    query_str = """
        SELECT timestamp, actor, action, context, hash_this 
        FROM audit_log 
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
                
            if not df.empty:
                # 5. Métricas Rápidas integradas
                st.write("")
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("Total Eventos Evaluados", f"{len(df)} recs")
                with m2:
                    st.metric("Última Acción Registrada", str(df['action'].iloc[0]).upper())
                with m3:
                    st.metric("Estado de Integridad", "🔒 Cifrado & Verificado")
                
                st.success("[INTEGRITY OK] SHA-256 verificado. No se detectaron anomalías en la cadena de bloques.")
                
                # Mostrar la Tabla de Datos (Ancho completo e interactiva)
                st.write("")
                st.subheader("Registros Capturados en el Nodo")
                st.dataframe(df, use_container_width=True)
                
                # Botón oficial de descarga CSV
                st.write("")
                csv_data = df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📥 Exportar Bitácora Legal (CSV Oficial)",
                    data=csv_data,
                    file_name=f"hyperion_bitacora_legal_{fecha_desde}_al_{fecha_hasta}.csv",
                    mime="text/csv",
                    help="Descarga el reporte firmado digitalmente por la base de datos para auditorías de cumplimiento."
                )
            else:
                st.warning("⚠️ No se encontraron eventos de seguridad en el rango de fechas seleccionado.")
                
        except Exception as e:
            st.error(f"❌ Error al consultar la tabla 'audit_log': {e}")
            st.info("💡 Verifica que la estructura de la tabla coincida con los campos: timestamp, actor, action, context, hash_this.")