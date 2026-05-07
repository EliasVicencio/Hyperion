import streamlit as st
import requests
import pandas as pd

# Configuración de URL - Asegúrate de que termine SIN barra diagonal
API_URL = "https://hyperion-gcic.onrender.com" 

def get_headers():
    if "access_token" in st.session_state:
        return {"Authorization": f"Bearer {st.session_state['access_token']}"}
    return {}

# --- PESTAÑA: GESTIÓN DE OPERADORES ---
def view_operadores():
    st.header("👥 Gestión de Operadores")
    
    try:
        response = requests.get(f"{API_URL}/admin/users", headers=get_headers())
        
        if response.status_code == 200:
            data = response.json()
            
            # BLINDAJE: Verificamos que sea una lista antes de pasar a Pandas
            if isinstance(data, list):
                if len(data) > 0:
                    df = pd.DataFrame(data)
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("No hay operadores registrados.")
            else:
                st.error(f"Formato inesperado del servidor: {type(data)}")
        elif response.status_code == 401:
            st.warning("⚠️ Sesión expirada o no autorizado. Por favor, re-auténticate.")
        else:
            st.error(f"Error del servidor (Código {response.status_code})")
            
    except Exception as e:
        st.error(f"❌ Error crítico de conexión: {str(e)}")

# --- PESTAÑA: LOGS DE AUDITORÍA ---
def view_audit_logs():
    st.header("📜 Registros de Auditoría")
    
    try:
        response = requests.get(f"{API_URL}/admin/audit-logs", headers=get_headers())
        
        if response.status_code == 200:
            data = response.json()
            
            # BLINDAJE contra el error "must pass an index"
            if isinstance(data, list):
                if len(data) > 0:
                    df = pd.DataFrame(data)
                    # Forzamos que el índice sea el timestamp o ID para evitar el error de scalar values
                    st.table(df)
                else:
                    st.info("Aún no hay registros en la base de datos.")
            else:
                st.error("El servidor no devolvió una lista de logs válida.")
        else:
            st.error(f"Error al obtener logs: {response.status_code}")
            
    except Exception as e:
        st.error(f"❌ Error de conexión: {str(e)}")

# --- PESTAÑA: ESTADO DEL SISTEMA (HEALTH) ---
def view_health():
    st.header("🚦 Estado del Sistema")
    
    try:
        response = requests.get(f"{API_URL}/health/deep")
        if response.status_code == 200:
            health = response.json()
            
            # Widgets de estado
            c1, c2, c3 = st.columns(3)
            c1.metric("API", "🟢 ONLINE" if health.get("api") == "healthy" else "🔴 DOWN")
            c2.metric("DB", "🟢 CONECTADA" if health.get("database") == "healthy" else "🔴 ERROR")
            c3.metric("SCORE", f"{health.get('health_score', 0)}%")
        else:
            st.error("No se pudo obtener el estado de salud profundo.")
    except:
        st.error("Servidor inalcanzable.")