import subprocess
import json
import os

def run_hyperion_scan(target_path: str = "."):
    # Ejecutamos Bandit en modo JSON
    # -r: recursivo, -f json: formato de salida
    result = subprocess.run(
        ["bandit", "-r", target_path, "-f", "json"], 
        capture_output=True, 
        text=True
    )
    
    # Si Bandit encuentra algo, el código de salida no es 0, pero el JSON se genera igual
    try:
        data = json.loads(result.stdout)
    except:
        return {"error": "No se pudo procesar el escaneo"}

    issues = data.get("results", [])
    
    # Separamos por severidad (Pensamiento Crítico contra el "Falso Positivo")
    criticals = [i for i in issues if i["issue_severity"] == "HIGH"]
    mediums = [i for i in issues if i["issue_severity"] == "MEDIUM"]
    
    # La decisión final: ¿Se puede desplegar?
    can_deploy = len(criticals) == 0
    
    return {
        "status": "REJECTED" if not can_deploy else "APPROVED",
        "can_deploy": can_deploy,
        "critical_count": len(criticals),
        "medium_count": len(mediums),
        "vulnerabilities": [
            {
                "file": i["filename"],
                "line": i["line_number"],
                "issue": i["issue_text"]
            } for i in criticals
        ]
    }