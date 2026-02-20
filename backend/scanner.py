import subprocess
import json

def analyze_code():
    # Escaneamos la propia carpeta de backend como ejemplo
    result = subprocess.run(["bandit", "-r", ".", "-f", "json"], capture_output=True, text=True)
    return json.loads(result.stdout)