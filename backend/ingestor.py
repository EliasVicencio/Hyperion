import hashlib
import json
import os
from datetime import datetime
from threading import Lock

VAULT_DIR = "logs/vault"
os.makedirs(VAULT_DIR, exist_ok=True)
lock = Lock() 

class HyperionIngestor:
    @staticmethod
    def get_last_hash(service_id: str):
        path = f"{VAULT_DIR}/{service_id}.json"
        if not os.path.exists(path):
            return "0" * 64
        with open(path, "r") as f:
            try:
                logs = json.load(f)
                return logs[-1]["hash_this"] if logs else "0" * 64
            except:
                return "0" * 64

    @classmethod
    def process_log(cls, service_id: str, payload: dict):
        with lock: 
            prev_hash = cls.get_last_hash(service_id)
            
            # Ajuste de nombres de campos para compatibilidad con el Dashboard
            entry = {
                "index": cls._get_next_index(service_id),
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "source": service_id,
                "event_type": payload.get("event_type", "N/A"), # Cambiado 'event' por 'event_type'
                "actor": payload.get("actor", "system"),
                "target": payload.get("target", "unknown"),
                "context": payload.get("context", {}),
                "hash_prev": prev_hash
            }
            
            # Cálculo del Hash
            entry_json = json.dumps(entry, sort_keys=True)
            entry["hash_this"] = hashlib.sha256(entry_json.encode()).hexdigest()
            
            cls._save_to_vault(service_id, entry)
            return entry["hash_this"], entry["index"]

    @staticmethod
    def _get_next_index(service_id: str):
        path = f"{VAULT_DIR}/{service_id}.json"
        if not os.path.exists(path): return 0
        with open(path, "r") as f:
            try: 
                data = json.load(f)
                return len(data)
            except: return 0

    @staticmethod
    def _save_to_vault(service_id: str, entry: dict):
        path = f"{VAULT_DIR}/{service_id}.json"
        logs = []
        if os.path.exists(path):
            with open(path, "r") as f:
                try: logs = json.load(f)
                except: logs = []
        logs.append(entry)
        with open(path, "w") as f:
            json.dump(logs, f, indent=4)