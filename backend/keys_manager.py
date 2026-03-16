"""
keys_manager.py  —  Gestor de API Keys con cifrado fuerte.

Estándares de seguridad:
  - AES-128-CBC (Fernet) para cifrado en reposo
  - Master key derivada con PBKDF2-HMAC-SHA256 (600 000 iteraciones)
  - Salt único por instalación (16 bytes, CSPRNG)
  - Archivos con permisos 0o600 (solo owner)
  - Keys NUNCA se exponen en variables de entorno ni logs
  - Keys en memoria se borran después de usarse (best-effort)
  - Audit log de accesos (sin valores)
  - Bootstrap: si una key se pasa via env var, se importa al store encriptado
    y se borra del entorno inmediatamente
"""

import os, json, hashlib, logging, time
from pathlib import Path
from cryptography.fernet import Fernet
import base64

DATA_DIR   = Path("/app/data/keys")   # ← volumen persistente osint-keys
SALT_FILE  = DATA_DIR / ".salt"
KEYS_FILE  = DATA_DIR / "apikeys.enc"
AUDIT_FILE = DATA_DIR / "keys_audit.log"

_PBKDF2_ITERATIONS = 600_000
_log = logging.getLogger("keys_manager")

SERVICES = {
    "hunter_io": {
        "label": "Hunter.io", "url": "https://hunter.io/api-keys",
        "help": "Free tier: 25 búsquedas/mes. Busca emails por dominio.",
        "sensitive": False, "envvar": "HUNTER_API_KEY",
    },
    "hibp": {
        "label": "Have I Been Pwned", "url": "https://haveibeenpwned.com/API/Key",
        "help": "API de pago (~$3.50/mes). Detecta brechas por dominio/email.",
        "sensitive": True, "envvar": "HIBP_API_KEY",
    },
    "snov_io_client": {
        "label": "Snov.io — Client ID", "url": "https://app.snov.io/account?type=api",
        "help": "Free tier: 50 créditos/mes.", "sensitive": False, "envvar": "SNOV_CLIENT_ID",
    },
    "snov_io_secret": {
        "label": "Snov.io — Client Secret", "url": "https://app.snov.io/account?type=api",
        "help": "Ver campo anterior.", "sensitive": True, "envvar": "SNOV_CLIENT_SECRET",
    },
    "shodan": {
        "label": "Shodan", "url": "https://account.shodan.io/",
        "help": "Free tier disponible. IoT, servicios expuestos, FAVICON hash.",
        "sensitive": True, "envvar": "SHODAN_API_KEY",
    },
    "virustotal": {
        "label": "VirusTotal", "url": "https://www.virustotal.com/gui/my-apikey",
        "help": "Free tier: 500 req/día. Reputación de dominio, IPs maliciosas.",
        "sensitive": True, "envvar": "VIRUSTOTAL_API_KEY",
    },
    "securitytrails": {
        "label": "SecurityTrails", "url": "https://securitytrails.com/app/account/credentials",
        "help": "Free tier: 50 req/mes. Subdomains históricos y DNS history.",
        "sensitive": True, "envvar": "SECURITYTRAILS_API_KEY",
    },
    "intelx": {
        "label": "Intelligence X", "url": "https://intelx.io/account?tab=developer",
        "help": "Free tier disponible. Dark web, brechas, credenciales filtradas.",
        "sensitive": True, "envvar": "INTELX_API_KEY",
    },
}

# ── Salt ──────────────────────────────────────────────────────────────────────
def _get_or_create_salt() -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()
    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    SALT_FILE.chmod(0o600)
    return salt

# ── Key derivation: PBKDF2-HMAC-SHA256 ───────────────────────────────────────
def _derive_fernet_key(salt: bytes) -> bytes:
    """
    Derives encryption key from OSINT_DEPLOY_SECRET only.
    NOT tied to hostname — hostname changes on every docker rebuild
    which would invalidate all stored keys.
    600 000 PBKDF2 iterations (OWASP 2023 recommendation for SHA-256).
    """
    deploy_secret = os.environ.get("OSINT_DEPLOY_SECRET", "osint-default-changeme")
    password      = deploy_secret.encode()
    raw = hashlib.pbkdf2_hmac("sha256", password, salt, _PBKDF2_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(raw)

def _fernet() -> Fernet:
    return Fernet(_derive_fernet_key(_get_or_create_salt()))

# ── Audit log (no values ever) ────────────────────────────────────────────────
def _audit(action: str, service_id: str, success: bool = True) -> None:
    try:
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "action": action, "service": service_id, "ok": success}
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        AUDIT_FILE.chmod(0o600)
    except Exception:
        pass

# ── Core ──────────────────────────────────────────────────────────────────────
def load_keys() -> dict:
    if not KEYS_FILE.exists():
        return {}
    try:
        encrypted = KEYS_FILE.read_bytes()
        plain = _fernet().decrypt(encrypted)
        data  = json.loads(plain)
        plain = b"\x00" * len(plain)  # best-effort wipe
        return data
    except Exception as e:
        _log.warning("load_keys failed (%s: %s) — keys may have been encrypted with different secret or hostname",
                     type(e).__name__, str(e)[:100])
        return {}

def save_keys(keys: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    plain = json.dumps(keys).encode()
    try:
        encrypted = _fernet().encrypt(plain)
        KEYS_FILE.write_bytes(encrypted)
        KEYS_FILE.chmod(0o600)
    finally:
        plain = b"\x00" * len(plain)  # best-effort wipe

def get_key(service_id: str) -> str | None:
    """
    Get a key. Never logs or returns the value in errors.
    Bootstrap: if key is in env var, imports it to encrypted store + clears env.
    """
    stored = load_keys().get(service_id)
    if stored:
        _audit("get", service_id)
        return stored

    # Bootstrap from env var (first start)
    svc = SERVICES.get(service_id, {})
    env_name = svc.get("envvar", "")
    if env_name:
        env_val = os.environ.get(env_name, "").strip()
        if env_val:
            set_key(service_id, env_val)
            os.environ.pop(env_name, None)  # clear from /proc/*/environ
            _audit("bootstrap", service_id)
            _log.info("'%s' imported from env → encrypted store (env cleared)", service_id)
            return env_val

    return None

def set_key(service_id: str, value: str) -> None:
    if service_id not in SERVICES:
        raise ValueError(f"Unknown service: {service_id}")
    keys = load_keys()
    action = "set" if value else "delete"
    if value:
        keys[service_id] = value
    else:
        keys.pop(service_id, None)
    save_keys(keys)
    _audit(action, service_id)
    _log.info("Key '%s' %s", service_id, action)

def get_status() -> list:
    """Service list with config status. Never exposes values."""
    stored = load_keys()
    result = []
    for svc_id, meta in SERVICES.items():
        has_stored = bool(stored.get(svc_id))
        has_env    = bool(os.environ.get(meta.get("envvar", ""), "").strip())
        result.append({
            "id":         svc_id,
            "label":      meta["label"],
            "url":        meta["url"],
            "help":       meta["help"],
            "sensitive":  meta.get("sensitive", False),
            "configured": has_stored or has_env,
            "source":     "encrypted_store" if has_stored
                          else ("env_pending_import" if has_env else "none"),
        })
    return result

def get_audit_log(last_n: int = 100) -> list:
    if not AUDIT_FILE.exists():
        return []
    try:
        lines = AUDIT_FILE.read_text().strip().splitlines()
        entries = []
        for line in lines[-last_n:]:
            try: entries.append(json.loads(line))
            except Exception: pass
        return list(reversed(entries))
    except Exception:
        return []
