import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent

# Set isolated framework directories for local sandboxing
os.environ.setdefault("KERAS_HOME", str(BASE_DIR / ".keras"))
os.environ.setdefault("MPLCONFIGDIR", str(BASE_DIR / ".matplotlib_cache"))

# Directory Hierarchy
DATA_DIR = BASE_DIR / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"
DATA_SAMPLES_DIR = DATA_DIR / "samples"

MODELS_DIR = BASE_DIR / "models"
SAVED_MODEL_DIR = MODELS_DIR / "saved_model"
METADATA_DIR = MODELS_DIR / "metadata"

ARTIFACTS_DIR = BASE_DIR / "artifacts"
EVALUATION_DIR = ARTIFACTS_DIR / "evaluation"
PLOTS_DIR = ARTIFACTS_DIR / "plots"

DOCS_DIR = BASE_DIR / "docs"
DATABASE_PATH = DATA_DIR / "cyber_soc.db"

# Create required directories
for directory in [
    DATA_RAW_DIR, DATA_PROCESSED_DIR, DATA_SAMPLES_DIR,
    SAVED_MODEL_DIR, METADATA_DIR, EVALUATION_DIR, PLOTS_DIR
]:
    directory.mkdir(parents=True, exist_ok=True)

# Application Settings
APP_NAME = "Deep Learning Cyber Threat Detection & SOAR Prototype"
VERSION = "1.0.0"
# DEPLOYMENT PREPARATION: Environment configurable network binding
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", 5050))
DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "academic-soc-secret-key-btech-2026")
MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", 100))

# FreeLLMAPI Configuration (OpenAI-Compatible AI Gateway)
FREELLMAPI_BASE_URL = os.environ.get("FREELLMAPI_BASE_URL", "http://localhost:8000/v1").rstrip("/")
FREELLMAPI_API_KEY = os.environ.get("FREELLMAPI_API_KEY", "sk-freellmapi-free")
FREELLMAPI_MODEL = os.environ.get("FREELLMAPI_MODEL", "gemini-1.5-flash")
FREELLMAPI_TIMEOUT_SEC = int(os.environ.get("FREELLMAPI_TIMEOUT_SEC", 8))

# Incident Response Mode
# Default MUST remain SIMULATION ONLY to ensure no unauthorized host modifications
DEFAULT_RESPONSE_MODE = "SIMULATION_ONLY"
ALLOWED_RESPONSE_MODES = ["SIMULATION_ONLY", "MANUAL_APPROVAL_ONLY"]

# Canonical Attack Categories (Standard 5-class multi-classification mapping)
ATTACK_CATEGORIES = {
    "Benign": 0,
    "DoS": 1,
    "Probe": 2,
    "R2L": 3,
    "U2R": 4
}
INV_ATTACK_CATEGORIES = {v: k for k, v in ATTACK_CATEGORIES.items()}

# NSL-KDD specific raw attack mapping to canonical 5 classes
NSL_KDD_ATTACK_MAP = {
    # Benign
    "normal": "Benign",
    # DoS
    "apache2": "DoS", "back": "DoS", "land": "DoS", "neptune": "DoS",
    "mailbomb": "DoS", "pod": "DoS", "processtable": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "udpstorm": "DoS",
    # Probe
    "ipsweep": "Probe", "mscan": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "saint": "Probe", "satan": "Probe",
    # R2L (Remote to Local)
    "ftp_write": "R2L", "guess_passwd": "R2L", "httptunnel": "R2L", "imap": "R2L",
    "multihop": "R2L", "named": "R2L", "phf": "R2L", "sendmail": "R2L",
    "snmpgetattack": "R2L", "snmpguess": "R2L", "spy": "R2L", "warezclient": "R2L",
    "warezmaster": "R2L", "xlock": "R2L", "xsnoop": "R2L",
    # U2R (User to Root)
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "ps": "U2R",
    "rootkit": "U2R", "sqlattack": "U2R", "xterm": "U2R"
}

# CICIDS2017 specific label mapping to canonical classes
CICIDS_ATTACK_MAP = {
    "BENIGN": "Benign",
    "DDoS": "DoS", "DoS Hulk": "DoS", "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS", "Heartbleed": "DoS",
    "PortScan": "Probe",
    "FTP-Patator": "R2L", "SSH-Patator": "R2L", "Bot": "R2L",
    "Web Attack  Brute Force": "R2L", "Web Attack  XSS": "R2L",
    "Web Attack  Sql Injection": "R2L",
    "Infiltration": "U2R"
}

# Severity Policies & Thresholds
SEVERITY_LEVELS = ["Informational", "Low", "Medium", "High", "Critical"]

# Mapping from Attack Category & Confidence to Suggested SOAR Actions
RESPONSE_POLICY = {
    "Benign": {
        "severity": "Informational",
        "action": "LOG_TELEMETRY",
        "description": "Normal network transaction recorded for baseline analysis.",
        "requires_approval": False
    },
    "Probe": {
        "severity": "Low",
        "action": "RATE_LIMIT_AND_LOG",
        "description": "Reconnaissance activity detected (e.g. port scan/ping sweep). Apply rate-limiting policy and monitor source IP.",
        "requires_approval": False
    },
    "DoS": {
        "severity": "High",
        "action": "SIMULATED_IP_BLOCK",
        "description": "High volume denial-of-service traffic detected. Propose edge firewall blocking rule for source IP.",
        "requires_approval": True
    },
    "R2L": {
        "severity": "High",
        "action": "SIMULATED_SESSION_TERMINATE",
        "description": "Unauthorized access or brute-force pattern detected. Terminate active transport session and flag credentials.",
        "requires_approval": True
    },
    "U2R": {
        "severity": "Critical",
        "action": "SIMULATED_HOST_ISOLATION",
        "description": "Privilege escalation / rootkit behavior detected. Propose quarantine of target host and alert incident commander.",
        "requires_approval": True
    }
}

# Supported features for NSL-KDD
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"
]
