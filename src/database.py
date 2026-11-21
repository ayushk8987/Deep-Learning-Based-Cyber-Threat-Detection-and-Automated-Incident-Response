import sqlite3
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from werkzeug.security import generate_password_hash, check_password_hash
import config

def get_db_connection() -> sqlite3.Connection:
    """Creates and returns a connection to the SQLite database with row factory."""
    conn = sqlite3.connect(str(config.DATABASE_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initializes all relational tables if they do not already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Dataset Metadata
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS dataset_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dataset_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        row_count INTEGER NOT NULL,
        feature_count INTEGER NOT NULL,
        class_distribution TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)

    # 2. Model Metadata
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS model_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT NOT NULL UNIQUE,
        model_type TEXT NOT NULL,
        architecture TEXT NOT NULL,
        accuracy REAL,
        macro_f1 REAL,
        weighted_f1 REAL,
        training_time_sec REAL,
        inference_latency_ms REAL,
        model_path TEXT NOT NULL,
        preprocessor_path TEXT NOT NULL,
        is_active INTEGER DEFAULT 0,
        created_at TEXT NOT NULL
    );
    """)

    # 3. Detection Events
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS detection_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_uuid TEXT NOT NULL UNIQUE,
        timestamp TEXT NOT NULL,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        service TEXT,
        predicted_label TEXT NOT NULL,
        confidence REAL NOT NULL,
        severity TEXT NOT NULL,
        raw_features TEXT
    );
    """)

    # 4. Incident Records
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incident_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL UNIQUE,
        event_uuid TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL NOT NULL,
        recommended_action TEXT NOT NULL,
        action_status TEXT NOT NULL,
        response_mode TEXT NOT NULL,
        analyst_notes TEXT,
        requires_approval INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (event_uuid) REFERENCES detection_events (event_uuid)
    );
    """)

    # 5. Simulated Response Actions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS simulated_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        action_type TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        details TEXT NOT NULL,
        execution_status TEXT NOT NULL,
        simulated_at TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incident_records (incident_id)
    );
    """)

    # 6. Analyst Reviews
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analyst_reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        analyst_name TEXT NOT NULL,
        decision TEXT NOT NULL,
        comments TEXT,
        reviewed_at TEXT NOT NULL,
        FOREIGN KEY (incident_id) REFERENCES incident_records (incident_id)
    );
    """)

    # 7. System Audit Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    );
    """)

    # 8. User Accounts (AUTH VALIDATION)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Security Analyst',
        created_at TEXT NOT NULL
    );
    """)

    # Seed default authorized analyst if no users exist
    cursor.execute("SELECT COUNT(*) as count FROM users")
    if cursor.fetchone()["count"] == 0:
        default_email = "analyst@soc.local"
        default_pwd_hash = generate_password_hash("Secure@SOC2026!")
        cursor.execute("""
            INSERT INTO users (email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            default_email, default_pwd_hash, "Ayush Kumar (Lead Analyst)",
            "Senior Security Analyst", datetime.now(timezone.utc).isoformat()
        ))

    conn.commit()
    conn.close()

def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """AUTH VALIDATION: Validates user credentials against hashed database records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, password_hash, full_name, role FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row["password_hash"], password):
        user_dict = dict(row)
        user_dict.pop("password_hash", None)
        return user_dict
    return None

def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """AUTH VALIDATION: Fetches user by email address."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, full_name, role, created_at FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_user(email: str, password: str, full_name: str, role: str = "Security Analyst") -> bool:
    """AUTH VALIDATION: Securely registers a new user with password hashing."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users (email, password_hash, full_name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            email.strip().lower(),
            generate_password_hash(password),
            full_name.strip(),
            role.strip(),
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def log_audit(action: str, details: str = "") -> None:
    """Logs an operational event to the audit trail."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (action, details, timestamp) VALUES (?, ?, ?)",
        (action, details, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

def save_incident(
    threat_category: str,
    severity: str,
    confidence: float,
    recommended_action: str,
    action_status: str,
    requires_approval: bool,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "10.0.0.1",
    protocol: str = "tcp",
    service: str = "http",
    raw_features: Optional[Dict[str, Any]] = None,
    response_mode: str = config.DEFAULT_RESPONSE_MODE
) -> str:
    """Records a new threat event and corresponding incident record."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    event_uuid = f"EVT-{uuid.uuid4().hex[:8].upper()}"
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    now_ts = datetime.now(timezone.utc).isoformat()

    # Insert Detection Event
    cursor.execute("""
        INSERT INTO detection_events 
        (event_uuid, timestamp, source_ip, destination_ip, protocol, service, predicted_label, confidence, severity, raw_features)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_uuid, now_ts, source_ip, destination_ip, protocol, service,
        threat_category, confidence, severity, json.dumps(raw_features or {})
    ))

    # Insert Incident Record
    cursor.execute("""
        INSERT INTO incident_records
        (incident_id, event_uuid, threat_category, severity, confidence, recommended_action, 
         action_status, response_mode, requires_approval, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        incident_id, event_uuid, threat_category, severity, confidence, recommended_action,
        action_status, response_mode, 1 if requires_approval else 0, now_ts, now_ts
    ))

    # If action was automatically executed in simulation (e.g. for low severity / no approval needed)
    if action_status == "SIMULATED_EXECUTED":
        cursor.execute("""
            INSERT INTO simulated_actions 
            (incident_id, action_type, target_entity, details, execution_status, simulated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_id, recommended_action, source_ip,
            json.dumps({"action": recommended_action, "mode": "SIMULATION_ONLY", "rule": "Auto-dispatched policy"}),
            "SIMULATION_SUCCESS", now_ts
        ))

    conn.commit()
    conn.close()
    return incident_id

def get_incidents(limit: int = 100, severity: Optional[str] = None, threat: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves list of incident records with event details."""
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        SELECT i.incident_id, i.threat_category, i.severity, i.confidence,
               i.recommended_action, i.action_status, i.requires_approval,
               i.response_mode, i.analyst_notes, i.created_at,
               e.source_ip, e.destination_ip, e.protocol, e.service
        FROM incident_records i
        JOIN detection_events e ON i.event_uuid = e.event_uuid
        WHERE 1=1
    """
    params = []
    if severity:
        query += " AND i.severity = ?"
        params.append(severity)
    if threat:
        query += " AND i.threat_category = ?"
        params.append(threat)
    
    query += " ORDER BY i.created_at DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()
    incidents = [dict(row) for row in rows]
    conn.close()
    return incidents

def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full details for a single incident including reviews and simulated actions."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT i.*, e.source_ip, e.destination_ip, e.protocol, e.service, e.raw_features
        FROM incident_records i
        JOIN detection_events e ON i.event_uuid = e.event_uuid
        WHERE i.incident_id = ?
    """, (incident_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    
    incident = dict(row)
    if incident.get("raw_features"):
        try:
            incident["raw_features"] = json.loads(incident["raw_features"])
        except Exception:
            pass

    # Fetch simulated actions
    cursor.execute("SELECT * FROM simulated_actions WHERE incident_id = ? ORDER BY simulated_at DESC", (incident_id,))
    incident["simulated_actions"] = [dict(r) for r in cursor.fetchall()]

    # Fetch reviews
    cursor.execute("SELECT * FROM analyst_reviews WHERE incident_id = ? ORDER BY reviewed_at DESC", (incident_id,))
    incident["reviews"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return incident

def review_incident(incident_id: str, analyst_name: str, decision: str, comments: str) -> bool:
    """Updates incident status based on analyst review (APPROVE / REJECT)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    now_ts = datetime.now(timezone.utc).isoformat()

    cursor.execute("SELECT recommended_action, action_status FROM incident_records WHERE incident_id = ?", (incident_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    recommended_action = row["recommended_action"]
    new_status = "SIMULATED_EXECUTED" if decision == "APPROVED" else "ANALYST_REJECTED"

    # Insert review
    cursor.execute("""
        INSERT INTO analyst_reviews (incident_id, analyst_name, decision, comments, reviewed_at)
        VALUES (?, ?, ?, ?, ?)
    """, (incident_id, analyst_name, decision, comments, now_ts))

    # Update incident record
    cursor.execute("""
        UPDATE incident_records 
        SET action_status = ?, analyst_notes = ?, updated_at = ?
        WHERE incident_id = ?
    """, (new_status, comments, now_ts, incident_id))

    # If approved, log simulated containment action
    if decision == "APPROVED":
        cursor.execute("SELECT source_ip FROM detection_events e JOIN incident_records i ON e.event_uuid = i.event_uuid WHERE i.incident_id = ?", (incident_id,))
        ip_row = cursor.fetchone()
        source_ip = ip_row["source_ip"] if ip_row else "192.168.1.100"

        cursor.execute("""
            INSERT INTO simulated_actions 
            (incident_id, action_type, target_entity, details, execution_status, simulated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            incident_id, recommended_action, source_ip,
            json.dumps({"analyst": analyst_name, "decision": decision, "notes": comments, "mode": "SIMULATION_ONLY"}),
            "SIMULATION_SUCCESS", now_ts
        ))

    conn.commit()
    conn.close()
    log_audit("INCIDENT_REVIEWED", f"Incident {incident_id} reviewed by {analyst_name}: {decision}")
    return True

def get_dashboard_metrics() -> Dict[str, Any]:
    """Computes aggregated metrics for the overview dashboard."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM detection_events")
    total_analyzed = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM detection_events WHERE predicted_label = 'Benign'")
    benign_count = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM detection_events WHERE predicted_label != 'Benign'")
    malicious_count = cursor.fetchone()["total"]

    # Incidents by severity
    cursor.execute("SELECT severity, COUNT(*) as count FROM incident_records GROUP BY severity")
    severity_dist = {row["severity"]: row["count"] for row in cursor.fetchall()}

    # Threats by category
    cursor.execute("SELECT threat_category, COUNT(*) as count FROM incident_records GROUP BY threat_category")
    threat_dist = {row["threat_category"]: row["count"] for row in cursor.fetchall()}

    # Pending approvals count
    cursor.execute("SELECT COUNT(*) as count FROM incident_records WHERE action_status = 'PENDING_APPROVAL'")
    pending_approvals = cursor.fetchone()["count"]

    # Simulated actions count
    cursor.execute("SELECT COUNT(*) as count FROM simulated_actions")
    simulated_actions_count = cursor.fetchone()["count"]

    conn.close()
    return {
        "total_analyzed": total_analyzed,
        "benign_count": benign_count,
        "malicious_count": malicious_count,
        "severity_distribution": severity_dist,
        "threat_distribution": threat_dist,
        "pending_approvals": pending_approvals,
        "simulated_actions_count": simulated_actions_count,
        "response_mode": config.DEFAULT_RESPONSE_MODE
    }

def get_simulated_actions(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves logged simulated response actions."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT a.*, i.threat_category, i.severity 
        FROM simulated_actions a
        JOIN incident_records i ON a.incident_id = i.incident_id
        ORDER BY a.simulated_at DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    actions = [dict(r) for r in rows]
    conn.close()
    return actions
