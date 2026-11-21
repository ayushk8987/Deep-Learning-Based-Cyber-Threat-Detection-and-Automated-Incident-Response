import csv
import json
import io
from typing import List, Dict, Any
from pathlib import Path
import config
from src.database import get_db_connection, get_incidents, get_dashboard_metrics

def generate_csv_incident_report() -> str:
    """Generates a CSV string containing all logged security incidents and response statuses."""
    incidents = get_incidents(limit=1000)
    output = io.StringIO()
    
    fieldnames = [
        "incident_id", "created_at", "threat_category", "severity", "confidence",
        "recommended_action", "action_status", "response_mode", "source_ip",
        "destination_ip", "protocol", "service", "analyst_notes"
    ]
    
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for inc in incidents:
        writer.writerow(inc)
        
    return output.getvalue()

def generate_academic_project_summary() -> Dict[str, Any]:
    """Compiles a full academic project summary for faculty evaluation."""
    metrics = get_dashboard_metrics()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM model_metadata ORDER BY id DESC")
    models_meta = [dict(r) for r in cursor.fetchall()]
    conn.close()

    eval_json_path = config.EVALUATION_DIR / "cnn_lstm_metrics.json"
    dl_metrics = {}
    if eval_json_path.exists():
        with open(eval_json_path, "r") as f:
            dl_metrics = json.load(f)

    return {
        "project_title": "Deep Learning-Based Cyber Threat Detection and Automated Incident Response",
        "degree": "Bachelor of Technology in Computer Science & Engineering",
        "frameworks": ["TensorFlow/Keras", "Scikit-Learn", "Flask", "SQLite"],
        "dataset_benchmark": "NSL-KDD / CICIDS2017 flow-level feature representation",
        "architecture": "Hybrid 1D-CNN + Bidirectional-LSTM + Multi-Head Self-Attention",
        "response_engine": "Rule-based SOAR Policy Engine with Human-in-the-Loop Approval & Safe Simulation",
        "dashboard_summary": metrics,
        "registered_models": models_meta,
        "deep_learning_evaluation": dl_metrics
    }
