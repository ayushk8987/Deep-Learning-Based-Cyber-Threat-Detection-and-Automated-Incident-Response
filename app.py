import os
import io
import json
import re
from pathlib import Path
from flask import Flask, request, jsonify, render_template, send_file, Response, session, redirect, url_for
from werkzeug.utils import secure_filename
import pandas as pd

import config
from src.database import (
    init_db, get_dashboard_metrics, get_incidents, get_incident_by_id,
    review_incident, get_simulated_actions, get_db_connection, log_audit,
    authenticate_user, get_user_by_email
)
from src.data_validation import validate_dataset_schema
from src.data_loader import generate_synthetic_dataset
from src.predict import ThreatPredictionPipeline
from src.reporting import generate_csv_incident_report, generate_academic_project_summary

# Initialize Flask Application
app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_SIZE_MB * 1024 * 1024

# Ensure Database Tables Exist
init_db()

# Initialize Inference Pipeline (Lazy singleton)
_pipeline = None

def get_pipeline() -> ThreatPredictionPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = ThreatPredictionPipeline()
    return _pipeline

# AUTH VALIDATION: Context processor for user session
@app.context_processor
def inject_user():
    return {"current_user": session.get("user")}

# AUTH VALIDATION: RFC 5322 compatible email validation pattern
RFC_5322_EMAIL_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*|"
    r"\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")"
    r"@(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?|"
    r"\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-zA-Z0-9-]*[a-zA-Z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"
)

def validate_password_criteria(password: str) -> dict:
    """AUTH VALIDATION: Evaluates 5-point password rules."""
    return {
        "minLength": len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[^A-Za-z0-9]", password))
    }

# -------------------------------------------------------------
# AUTHENTICATION ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/auth/login", methods=["POST"])
def auth_login_api():
    """AUTH VALIDATION: Validates email, password criteria, and authenticates analyst session."""
    data = request.get_json() or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))

    if not email:
        return jsonify({"success": False, "error": "Please enter your email address."}), 400

    if not RFC_5322_EMAIL_REGEX.match(email):
        return jsonify({"success": False, "error": "Please enter a valid email address matching RFC 5322 standard."}), 400

    if not password:
        return jsonify({"success": False, "error": "Please enter your password."}), 400

    # Validate 5 password rules
    rules = validate_password_criteria(password)
    if not all(rules.values()):
        missing = []
        if not rules["minLength"]: missing.append("at least 8 characters")
        if not rules["uppercase"]: missing.append("one uppercase letter (A-Z)")
        if not rules["lowercase"]: missing.append("one lowercase letter (a-z)")
        if not rules["number"]: missing.append("one number (0-9)")
        if not rules["special"]: missing.append("one special character")
        return jsonify({
            "success": False,
            "error": f"Password requirement not met: must include {', '.join(missing)}.",
            "rules": rules
        }), 400

    user = authenticate_user(email, password)
    if not user:
        return jsonify({"success": False, "error": "Unable to sign in. Please check your credentials and try again."}), 401

    session["user"] = user
    log_audit("USER_LOGIN_SUCCESS", f"Analyst {user['email']} authenticated successfully.")
    return jsonify({
        "success": True,
        "message": "Authentication successful.",
        "user": user
    })

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout_api():
    """AUTH VALIDATION: Clears current analyst session."""
    user = session.pop("user", None)
    if user:
        log_audit("USER_LOGOUT", f"Analyst {user.get('email')} logged out.")
    return jsonify({"success": True, "message": "Logged out successfully."})

@app.route("/api/auth/status", methods=["GET"])
def auth_status_api():
    """AUTH VALIDATION: Returns session authentication state."""
    user = session.get("user")
    return jsonify({
        "authenticated": user is not None,
        "user": user
    })

# -------------------------------------------------------------
# REST API ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health status check for system components and active model."""
    pipeline = get_pipeline()
    return jsonify({
        "status": "healthy",
        "app_name": config.APP_NAME,
        "version": config.VERSION,
        "database_connected": config.DATABASE_PATH.exists(),
        "model_loaded": pipeline.is_ready(),
        "active_model_type": pipeline.active_model_type,
        "response_mode": config.DEFAULT_RESPONSE_MODE
    })

@app.route("/api/dashboard/summary", methods=["GET"])
def dashboard_summary():
    """Aggregated detection and incident response metrics."""
    metrics = get_dashboard_metrics()
    pipeline = get_pipeline()
    metrics["model_ready"] = pipeline.is_ready()
    metrics["active_model"] = pipeline.active_model_type
    return jsonify(metrics)

@app.route("/api/model/status", methods=["GET"])
def model_status():
    """Current model metadata from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM model_metadata WHERE is_active = 1 LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "NO_ACTIVE_MODEL", "message": "No trained model currently active in database."}), 404

    return jsonify(dict(row))

@app.route("/api/model/metrics", methods=["GET"])
def model_metrics():
    """Detailed evaluation metrics, confusion matrix, and training curves."""
    eval_json_path = config.EVALUATION_DIR / "cnn_lstm_metrics.json"
    comp_json_path = config.EVALUATION_DIR / "model_comparison.json"

    metrics_data = {}
    if eval_json_path.exists():
        with open(eval_json_path, "r") as f:
            metrics_data["cnn_lstm"] = json.load(f)

    if comp_json_path.exists():
        with open(comp_json_path, "r") as f:
            metrics_data["comparison"] = json.load(f)

    if not metrics_data:
        return jsonify({"status": "NOT_AVAILABLE", "message": "Model evaluation has not been executed yet."}), 404

    return jsonify(metrics_data)

@app.route("/api/dataset/validate", methods=["POST"])
def validate_dataset_api():
    """Inspects and validates an uploaded CSV file without running inference."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded in form field 'file'"}), 400

    file = request.files["file"]
    if not file.filename.endswith(".csv"):
        return jsonify({"error": "Only CSV files are supported."}), 400

    try:
        df = pd.read_csv(file)
        val_summary = validate_dataset_schema(df, is_training=False)
        return jsonify(val_summary)
    except Exception as e:
        return jsonify({"error": f"Failed to parse CSV file: {str(e)}"}), 400

@app.route("/api/detection/predict", methods=["POST"])
def run_prediction_api():
    """Accepts CSV file upload, runs batch inference, and records incidents."""
    pipeline = get_pipeline()
    if not pipeline.is_ready():
        return jsonify({"error": "Inference model is not initialized or trained yet."}), 503

    if "file" not in request.files:
        return jsonify({"error": "No file attached to request."}), 400

    file = request.files["file"]
    if not file.filename.endswith((".csv", ".txt")):
        return jsonify({"error": "File must be a .csv or .txt file."}), 400

    try:
        # Check if file has header, otherwise try NSL-KDD format
        first_line = file.stream.readline().decode("utf-8")
        file.stream.seek(0)
        
        if any(c in first_line for c in ["duration", "protocol_type", "src_bytes", "Destination Port"]):
            df = pd.read_csv(file)
        else:
            # Raw NSL-KDD without header
            df = pd.read_csv(file, header=None, names=config.NSL_KDD_COLUMNS)

        max_limit = int(request.form.get("limit", 250))
        results = pipeline.predict_batch(df, save_incidents=True, max_records=max_limit)

        return jsonify({
            "status": "success",
            "processed_count": len(results),
            "results": results
        })
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {str(e)}"}), 500

@app.route("/api/incidents", methods=["GET"])
def list_incidents():
    """Retrieves filtered list of security incidents."""
    severity = request.args.get("severity")
    threat = request.args.get("threat")
    limit = int(request.args.get("limit", 100))
    incidents = get_incidents(limit=limit, severity=severity, threat=threat)
    return jsonify(incidents)

@app.route("/api/incidents/<incident_id>", methods=["GET"])
def incident_detail(incident_id: str):
    """Retrieves complete details for a single incident."""
    incident = get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    return jsonify(incident)

@app.route("/api/incidents/<incident_id>/review", methods=["POST"])
def review_incident_api(incident_id: str):
    """Submits a human security analyst approval or rejection decision."""
    data = request.get_json() or {}
    decision = data.get("decision", "APPROVED").upper()
    analyst_name = data.get("analyst_name", "Lead SOC Analyst")
    comments = data.get("comments", "Reviewed and verified via SOC portal.")

    if decision not in ["APPROVED", "REJECTED"]:
        return jsonify({"error": "Decision must be 'APPROVED' or 'REJECTED'"}), 400

    success = review_incident(incident_id, analyst_name, decision, comments)
    if not success:
        return jsonify({"error": "Incident not found or could not be updated."}), 404

    return jsonify({
        "status": "success",
        "incident_id": incident_id,
        "decision": decision,
        "mode": config.DEFAULT_RESPONSE_MODE,
        "message": f"Incident {incident_id} successfully {decision.lower()} in safe simulation mode."
    })

@app.route("/api/incidents/<incident_id>/ai-explain", methods=["GET"])
def ai_explain_incident(incident_id: str):
    """Generates an AI threat intelligence briefing using FreeLLMAPI (with resilient fallback)."""
    from src.llm_assistant import query_freellmapi_analysis
    incident = get_incident_by_id(incident_id)
    if not incident:
        return jsonify({"error": "Incident not found"}), 404
    intel = query_freellmapi_analysis(incident)
    return jsonify(intel)

@app.route("/api/responses/history", methods=["GET"])
def response_history_api():
    """Lists history of simulated SOAR response actions."""
    limit = int(request.args.get("limit", 50))
    actions = get_simulated_actions(limit=limit)
    return jsonify(actions)

@app.route("/api/export/incidents", methods=["GET"])
def export_incidents_csv():
    """Exports all logged incidents as a CSV report."""
    csv_content = generate_csv_incident_report()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=soc_incidents_report.csv"}
    )

@app.route("/api/generate-demo-data", methods=["POST"])
def generate_demo_data_api():
    """Creates a sample test CSV in data/samples/ for instant verification."""
    sample_path = config.DATA_SAMPLES_DIR / "synthetic_demo_flows.csv"
    generate_synthetic_dataset(sample_path, num_records=200)
    return jsonify({
        "status": "success",
        "file_path": str(sample_path),
        "filename": "synthetic_demo_flows.csv",
        "records": 200,
        "note": "Explicitly labelled as synthetic verification dataset."
    })

@app.route("/api/detection/simulate-preset", methods=["POST"])
def simulate_preset_api():
    """Generates realistic packet flows for a chosen attack category and runs real-time DL inference."""
    data = request.get_json() or {}
    category = str(data.get("category", "random")).lower()
    count = min(int(data.get("count", 5)), 25)

    pipeline = get_pipeline()
    if not pipeline.is_ready():
        return jsonify({"error": "Inference model is not initialized or trained yet."}), 503

    sample_file = config.DATA_SAMPLES_DIR / "synthetic_demo_flows.csv"
    if not sample_file.exists():
        generate_synthetic_dataset(sample_file, num_records=200)

    try:
        df = pd.read_csv(sample_file)
        if category in ["dos", "neptune"]:
            subset = df[df["label"].isin(["neptune", "smurf", "back", "teardrop", "pod"])]
        elif category in ["probe", "satan"]:
            subset = df[df["label"].isin(["satan", "ipsweep", "portsweep", "nmap"])]
        elif category in ["r2l", "guess_passwd"]:
            subset = df[df["label"].isin(["guess_passwd", "warezmaster", "ftp_write", "multihop"])]
        elif category in ["benign", "normal"]:
            subset = df[df["label"] == "normal"]
        else:
            subset = df

        if subset.empty:
            subset = df

        sample_df = subset.sample(n=min(count, len(subset)), replace=True)
        results = pipeline.predict_batch(sample_df, save_incidents=True, max_records=count)

        analyst = session.get("user", {}).get("full_name", "Security Analyst")
        log_audit("PRESET_SIMULATION_EXECUTED", f"Analyst {analyst} ran preset simulation for {category.upper()} ({len(results)} flows).")

        return jsonify({
            "status": "success",
            "category": category,
            "processed_count": len(results),
            "results": results
        })
    except Exception as e:
        return jsonify({"error": f"Preset simulation failed: {str(e)}"}), 500

# -------------------------------------------------------------
# WEB USER INTERFACE ROUTES
# -------------------------------------------------------------

@app.route("/")
def view_dashboard():
    """Overview Security Operations Center (SOC) dashboard."""
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/detection")
def view_detection():
    """Traffic analysis and batch inference page."""
    return render_template("detection.html", active_page="detection")

@app.route("/incidents")
def view_incidents():
    """Incident management and analyst review workflow."""
    return render_template("incidents.html", active_page="incidents")

@app.route("/model-metrics")
def view_model_metrics():
    """Deep learning vs baseline performance evaluation view."""
    return render_template("model_metrics.html", active_page="model_metrics")

@app.route("/response-center")
def view_response_center():
    """SOAR response policies and simulated containment history."""
    return render_template("response_center.html", active_page="response_center")

@app.route("/settings")
def view_settings():
    """System settings, dataset paths, and diagnostic status."""
    return render_template("settings.html", active_page="settings")

# AUTH VALIDATION: Authentication view routes
@app.route("/login")
def view_login():
    """AUTH VALIDATION: Renders the white-themed authentication portal."""
    if session.get("user"):
        return redirect(url_for("view_dashboard"))
    return render_template("login.html", active_page="login")

@app.route("/logout")
def view_logout():
    """AUTH VALIDATION: Logs out user and redirects to login."""
    session.pop("user", None)
    return redirect(url_for("view_login"))

# -------------------------------------------------------------
# APPLICATION ENTRYPOINT
# -------------------------------------------------------------

if __name__ == "__main__":
    print(f"Starting {config.APP_NAME} v{config.VERSION} on http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
