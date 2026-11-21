from typing import Dict, Any, Tuple
import json
import config
from src.database import save_incident, log_audit

def generate_response_recommendation(
    threat_category: str,
    severity: str,
    confidence: float,
    source_ip: str = "192.168.1.105",
    destination_ip: str = "10.0.0.1",
    protocol: str = "tcp",
    service: str = "http",
    raw_features: Dict[str, Any] = None,
    auto_save: bool = True
) -> Dict[str, Any]:
    """
    Evaluates policy rules and determines the explainable incident response recommendation.
    Enforces safe simulation mode: NO host firewall or network configurations are ever modified.
    """
    policy = config.RESPONSE_POLICY.get(threat_category, config.RESPONSE_POLICY["Benign"])
    
    recommended_action = policy["action"]
    base_description = policy["description"]
    requires_approval = policy["requires_approval"]

    # In SIMULATION_ONLY mode:
    # If requires_approval is False (e.g. Benign, Probe), action executes immediately in simulation.
    # If requires_approval is True (e.g. DoS IP Block, U2R Host Isolation), status is PENDING_APPROVAL.
    if requires_approval:
        action_status = "PENDING_APPROVAL"
        status_note = "Action staged in simulation pending human Security Analyst authorization."
    else:
        action_status = "SIMULATED_EXECUTED"
        status_note = "Action automatically simulated according to active defensive policy."

    simulated_payload = {
        "action_type": recommended_action,
        "mode": config.DEFAULT_RESPONSE_MODE,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "target_service": service,
        "simulated_command": f"# [SIMULATION ONLY] iptables -A INPUT -s {source_ip} -j DROP",
        "safeguard_active": True
    }

    incident_id = None
    if auto_save:
        incident_id = save_incident(
            threat_category=threat_category,
            severity=severity,
            confidence=confidence,
            recommended_action=recommended_action,
            action_status=action_status,
            requires_approval=requires_approval,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            service=service,
            raw_features=raw_features,
            response_mode=config.DEFAULT_RESPONSE_MODE
        )
        log_audit(
            "RESPONSE_RECOMMENDED",
            f"Incident {incident_id}: Threat={threat_category}, Action={recommended_action}, Status={action_status}"
        )

    return {
        "incident_id": incident_id,
        "threat_category": threat_category,
        "severity": severity,
        "confidence": confidence,
        "recommended_action": recommended_action,
        "action_status": action_status,
        "requires_approval": requires_approval,
        "policy_description": base_description,
        "status_note": status_note,
        "simulated_payload": simulated_payload,
        "response_mode": config.DEFAULT_RESPONSE_MODE
    }
