from typing import Dict, Any, Tuple
import config

def calculate_threat_severity(
    threat_category: str,
    confidence: float,
    flow_features: Dict[str, Any] = None
) -> Tuple[str, str]:
    """
    Computes an explainable threat severity score based on attack category,
    model confidence, and contextual risk factors.
    
    Returns:
        (severity_level, rationale)
    """
    flow_features = flow_features or {}

    if threat_category == "Benign":
        return "Informational", "Normal network flow characteristics; no anomalous divergence detected."

    elif threat_category == "Probe":
        if confidence > 0.85:
            return "Medium", f"High-confidence reconnaissance activity (confidence: {confidence*100:.1f}%). Repeated scanning signature."
        return "Low", f"Reconnaissance / scanning pattern observed with moderate confidence ({confidence*100:.1f}%)."

    elif threat_category == "DoS":
        # Check volume metrics if present
        src_bytes = flow_features.get("src_bytes", 0)
        count = flow_features.get("count", 0)
        if confidence > 0.88 or count > 300:
            return "Critical", f"Volumetric Denial-of-Service detected (confidence: {confidence*100:.1f}%, packet burst rate: {count}). Threat of service exhaustion."
        return "High", f"Denial-of-Service pattern detected (confidence: {confidence*100:.1f}%). Risk of degraded resource availability."

    elif threat_category == "R2L":
        failed_logins = flow_features.get("num_failed_logins", 0)
        if failed_logins > 0 or confidence > 0.85:
            return "Critical", f"Active remote brute-force or unauthorized credential trial detected (failed logins: {failed_logins}, confidence: {confidence*100:.1f}%)."
        return "High", f"Unauthorized remote-to-local access attempt detected (confidence: {confidence*100:.1f}%)."

    elif threat_category == "U2R":
        # Root privilege escalation is inherently high risk even at moderate confidence
        return "Critical", f"Critical privilege escalation / rootkit pattern detected (confidence: {confidence*100:.1f}%). Threat of full system takeover."

    return "Low", f"Unclassified anomalous pattern detected (confidence: {confidence*100:.1f}%)."
