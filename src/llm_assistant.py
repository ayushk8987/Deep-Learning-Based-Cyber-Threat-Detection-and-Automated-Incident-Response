import json
import urllib.request
import urllib.error
from typing import Dict, Any

import config

DETERMINISTIC_THREAT_INTEL = {
    "DoS": {
        "summary": "Volumetric denial-of-service activity attempting resource exhaustion on destination services.",
        "mitre_technique": "T1498 - Network Denial of Service",
        "containment": "Deploy stateless border filtering (iptables / BGP Flowspec), rate-limit ingress TCP SYN packets, and verify gateway health."
    },
    "Probe": {
        "summary": "Network reconnaissance sweep probing open ports and service banners to map internal topology.",
        "mitre_technique": "T1046 - Network Service Discovery",
        "containment": "Blackhole scanning source IP for 60 minutes, review perimeter firewall ingress logs, and verify internal host isolation."
    },
    "R2L": {
        "summary": "Unauthorized remote access attempt exploiting authentication interfaces or service vulnerabilities.",
        "mitre_technique": "T1110 - Brute Force / Password Guessing",
        "containment": "Terminate active sessions, enforce account lockout policies, rotate exposed service credentials, and inspect auth logs."
    },
    "U2R": {
        "summary": "Privilege escalation attempt seeking root/administrative execution privileges on target host.",
        "mitre_technique": "T1068 - Exploitation for Privilege Escalation",
        "containment": "Isolate host from production VLAN, dump memory artifacts for forensic triage, and audit process hierarchy."
    },
    "Benign": {
        "summary": "Normal legitimate network telemetry consistent with established baseline profile.",
        "mitre_technique": "None (Legitimate Operational Traffic)",
        "containment": "Log telemetry record to data lake for continuous baseline model refinement. No defensive intervention required."
    }
}

def generate_fallback_analysis(incident: Dict[str, Any]) -> str:
    """Generates an explainable deterministic SOC briefing when LLM endpoint is unreachable."""
    cat = incident.get("threat_category", "Benign")
    intel = DETERMINISTIC_THREAT_INTEL.get(cat, DETERMINISTIC_THREAT_INTEL["Benign"])
    conf_pct = float(incident.get("confidence", 0.0)) * 100

    return (
        f"### SOC Incident Briefing (Automated Rule-Based Intelligence)\n\n"
        f"**1. Threat Assessment & Attack Profile:**\n"
        f"{intel['summary']} (DL Model Confidence: {conf_pct:.1f}%).\n\n"
        f"**2. MITRE ATT&CK Matrix Alignment:**\n"
        f"`{intel['mitre_technique']}`\n\n"
        f"**3. Recommended Containment & Remediation:**\n"
        f"{intel['containment']} Recommended playbook action: `{incident.get('recommended_action', 'LOG_TELEMETRY')}`."
    )

def query_freellmapi_analysis(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Queries FreeLLMAPI (OpenAI-compatible /v1 endpoint) to generate an AI-powered
    threat intelligence analysis for a detected security incident.
    Falls back gracefully if the endpoint is offline or unavailable.
    """
    cat = incident.get("threat_category", "Benign")
    prompt = (
        f"You are a Senior Security Operations Center (SOC) Incident Responder.\n"
        f"Analyze the following detected network threat telemetry:\n"
        f"- Incident ID: {incident.get('incident_id')}\n"
        f"- Threat Category: {cat}\n"
        f"- Severity: {incident.get('severity')}\n"
        f"- Deep Learning Model Confidence: {float(incident.get('confidence', 0.0)) * 100:.1f}%\n"
        f"- Source Entity: {incident.get('source_ip')} -> Destination: {incident.get('destination_ip')}\n"
        f"- Protocol / Service: {incident.get('protocol', 'tcp')} / {incident.get('service', 'http')}\n"
        f"- Recommended SOAR Action: {incident.get('recommended_action')}\n\n"
        f"Provide a concise 3-part Markdown analysis:\n"
        f"1. Executive Attack Summary & Blast Radius\n"
        f"2. MITRE ATT&CK Technique Mapping (Technique ID & Name)\n"
        f"3. Containment & Remediation Guidance"
    )

    url = f"{config.FREELLMAPI_BASE_URL}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {config.FREELLMAPI_API_KEY}"
    }
    payload = {
        "model": config.FREELLMAPI_MODEL,
        "messages": [
            {"role": "system", "content": "You are a professional Cyber Threat Intelligence and SOAR Copilot."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 450
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=config.FREELLMAPI_TIMEOUT_SEC) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            return {
                "success": True,
                "provider": "FreeLLMAPI",
                "model": config.FREELLMAPI_MODEL,
                "analysis": content.strip()
            }
    except Exception as e:
        # Graceful fallback to deterministic threat intelligence
        fallback_text = generate_fallback_analysis(incident)
        return {
            "success": True,
            "provider": "Deterministic SOC Intelligence (Fallback)",
            "model": "rule-engine-v1",
            "analysis": fallback_text,
            "fallback": True,
            "error_note": f"FreeLLMAPI endpoint ({url}) was unreachable ({str(e)}). Serving deterministic rule intelligence."
        }
