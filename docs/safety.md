# Safety, Ethics & Safeguards Document

## 1. Safety Philosophy & Threat Model
In automated cybersecurity operations, the implementation of automated incident response carries inherent operational hazards. An autonomous intrusion response system that acts on statistical predictions without verification can cause **self-inflicted Denial-of-Service (DoS)** by erroneously quarantining legitimate business servers, blocking authentic customer IP subnets, or terminating operational database connections.

To eliminate these risks in an undergraduate research and academic environment, this project enforces the following mandatory safeguards:

---

## 2. Mandatory Technical Safeguards

### 2.1 Default Simulation Mode
- **Policy:** The application defaults unconditionally to `SIMULATION_ONLY`.
- **Enforcement:** The system **never** executes system commands (`iptables`, `ufw`, `netsh`, `ip route`) or modifies operating system configuration files.
- **Audit Verification:** All response actions generate structured mock payloads (e.g. `# [SIMULATION ONLY] iptables -A INPUT -s 192.168.1.105 -j DROP`) stored within the local SQLite audit log rather than kernel packet filters.

### 2.2 Human-in-the-Loop (HITL) Authorization Gate
- **Low-Impact Actions:** Low-severity events (`LOG_TELEMETRY`, `RATE_LIMIT_AND_LOG`) are automatically simulated and recorded to prevent analyst alert fatigue.
- **High-Impact Actions:** Destructive or disruptive responses (`SIMULATED_IP_BLOCK`, `SIMULATED_SESSION_TERMINATE`, `SIMULATED_HOST_ISOLATION`) are permanently gated behind human approval.
- **Status State Machine:**
  ```
  [ Detection Event ] ──▶ [ Severity Assessment ]
                                 │
                ┌────────────────┴────────────────┐
                ▼ (Low / Info)                    ▼ (High / Critical)
       [ SIMULATED_EXECUTED ]            [ PENDING_APPROVAL ]
                                                  │
                                                  ▼
                                      [ Human Analyst Review ]
                                                  │
                                 ┌────────────────┴────────────────┐
                                 ▼ (Approved)                      ▼ (Rejected)
                        [ SIMULATED_EXECUTED ]            [ ANALYST_REJECTED ]
  ```

### 2.3 Localhost-Bound Network Exposure
- The Flask development server is configured by default to bind solely to loopback interface `127.0.0.1:5050`. It is never exposed to public internet interfaces without reverse-proxy authentication.

---

## 3. Residual Research Limitations & Ethical Considerations

1. **Adversarial Perturbations:** Deep learning neural networks are susceptible to adversarial evasion attacks (e.g. Fast Gradient Sign Method, feature manipulation) where subtle, non-functional adjustments to packet timings or lengths bypass classification. The prototype notes this limitation for Phase-II future work.
2. **Distribution Shift & Concept Drift:** Network environments evolve rapidly. A model trained on historic datasets (NSL-KDD or CICIDS2017) may exhibit degraded performance against novel zero-day attack vectors not present in the training distribution. Continuous retraining and baseline drift monitoring are required for live deployment.
3. **Defense-in-Depth Principle:** The prototype is designed as an advisory decision-support system to assist security analysts, not as a replacement for human judgment or perimeter defenses.
