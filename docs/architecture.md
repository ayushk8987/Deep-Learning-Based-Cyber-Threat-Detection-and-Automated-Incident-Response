# System Architecture Document

## 1. System Overview
The **Deep Learning-Based Cyber Threat Detection and Automated Incident Response (SOAR)** prototype is an end-to-end cybersecurity system designed to identify network intrusions from structured flow records, evaluate threat severity, and simulate defensive containment actions within an explainable, human-in-the-loop framework.

The system is deployed locally on `127.0.0.1:5050` and operates in **SIMULATION ONLY** mode by default to ensure zero unauthorized modifications to host firewall tables, routes, or network interfaces.

```
========================================================================================
                                SYSTEM PIPELINE ARCHITECTURE
========================================================================================

 [ Network Traffic Flow CSV ] (NSL-KDD / CICIDS2017 Standard)
              │
              ▼
 ┌─────────────────────────────────────────────────────────┐
 │               Data Validation & Ingestion               │
 │  - Schema Detection & Leakage Column Stripping          │
 │  - Infinite / Missing Value Imputation                  │
 └─────────────────────────────────────────────────────────┘
              │
              ▼
 ┌─────────────────────────────────────────────────────────┐
 │          FlowDataPreprocessor (Pipeline Guard)          │
 │  - StandardScaler for Numerical Flow Metrics            │
 │  - OneHotEncoder for Categorical Protocols/Flags        │
 │  - Fitted strictly on Training Split (Leakage Defense)  │
 └─────────────────────────────────────────────────────────┘
              │ Transformed Features (118-D)
              ▼
 ┌─────────────────────────────────────────────────────────┐
 │           Inference & Detection Engine                  │
 │  - Hybrid 1D-CNN: Spatial Flow Feature Combinations     │
 │  - Bidirectional LSTM: Temporal Sequence Dynamics       │
 │  - Multi-Head Attention: Anomalous Feature Gating       │
 │  - Softmax Multiclass: Benign, DoS, Probe, R2L, U2R     │
 └─────────────────────────────────────────────────────────┘
              │ Predicted Category + Confidence P(y|x)
              ▼
 ┌─────────────────────────────────────────────────────────┐
 │                Severity Scoring Engine                  │
 │  - Calculates Impact: Informational, Low, Med, High, Crit│
 │  - Contextual Risk Factors (Packet counts, login trials)│
 └─────────────────────────────────────────────────────────┘
              │
              ▼
 ┌─────────────────────────────────────────────────────────┐
 │         Rule-Based Incident Response (SOAR)             │
 │  - High/Critical Actions -> PENDING_APPROVAL            │
 │  - Low/Info Actions     -> AUTO_SIMULATED               │
 │  - Simulation Isolation: Emits safe iptables mock rule   │
 └─────────────────────────────────────────────────────────┘
              │
       ┌──────┴─────────────────────────────────────────────┐
       ▼                                                    ▼
┌───────────────────────────┐                 ┌───────────────────────────┐
│ SQLite Database           │                 │ Flask SOC Web Dashboard   │
│ - detection_events        │◀────────────────│ - Live Operations View    │
│ - incident_records        │                 │ - Traffic Analysis Page   │
│ - simulated_actions       │                 │ - Human Analyst Review    │
│ - audit_logs              │                 │ - Model Evaluation Report │
└───────────────────────────┘                 └───────────────────────────┘
========================================================================================
```

## 2. Subsystem Breakdown

### 2.1 Ingestion & Preprocessing Subsystem
- **Module:** `src/data_loader.py`, `src/data_validation.py`, `src/preprocessing.py`
- **Function:** Ingests raw tabular network records, strips metadata/leakage identifiers (e.g. `difficulty_level`), applies fitted `StandardScaler` to continuous metrics and `OneHotEncoder` to discrete attributes (`protocol_type`, `service`, `flag`).
- **Data Integrity:** Guarantees that testing and inference use the exact transformation parameters fitted on the training split.

### 2.2 Deep Learning Detection Engine
- **Module:** `src/train_deep_learning.py`, `src/predict.py`
- **Model:** `Hybrid_CNN_LSTM_Attention_IDS`
- **Layers:**
  1. `Input`: Shape `(118, 1)`
  2. `Conv1D(filters=64, kernel_size=3)` + `BatchNorm` + `MaxPool1D(2)`
  3. `Conv1D(filters=128, kernel_size=3)` + `BatchNorm` + `Dropout(0.3)`
  4. `Bidirectional(LSTM(64, return_sequences=True))`
  5. `MultiHeadAttention(num_heads=4, key_dim=32)` + Residual Connection + `LayerNorm`
  6. `GlobalAveragePooling1D`
  7. `Dense(64, relu)` + `Dropout(0.3)`
  8. `Dense(5, softmax)`
- **Output:** Categorical probability distribution across canonical classes: `Benign`, `DoS`, `Probe`, `R2L`, `U2R`.

### 2.3 Threat Severity Engine
- **Module:** `src/severity_engine.py`
- **Function:** Assigns an explainable severity rating (`Informational`, `Low`, `Medium`, `High`, `Critical`) combining the model's confidence with operational risk parameters (burst packet counts, failed login attempts).

### 2.4 SOAR Policy & Simulation Subsystem
- **Module:** `src/response_engine.py`
- **Function:** Evaluates policy lookup tables to determine response actions:
  - `LOG_TELEMETRY`
  - `RATE_LIMIT_AND_LOG`
  - `SIMULATED_IP_BLOCK`
  - `SIMULATED_SESSION_TERMINATE`
  - `SIMULATED_HOST_ISOLATION`
- **Human-in-the-Loop:** High-impact actions are held in `PENDING_APPROVAL` status until an analyst explicitly approves via the interactive modal.

### 2.5 Persistence & Reporting Subsystem
- **Module:** `src/database.py`, `src/reporting.py`
- **Storage:** SQLite3 (`data/cyber_soc.db`)
- **Reporting:** Exports CSV reports and academic summaries for faculty review.
