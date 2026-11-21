import os
import json
from pathlib import Path
from typing import Dict, Any, List, Union, Optional
import numpy as np
import pandas as pd
import joblib

import config
from src.preprocessing import FlowDataPreprocessor
from src.severity_engine import calculate_threat_severity
from src.response_engine import generate_response_recommendation

os.environ.setdefault("KERAS_HOME", str(config.BASE_DIR / ".keras"))
os.environ.setdefault("MPLCONFIGDIR", str(config.BASE_DIR / ".matplotlib_cache"))
from tensorflow import keras

class ThreatPredictionPipeline:
    """
    Manages model loading, feature transformation, inference execution,
    severity evaluation, and incident response dispatch.
    """
    def __init__(self):
        self.preprocessor: Optional[FlowDataPreprocessor] = None
        self.dl_model = None
        self.rf_model = None
        self.active_model_type = "NONE"
        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads fitted preprocessor and best available trained model."""
        preprocessor_path = config.SAVED_MODEL_DIR / "preprocessor.joblib"
        if preprocessor_path.exists():
            self.preprocessor = FlowDataPreprocessor.load(preprocessor_path)

        dl_path = config.SAVED_MODEL_DIR / "cnn_lstm_ids.keras"
        if dl_path.exists():
            try:
                self.dl_model = keras.models.load_model(str(dl_path))
                self.active_model_type = "DEEP_LEARNING_CNN_LSTM"
                print(f"Loaded active Deep Learning model from {dl_path}")
                return
            except Exception as e:
                print(f"Warning: Failed to load DL model: {e}")

        rf_path = config.SAVED_MODEL_DIR / "baseline_rf.joblib"
        if rf_path.exists():
            try:
                self.rf_model = joblib.load(rf_path)
                self.active_model_type = "BASELINE_RANDOM_FOREST"
                print(f"Loaded baseline model from {rf_path}")
            except Exception as e:
                print(f"Warning: Failed to load baseline model: {e}")

    def is_ready(self) -> bool:
        """Checks if a model and preprocessor are loaded and available for inference."""
        return self.preprocessor is not None and (self.dl_model is not None or self.rf_model is not None)

    def predict_batch(
        self,
        df: pd.DataFrame,
        save_incidents: bool = True,
        max_records: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Executes batch inference on network flow records.
        """
        if not self.is_ready():
            raise RuntimeError("Inference pipeline not initialized. Ensure models are trained and saved.")

        # Limit batch size to prevent browser/server lockup
        records_df = df.head(max_records).copy()
        
        # Transform features
        X_trans, _ = self.preprocessor.transform(records_df)

        # Inference
        if self.active_model_type == "DEEP_LEARNING_CNN_LSTM":
            X_dl = np.expand_dims(X_trans, axis=-1)
            probabilities = self.dl_model.predict(X_dl, verbose=0)
            pred_indices = np.argmax(probabilities, axis=-1)
            confidences = np.max(probabilities, axis=-1)
        else:
            # Baseline Random Forest
            probabilities = self.rf_model.predict_proba(X_trans)
            pred_indices = np.argmax(probabilities, axis=-1)
            confidences = np.max(probabilities, axis=-1)

        results = []
        for i in range(len(records_df)):
            idx = int(pred_indices[i])
            threat_name = config.INV_ATTACK_CATEGORIES.get(idx, "Benign")
            conf = float(confidences[i])
            row_dict = records_df.iloc[i].to_dict()

            # Synthetic IP assignment if missing in tabular flow datasets
            src_ip = str(row_dict.get("Source IP", f"192.168.1.{10 + (i % 80)}"))
            dst_ip = str(row_dict.get("Destination IP", "10.0.0.1"))
            proto = str(row_dict.get("protocol_type", "tcp"))
            srv = str(row_dict.get("service", "http"))

            # Calculate Severity
            sev, rationale = calculate_threat_severity(
                threat_category=threat_name,
                confidence=conf,
                flow_features=row_dict
            )

            # Generate Response Recommendation
            resp = generate_response_recommendation(
                threat_category=threat_name,
                severity=sev,
                confidence=conf,
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto,
                service=srv,
                raw_features=row_dict,
                auto_save=save_incidents
            )

            result_entry = {
                "record_index": i,
                "threat_category": threat_name,
                "confidence": round(conf, 4),
                "severity": sev,
                "severity_rationale": rationale,
                "recommended_action": resp["recommended_action"],
                "action_status": resp["action_status"],
                "incident_id": resp["incident_id"],
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": proto,
                "service": srv,
                "probabilities": {
                    config.INV_ATTACK_CATEGORIES[c_idx]: round(float(probabilities[i][c_idx]), 4)
                    for c_idx in range(len(config.ATTACK_CATEGORIES))
                }
            }
            results.append(result_entry)

        return results
