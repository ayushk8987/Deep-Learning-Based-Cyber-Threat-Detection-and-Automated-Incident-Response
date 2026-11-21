import time
import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, classification_report
import joblib

import config
from src.data_loader import download_nsl_kdd, load_nsl_kdd
from src.preprocessing import FlowDataPreprocessor
from src.database import get_db_connection, log_audit

def train_baseline_model(
    train_path: Optional[Path] = None,
    test_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Trains a classical Random Forest baseline classifier on benchmark flow data.
    Evaluates independently on held-out test data.
    """
    if train_path is None or test_path is None:
        train_path, test_path = download_nsl_kdd(use_20_percent=True)

    print(f"Loading training data from {train_path}...")
    train_df = load_nsl_kdd(train_path)
    print(f"Loading test data from {test_path}...")
    test_df = load_nsl_kdd(test_path)

    # Preprocessing
    print("Fitting preprocessor pipeline on training data solely...")
    preprocessor = FlowDataPreprocessor()
    preprocessor.fit(train_df, target_col="label")
    
    preprocessor_path = config.SAVED_MODEL_DIR / "preprocessor.joblib"
    preprocessor.save(preprocessor_path)

    X_train, y_train = preprocessor.transform(train_df, target_col="label")
    X_test, y_test = preprocessor.transform(test_df, target_col="label")

    print(f"Preprocessed features shape: Train {X_train.shape}, Test {X_test.shape}")

    # Model definition
    print("Training Random Forest baseline classifier...")
    start_train = time.time()
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    train_duration = round(time.time() - start_train, 2)
    print(f"Random Forest trained in {train_duration} seconds.")

    # Latency benchmark
    sample_sub = X_test[:100]
    start_inf = time.time()
    _ = rf.predict(sample_sub)
    inf_latency = round(((time.time() - start_inf) / 100) * 1000, 3)

    # Independent Evaluation
    y_pred = rf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    report = classification_report(
        y_test, y_pred,
        target_names=list(config.ATTACK_CATEGORIES.keys()),
        output_dict=True,
        zero_division=0
    )

    print(f"Random Forest Results -> Accuracy: {acc:.4f}, Macro-F1: {macro_f1:.4f}, Weighted-F1: {weighted_f1:.4f}")

    # Save artifacts
    model_path = config.SAVED_MODEL_DIR / "baseline_rf.joblib"
    joblib.dump(rf, model_path)

    metrics = {
        "model_name": "Random_Forest_Baseline",
        "model_type": "Classical_ML",
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "training_time_sec": train_duration,
        "inference_latency_ms": inf_latency,
        "classification_report": report
    }

    # Record in database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO model_metadata 
        (model_name, model_type, architecture, accuracy, macro_f1, weighted_f1, 
         training_time_sec, inference_latency_ms, model_path, preprocessor_path, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (
        "Random_Forest_Baseline",
        "Classical_ML",
        "RandomForest(n_estimators=100, max_depth=20, class_weight='balanced')",
        acc, macro_f1, weighted_f1, train_duration, inf_latency,
        str(model_path), str(preprocessor_path), 0
    ))
    conn.commit()
    conn.close()

    log_audit("MODEL_TRAINED", f"Trained Random Forest Baseline: Acc={acc:.4f}, F1={macro_f1:.4f}")
    return metrics

if __name__ == "__main__":
    train_baseline_model()
