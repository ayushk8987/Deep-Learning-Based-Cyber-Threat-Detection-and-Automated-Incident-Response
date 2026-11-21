import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless execution
import matplotlib.pyplot as plt

import config
from src.data_loader import download_nsl_kdd, load_nsl_kdd
from src.preprocessing import FlowDataPreprocessor
import joblib

os.environ.setdefault("KERAS_HOME", str(config.BASE_DIR / ".keras"))
os.environ.setdefault("MPLCONFIGDIR", str(config.BASE_DIR / ".matplotlib_cache"))
from tensorflow import keras

def generate_evaluation_artifacts():
    """
    Loads saved models, runs comparative evaluation on test data, and generates publication-quality plots.
    """
    preprocessor_path = config.SAVED_MODEL_DIR / "preprocessor.joblib"
    cnn_lstm_path = config.SAVED_MODEL_DIR / "cnn_lstm_ids.keras"
    rf_path = config.SAVED_MODEL_DIR / "baseline_rf.joblib"

    if not preprocessor_path.exists() or not cnn_lstm_path.exists():
        print("Required model or preprocessor artifacts not found. Please train models first.")
        return

    # Load test set
    _, test_path = download_nsl_kdd(use_20_percent=True)
    test_df = load_nsl_kdd(test_path)
    preprocessor = FlowDataPreprocessor.load(preprocessor_path)

    X_test, y_test = preprocessor.transform(test_df, target_col="label")
    X_test_dl = np.expand_dims(X_test, axis=-1)

    # 1. Deep Learning Predictions
    model_dl = keras.models.load_model(str(cnn_lstm_path))
    probs_dl = model_dl.predict(X_test_dl, verbose=0)
    preds_dl = np.argmax(probs_dl, axis=-1)

    # 2. Confusion Matrix Plot
    from sklearn.metrics import confusion_matrix
    cm = confusion_matrix(y_test, preds_dl)
    classes = list(config.ATTACK_CATEGORIES.keys())

    plt.figure(figsize=(7, 6))
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("Confusion Matrix - Hybrid CNN-LSTM Architecture", fontsize=13, fontweight="bold")
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    # Normalize values for text annotation
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], "d"),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > thresh else "black")

    plt.ylabel("True Label", fontweight="bold")
    plt.xlabel("Predicted Label", fontweight="bold")
    plt.tight_layout()

    cm_path = config.PLOTS_DIR / "confusion_matrix.png"
    plt.savefig(cm_path, dpi=200)
    plt.close()
    print(f"Saved confusion matrix plot to {cm_path}")

    # 3. Training Curves (if history available)
    eval_json_path = config.EVALUATION_DIR / "cnn_lstm_metrics.json"
    if eval_json_path.exists():
        with open(eval_json_path, "r") as f:
            eval_data = json.load(f)
        hist = eval_data.get("training_history", {})
        if "loss" in hist and "val_loss" in hist:
            plt.figure(figsize=(10, 4.5))
            
            # Loss curve
            plt.subplot(1, 2, 1)
            plt.plot(hist["loss"], label="Training Loss", color="#1f77b4", linewidth=2)
            plt.plot(hist["val_loss"], label="Validation Loss", color="#ff7f0e", linestyle="--", linewidth=2)
            plt.title("Model Convergence: Loss Curves", fontweight="bold")
            plt.xlabel("Epoch")
            plt.ylabel("Cross-Entropy Loss")
            plt.legend()
            plt.grid(True, alpha=0.3)

            # Accuracy curve
            plt.subplot(1, 2, 2)
            plt.plot(hist.get("accuracy", []), label="Training Accuracy", color="#2ca02c", linewidth=2)
            plt.plot(hist.get("val_accuracy", []), label="Validation Accuracy", color="#d62728", linestyle="--", linewidth=2)
            plt.title("Model Convergence: Accuracy Curves", fontweight="bold")
            plt.xlabel("Epoch")
            plt.ylabel("Accuracy")
            plt.legend()
            plt.grid(True, alpha=0.3)

            plt.tight_layout()
            curves_path = config.PLOTS_DIR / "training_curves.png"
            plt.savefig(curves_path, dpi=200)
            plt.close()
            print(f"Saved training curves plot to {curves_path}")

    # 4. Comparative Model Summary
    comparison = {
        "models": {
            "Hybrid_CNN_LSTM_Attention": {
                "type": "Deep Learning (CNN + BiLSTM + Attention)",
                "test_accuracy": float(np.mean(preds_dl == y_test)),
                "classes": classes
            }
        }
    }
    if rf_path.exists():
        rf_model = joblib.load(rf_path)
        preds_rf = rf_model.predict(X_test)
        comparison["models"]["Random_Forest_Baseline"] = {
            "type": "Classical Machine Learning",
            "test_accuracy": float(np.mean(preds_rf == y_test)),
            "classes": classes
        }

    comp_path = config.EVALUATION_DIR / "model_comparison.json"
    with open(comp_path, "w") as f:
        json.dump(comparison, f, indent=2)
    print(f"Saved model comparison to {comp_path}")

if __name__ == "__main__":
    generate_evaluation_artifacts()
