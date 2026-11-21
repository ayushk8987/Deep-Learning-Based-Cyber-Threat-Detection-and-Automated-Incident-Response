import os
import time
import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight

import config

# Set environment before loading tensorflow/keras
os.environ.setdefault("KERAS_HOME", str(config.BASE_DIR / ".keras"))
os.environ.setdefault("MPLCONFIGDIR", str(config.BASE_DIR / ".matplotlib_cache"))

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, callbacks

from src.data_loader import download_nsl_kdd, load_nsl_kdd
from src.preprocessing import FlowDataPreprocessor
from src.database import get_db_connection, log_audit

def build_hybrid_cnn_lstm_attention_model(
    input_dim: int,
    num_classes: int = 5
) -> keras.Model:
    """
    Constructs a hybrid 1D-CNN + Bidirectional-LSTM + Multi-Head Attention architecture.
    
    1. Conv1D: Extracts localized spatial associations across contiguous flow features.
    2. MaxPool: Reduces dimensionality and preserves dominant feature activations.
    3. BiLSTM: Models bidirectional temporal/sequential dependencies across feature channels.
    4. MultiHeadAttention: Weighs critical anomalous feature states dynamically.
    5. Dense Softmax Head: Maps high-level representations to multiclass threat probabilities.
    """
    inputs = layers.Input(shape=(input_dim, 1), name="flow_feature_input")

    # Convolutional Feature Extraction Block
    x = layers.Conv1D(filters=64, kernel_size=3, padding="same", activation="relu", name="conv1d_layer1")(inputs)
    x = layers.BatchNormalization(name="bn_conv1")(x)
    x = layers.MaxPooling1D(pool_size=2, name="maxpool1")(x)

    x = layers.Conv1D(filters=128, kernel_size=3, padding="same", activation="relu", name="conv1d_layer2")(x)
    x = layers.BatchNormalization(name="bn_conv2")(x)
    x = layers.Dropout(0.3, name="conv_dropout")(x)

    # Recurrent Temporal Sequence Modeling
    lstm_out = layers.Bidirectional(
        layers.LSTM(64, return_sequences=True),
        name="bilstm_temporal_layer"
    )(x)

    # Multi-Head Attention Mechanism
    attn_out = layers.MultiHeadAttention(
        num_heads=4, key_dim=32, name="self_attention_mechanism"
    )(lstm_out, lstm_out)
    
    # Residual Add & Layer Normalization
    x = layers.Add(name="residual_attn_add")([lstm_out, attn_out])
    x = layers.LayerNormalization(name="ln_attn")(x)

    # Global Representation Pooling
    x = layers.GlobalAveragePooling1D(name="global_avg_pool")(x)

    # Fully-Connected Classification Head
    x = layers.Dense(64, activation="relu", name="dense_latent")(x)
    x = layers.Dropout(0.3, name="dense_dropout")(x)
    outputs = layers.Dense(num_classes, activation="softmax", name="threat_classification_head")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="Hybrid_CNN_LSTM_Attention_IDS")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model

def train_cnn_lstm_model(
    train_path: Optional[Path] = None,
    test_path: Optional[Path] = None,
    epochs: int = 10,
    batch_size: int = 128
) -> Dict[str, Any]:
    """
    Orchestrates end-to-end training and evaluation of the hybrid CNN-LSTM model.
    """
    if train_path is None or test_path is None:
        train_path, test_path = download_nsl_kdd(use_20_percent=True)

    print(f"Loading training data from {train_path}...")
    train_df = load_nsl_kdd(train_path)
    print(f"Loading test data from {test_path}...")
    test_df = load_nsl_kdd(test_path)

    # Preprocessing
    preprocessor_path = config.SAVED_MODEL_DIR / "preprocessor.joblib"
    if preprocessor_path.exists():
        preprocessor = FlowDataPreprocessor.load(preprocessor_path)
    else:
        preprocessor = FlowDataPreprocessor()
        preprocessor.fit(train_df, target_col="label")
        preprocessor.save(preprocessor_path)

    X_train, y_train = preprocessor.transform(train_df, target_col="label")
    X_test, y_test = preprocessor.transform(test_df, target_col="label")

    # Reshape input to (batch, features, 1) for Conv1D / LSTM
    X_train_dl = np.expand_dims(X_train, axis=-1)
    X_test_dl = np.expand_dims(X_test, axis=-1)

    input_dim = X_train_dl.shape[1]
    num_classes = len(config.ATTACK_CATEGORIES)

    print(f"DL Input shape: {X_train_dl.shape}, Output classes: {num_classes}")

    # Compute balanced class weights for training data
    unique_classes = np.unique(y_train)
    weights = compute_class_weight(class_weight="balanced", classes=unique_classes, y=y_train)
    class_weight_dict = {int(c): float(w) for c, w in zip(unique_classes, weights)}
    print(f"Calculated class weights: {class_weight_dict}")

    model = build_hybrid_cnn_lstm_attention_model(input_dim=input_dim, num_classes=num_classes)
    model.summary()

    # Callbacks
    model_save_path = config.SAVED_MODEL_DIR / "cnn_lstm_ids.keras"
    cb_list = [
        callbacks.EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True, verbose=1),
        callbacks.ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=2, min_lr=1e-5, verbose=1),
        callbacks.ModelCheckpoint(filepath=str(model_save_path), monitor="val_loss", save_best_only=True, verbose=1)
    ]

    print("Beginning Deep Learning model training...")
    start_train = time.time()
    history = model.fit(
        X_train_dl, y_train,
        validation_split=0.15,
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weight_dict,
        callbacks=cb_list,
        verbose=1
    )
    train_duration = round(time.time() - start_train, 2)
    print(f"CNN-LSTM model training completed in {train_duration} seconds.")

    # Latency benchmark
    sample_sub = X_test_dl[:100]
    start_inf = time.time()
    _ = model.predict(sample_sub, verbose=0)
    inf_latency = round(((time.time() - start_inf) / 100) * 1000, 3)

    # Independent Evaluation on Test Set
    print("Evaluating model on independent held-out test data...")
    test_probs = model.predict(X_test_dl, verbose=0)
    y_pred = np.argmax(test_probs, axis=-1)

    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    conf_mat = confusion_matrix(y_test, y_pred).tolist()

    report = classification_report(
        y_test, y_pred,
        target_names=list(config.ATTACK_CATEGORIES.keys()),
        output_dict=True,
        zero_division=0
    )

    print(f"Deep Learning Model Results -> Accuracy: {acc:.4f}, Macro-F1: {macro_f1:.4f}, Weighted-F1: {weighted_f1:.4f}")

    # Serialize evaluation results and training curves
    hist_dict = {k: [float(val) for val in v] for k, v in history.history.items()}
    eval_payload = {
        "model_name": "Hybrid_CNN_LSTM_Attention",
        "model_type": "Deep_Learning",
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "training_time_sec": train_duration,
        "inference_latency_ms": inf_latency,
        "confusion_matrix": conf_mat,
        "classification_report": report,
        "training_history": hist_dict
    }

    eval_json_path = config.EVALUATION_DIR / "cnn_lstm_metrics.json"
    with open(eval_json_path, "w") as f:
        json.dump(eval_payload, f, indent=2)

    # Register in SQLite database
    conn = get_db_connection()
    cursor = conn.cursor()
    # Mark previously active models as inactive
    cursor.execute("UPDATE model_metadata SET is_active = 0")
    cursor.execute("""
        INSERT OR REPLACE INTO model_metadata 
        (model_name, model_type, architecture, accuracy, macro_f1, weighted_f1, 
         training_time_sec, inference_latency_ms, model_path, preprocessor_path, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    """, (
        "Hybrid_CNN_LSTM_Attention",
        "Deep_Learning",
        "Conv1D(64,3) + Conv1D(128,3) + BiLSTM(64) + MultiHeadAttention(4) + Dense(64)",
        acc, macro_f1, weighted_f1, train_duration, inf_latency,
        str(model_save_path), str(preprocessor_path), 1
    ))
    conn.commit()
    conn.close()

    log_audit("MODEL_TRAINED", f"Trained CNN-LSTM: Acc={acc:.4f}, F1={macro_f1:.4f}, Latency={inf_latency}ms")
    return eval_payload

if __name__ == "__main__":
    train_cnn_lstm_model()
