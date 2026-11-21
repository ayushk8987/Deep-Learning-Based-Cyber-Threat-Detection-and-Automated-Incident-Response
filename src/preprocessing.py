import json
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
import joblib

import config
from src.data_validation import clean_and_sanitize_dataframe, detect_target_column

def map_to_canonical_category(raw_label: str) -> str:
    """Maps granular attack strings from NSL-KDD or CICIDS to canonical 5-class names."""
    clean = str(raw_label).strip().lower()
    
    # Check NSL-KDD mapping
    if clean in config.NSL_KDD_ATTACK_MAP:
        return config.NSL_KDD_ATTACK_MAP[clean]
    
    # Check CICIDS mapping
    for k, v in config.CICIDS_ATTACK_MAP.items():
        if k.lower() == clean:
            return v
    
    # Common keyword matching heuristic
    if "normal" in clean or "benign" in clean:
        return "Benign"
    elif "dos" in clean or "ddos" in clean or "smurf" in clean or "neptune" in clean or "hulk" in clean:
        return "DoS"
    elif "probe" in clean or "scan" in clean or "satan" in clean or "ipsweep" in clean:
        return "Probe"
    elif "u2r" in clean or "buffer_overflow" in clean or "rootkit" in clean or "infiltr" in clean:
        return "U2R"
    elif "r2l" in clean or "guess" in clean or "pass" in clean or "ftp" in clean or "ssh" in clean or "bot" in clean:
        return "R2L"
    
    return "Benign"

class FlowDataPreprocessor:
    """
    Encapsulates fitted feature scalers, categorical encoders, and label maps.
    Prevents data leakage by fitting solely on training splits.
    """
    def __init__(self):
        self.column_transformer: Optional[ColumnTransformer] = None
        self.numerical_cols = []
        self.categorical_cols = []
        self.feature_names_out = []
        self.label_mapping = config.ATTACK_CATEGORIES
        self.inv_label_mapping = config.INV_ATTACK_CATEGORIES

    def fit(self, df: pd.DataFrame, target_col: Optional[str] = None) -> "FlowDataPreprocessor":
        """Identifies column types and fits numerical scalers and categorical encoders."""
        cleaned_df = clean_and_sanitize_dataframe(df, drop_leakage=True)
        
        if target_col is None:
            target_col = detect_target_column(cleaned_df)
        
        feature_df = cleaned_df.drop(columns=[target_col]) if target_col and target_col in cleaned_df.columns else cleaned_df
        
        self.categorical_cols = feature_df.select_dtypes(include=["object", "category", "string"]).columns.tolist()
        self.numerical_cols = feature_df.select_dtypes(include=[np.number]).columns.tolist()

        transformers = []
        if self.numerical_cols:
            transformers.append(("num", StandardScaler(), self.numerical_cols))
        if self.categorical_cols:
            transformers.append(("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), self.categorical_cols))

        self.column_transformer = ColumnTransformer(transformers=transformers, remainder="drop")
        self.column_transformer.fit(feature_df)
        
        # Build output feature names list
        out_names = []
        if self.numerical_cols:
            out_names.extend(self.numerical_cols)
        if self.categorical_cols:
            cat_encoder = self.column_transformer.named_transformers_["cat"]
            encoded_cats = cat_encoder.get_feature_names_out(self.categorical_cols).tolist()
            out_names.extend(encoded_cats)
        self.feature_names_out = out_names

        return self

    def transform(self, df: pd.DataFrame, target_col: Optional[str] = None) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Applies fitted transformations to features and maps labels to integers."""
        if self.column_transformer is None:
            raise RuntimeError("Preprocessor has not been fitted yet! Call fit() before transform().")

        cleaned_df = clean_and_sanitize_dataframe(df, drop_leakage=True)
        
        if target_col is None:
            target_col = detect_target_column(cleaned_df)

        has_target = target_col and target_col in cleaned_df.columns
        feature_df = cleaned_df.drop(columns=[target_col]) if has_target else cleaned_df

        # Ensure all expected columns exist (fill missing with 0 or 'unknown')
        for col in self.numerical_cols:
            if col not in feature_df.columns:
                feature_df[col] = 0.0
        for col in self.categorical_cols:
            if col not in feature_df.columns:
                feature_df[col] = "other"

        X_transformed = self.column_transformer.transform(feature_df)

        y_encoded = None
        if has_target:
            mapped_labels = cleaned_df[target_col].apply(map_to_canonical_category)
            y_encoded = mapped_labels.map(self.label_mapping).fillna(0).astype(int).to_numpy()

        return np.asarray(X_transformed, dtype=np.float32), y_encoded

    def save(self, filepath: Path) -> None:
        """Serializes fitted preprocessor to disk."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, filepath)
        # Also save metadata json
        meta = {
            "numerical_cols": self.numerical_cols,
            "categorical_cols": self.categorical_cols,
            "total_input_features": len(self.feature_names_out),
            "feature_names_out": self.feature_names_out,
            "label_mapping": self.label_mapping
        }
        meta_path = filepath.with_suffix(".json")
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, filepath: Path) -> "FlowDataPreprocessor":
        """Loads fitted preprocessor from disk."""
        if not filepath.exists():
            raise FileNotFoundError(f"Preprocessor artifact not found at: {filepath}")
        return joblib.load(filepath)
