import pandas as pd
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
import config

TARGET_COLUMN_CANDIDATES = ["label", "Label", "attack_type", "class", "target", "attack"]
LEAKAGE_COLUMNS = ["difficulty_level", "Flow ID", "Source IP", "Destination IP", "Timestamp", "Unnamed: 0"]

def detect_target_column(df: pd.DataFrame) -> Optional[str]:
    """Identifies the target label column from candidate naming conventions."""
    for col in TARGET_COLUMN_CANDIDATES:
        if col in df.columns:
            return col
    # Check case-insensitive match
    lower_map = {c.lower(): c for c in df.columns}
    for cand in TARGET_COLUMN_CANDIDATES:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None

def validate_dataset_schema(df: pd.DataFrame, is_training: bool = True) -> Dict[str, Any]:
    """
    Performs comprehensive data inspection, schema validation, missing/duplicate checks,
    and class distribution analysis.
    """
    total_rows = len(df)
    total_cols = len(df.columns)
    
    # Missing values check
    missing_counts = df.isnull().sum()
    total_missing = int(missing_counts.sum())
    missing_details = missing_counts[missing_counts > 0].to_dict()

    # Infinite values check for numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    inf_counts = np.isinf(df[numeric_cols]).sum() if len(numeric_cols) > 0 else pd.Series(dtype=int)
    total_inf = int(inf_counts.sum())

    # Duplicate rows check
    duplicate_rows = int(df.duplicated().sum())

    # Target column analysis
    target_col = detect_target_column(df)
    class_distribution = {}
    is_valid = True
    error_messages = []

    if is_training:
        if not target_col:
            is_valid = False
            error_messages.append("No valid target label column found. Expected one of: " + ", ".join(TARGET_COLUMN_CANDIDATES))
        else:
            raw_dist = df[target_col].value_counts().to_dict()
            class_distribution = {str(k): int(v) for k, v in raw_dist.items()}
            if len(class_distribution) < 2:
                is_valid = False
                error_messages.append(f"Insufficient distinct classes in target column '{target_col}'. Found: {len(class_distribution)}")

    # Check for identifiable leakage columns
    present_leakage = [col for col in LEAKAGE_COLUMNS if col in df.columns]

    return {
        "is_valid": is_valid,
        "errors": error_messages,
        "total_rows": total_rows,
        "total_columns": total_cols,
        "target_column": target_col,
        "total_missing_values": total_missing,
        "missing_by_column": missing_details,
        "total_infinite_values": total_inf,
        "duplicate_rows": duplicate_rows,
        "identified_leakage_columns": present_leakage,
        "class_distribution": class_distribution,
        "column_names": list(df.columns)
    }

def clean_and_sanitize_dataframe(df: pd.DataFrame, drop_leakage: bool = True) -> pd.DataFrame:
    """
    Cleans infinite and NaN values, removes trailing whitespace from column names and string cells,
    and removes identified non-feature leakage columns.
    """
    cleaned_df = df.copy()

    # Strip column names
    cleaned_df.columns = [c.strip() for c in cleaned_df.columns]

    # Drop leakage columns if present
    if drop_leakage:
        for leak in LEAKAGE_COLUMNS:
            if leak in cleaned_df.columns:
                cleaned_df.drop(columns=[leak], inplace=True)

    # Clean infinite numbers by replacing with NaN then median/zero
    num_cols = cleaned_df.select_dtypes(include=[np.number]).columns
    cleaned_df[num_cols] = cleaned_df[num_cols].replace([np.inf, -np.inf], np.nan)
    cleaned_df[num_cols] = cleaned_df[num_cols].fillna(0)

    # Clean strings
    obj_cols = cleaned_df.select_dtypes(include=["object", "string"]).columns
    for oc in obj_cols:
        cleaned_df[oc] = cleaned_df[oc].astype(str).str.strip()

    return cleaned_df
