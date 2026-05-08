"""
Credential Stuffing Model Training Pipeline
===========================================

Phase 2 training script for the ACDS Credential Stuffing Detection module.

Expected dataset:
    data/credential_stuffing/rba_dataset.csv

Outputs:
    models/credential_stuffing_model.joblib
    reports/credential_stuffing_model_metrics.json
"""

import json
from pathlib import Path
from typing import Dict, List, Optional

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer


MAX_ROWS = 200_000
WINDOW = "5min"
WINDOW_MINUTES = 5
RANDOM_STATE = 42

FEATURE_COLUMNS = [
    "failed_attempts_from_ip",
    "unique_usernames_from_ip",
    "failed_attempts_for_username",
    "unique_ips_for_username",
    "attempts_per_minute",
    "success_after_failures",
    "user_agent_variation",
    "country_variation",
]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def normalize_column_name(name: str) -> str:
    return "".join(char for char in name.lower() if char.isalnum())


def detect_column(columns: List[str], candidates: List[str]) -> Optional[str]:
    normalized_to_original = {normalize_column_name(column): column for column in columns}
    normalized_candidates = [normalize_column_name(candidate) for candidate in candidates]

    for candidate in normalized_candidates:
        if candidate in normalized_to_original:
            return normalized_to_original[candidate]

    for candidate in normalized_candidates:
        for normalized, original in normalized_to_original.items():
            if candidate in normalized:
                return original

    return None


def detect_dataset_columns(df: pd.DataFrame) -> Dict[str, Optional[str]]:
    columns = list(df.columns)
    return {
        "username": detect_column(columns, [
            "username", "user", "user_id", "userid", "account", "account_id",
            "accountid", "login", "email",
        ]),
        "ip_address": detect_column(columns, [
            "ip_address", "ipaddress", "ip", "source_ip", "sourceip",
            "remote_ip", "remoteip", "client_ip", "clientip", "login_ip",
        ]),
        "timestamp": detect_column(columns, [
            "timestamp", "time", "datetime", "date_time", "event_time",
            "eventtime", "login_time", "logintime", "created_at",
        ]),
        "login_result": detect_column(columns, [
            "success", "succeeded", "login_success", "loginsuccess",
            "is_success", "issuccess", "result", "login_result",
            "loginresult", "status", "login_status", "failure", "failed",
        ]),
        "user_agent": detect_column(columns, [
            "user_agent", "useragent", "browser", "device", "client",
        ]),
        "country": detect_column(columns, [
            "country", "location", "geo", "geolocation", "region",
            "country_code", "countrycode",
        ]),
    }


def fail_missing_columns(mapping: Dict[str, Optional[str]], detected_columns: List[str]) -> None:
    required = ["username", "ip_address", "timestamp", "login_result"]
    missing = [name for name in required if mapping.get(name) is None]
    if not missing:
        return

    explanation = [
        "Required dataset columns are missing.",
        f"Missing logical fields: {', '.join(missing)}",
        "Required logical fields: username/user/account, IP address, timestamp, login result/success/failure.",
        f"Detected columns: {detected_columns}",
    ]
    raise ValueError("\n".join(explanation))


def parse_success(value) -> bool:
    if pd.isna(value):
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1

    text = str(value).strip().lower()
    success_values = {"success", "succeeded", "successful", "true", "yes", "y", "1", "ok", "allow", "allowed"}
    failure_values = {"failure", "failed", "fail", "false", "no", "n", "0", "denied", "blocked", "invalid"}

    if text in success_values:
        return True
    if text in failure_values:
        return False

    return "success" in text and "fail" not in text


def prepare_base_frame(df: pd.DataFrame, mapping: Dict[str, Optional[str]]) -> pd.DataFrame:
    prepared = pd.DataFrame({
        "username": df[mapping["username"]].astype(str).str.strip().str.lower(),
        "ip_address": df[mapping["ip_address"]].astype(str).str.strip(),
        "timestamp": pd.to_datetime(df[mapping["timestamp"]], errors="coerce", utc=True),
        "success": df[mapping["login_result"]].map(parse_success),
    })

    prepared["user_agent"] = (
        df[mapping["user_agent"]].astype(str).str.strip()
        if mapping.get("user_agent")
        else "unknown"
    )
    prepared["country"] = (
        df[mapping["country"]].astype(str).str.strip()
        if mapping.get("country")
        else "unknown"
    )

    before_drop = len(prepared)
    prepared = prepared.dropna(subset=["timestamp"])
    prepared = prepared[
        (prepared["username"] != "")
        & (prepared["username"] != "nan")
        & (prepared["ip_address"] != "")
        & (prepared["ip_address"] != "nan")
    ]
    dropped = before_drop - len(prepared)
    if dropped:
        print(f"Dropped {dropped} rows with invalid required values.")

    if prepared.empty:
        raise ValueError("No usable rows remain after parsing required fields.")

    prepared["failed"] = (~prepared["success"]).astype(int)
    prepared["attempt"] = 1
    return prepared.sort_values("timestamp").reset_index(drop=True)


def rolling_sum_by_group(df: pd.DataFrame, group_col: str, value_col: str) -> pd.Series:
    result = pd.Series(0.0, index=df.index)
    for _, group in df.groupby(group_col, sort=False):
        rolled = group.set_index("timestamp")[value_col].rolling(WINDOW).sum()
        result.loc[group.index] = rolled.to_numpy()
    return result


def rolling_nunique_by_group(df: pd.DataFrame, group_col: str, value_col: str) -> pd.Series:
    result = pd.Series(0.0, index=df.index)
    for _, group in df.groupby(group_col, sort=False):
        rolled = (
            group.set_index("timestamp")[value_col]
            .rolling(WINDOW)
            .apply(lambda values: len(set(values)), raw=False)
        )
        result.loc[group.index] = rolled.to_numpy()
    return result


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    featured = df.copy()

    # Numeric codes make rolling distinct counts stable and faster than strings.
    featured["username_code"] = pd.factorize(featured["username"])[0]
    featured["ip_code"] = pd.factorize(featured["ip_address"])[0]
    featured["user_agent_code"] = pd.factorize(featured["user_agent"])[0]
    featured["country_code"] = pd.factorize(featured["country"])[0]

    featured["failed_attempts_from_ip"] = rolling_sum_by_group(featured, "ip_address", "failed")
    featured["unique_usernames_from_ip"] = rolling_nunique_by_group(featured, "ip_address", "username_code")
    featured["failed_attempts_for_username"] = rolling_sum_by_group(featured, "username", "failed")
    featured["unique_ips_for_username"] = rolling_nunique_by_group(
        featured[featured["failed"] == 1], "username", "ip_code"
    ).reindex(featured.index, fill_value=0)
    attempts_from_ip = rolling_sum_by_group(featured, "ip_address", "attempt")
    featured["attempts_per_minute"] = attempts_from_ip / WINDOW_MINUTES
    featured["user_agent_variation"] = rolling_nunique_by_group(featured, "ip_address", "user_agent_code")
    featured["country_variation"] = rolling_nunique_by_group(featured, "ip_address", "country_code")
    featured["success_after_failures"] = (
        featured["success"] & (featured["failed_attempts_from_ip"] >= 5)
    ).astype(int)

    return featured


def generate_weak_labels(df: pd.DataFrame) -> pd.Series:
    labels = (
        (df["failed_attempts_from_ip"] >= 10)
        | (df["unique_usernames_from_ip"] >= 5)
        | (df["unique_ips_for_username"] >= 3)
        | (df["attempts_per_minute"] >= 10)
        | (df["success_after_failures"] == 1)
    )
    return labels.astype(int)


def build_behavioral_logistic_regression() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        (
            "classifier",
            LogisticRegression(
                class_weight="balanced",
                max_iter=2_000,
                random_state=RANDOM_STATE,
            ),
        ),
    ])


def build_behavioral_random_forest() -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )


def user_agent_has_signal(df: pd.DataFrame) -> bool:
    cleaned = df["user_agent"].fillna("unknown").astype(str).str.strip().str.lower()
    useful_values = cleaned[~cleaned.isin({"", "nan", "none", "unknown"})]
    return useful_values.nunique() > 0


def build_behavioral_tfidf_logistic_regression() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", StandardScaler(), FEATURE_COLUMNS),
            (
                "user_agent_tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    max_features=2_000,
                    ngram_range=(1, 2),
                    min_df=1,
                ),
                "user_agent",
            ),
        ],
        remainder="drop",
    )
    return Pipeline([
        ("features", preprocessor),
        (
            "classifier",
            LogisticRegression(
                class_weight="balanced",
                max_iter=2_000,
                random_state=RANDOM_STATE,
            ),
        ),
    ])


def evaluate_model(model, X_test: pd.DataFrame, y_test: pd.Series, model_name: str) -> Dict:
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)
    report_text = classification_report(y_test, predictions, zero_division=0)
    report_dict = classification_report(y_test, predictions, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_test, predictions)

    print(f"\nModel: {model_name}")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("Classification report:")
    print(report_text)
    print("Confusion matrix:")
    print(matrix)

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "classification_report": report_dict,
        "confusion_matrix": matrix.tolist(),
    }


def select_best_model(results: Dict[str, Dict]) -> str:
    return max(
        results,
        key=lambda name: (
            results[name]["metrics"]["f1_score"],
            results[name]["metrics"]["recall"],
        ),
    )


def save_outputs(model, metrics: Dict) -> None:
    root = repo_root()
    model_path = root / "models" / "credential_stuffing_model.joblib"
    metrics_path = root / "reports" / "credential_stuffing_model_metrics.json"

    model_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, model_path)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Saved model to {model_path}")
    print(f"Saved metrics to {metrics_path}")


def main() -> None:
    dataset_path = repo_root() / "data" / "credential_stuffing" / "rba_dataset.csv"
    if not dataset_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {dataset_path}\n"
            "Place the Risk-Based Authentication CSV at data/credential_stuffing/rba_dataset.csv"
        )

    df = pd.read_csv(dataset_path)
    detected_columns = list(df.columns)
    print(f"Detected columns ({len(detected_columns)}): {detected_columns}")

    if len(df) > MAX_ROWS:
        df = df.sample(n=MAX_ROWS, random_state=RANDOM_STATE)
        print(f"Sampled {MAX_ROWS} rows for fast FYP training.")

    mapping = detect_dataset_columns(df)
    print(f"Column mapping: {mapping}")
    fail_missing_columns(mapping, detected_columns)

    base = prepare_base_frame(df, mapping)
    featured = engineer_features(base)
    featured["label"] = generate_weak_labels(featured)

    label_counts = featured["label"].value_counts().to_dict()
    print(f"Weak label distribution: {label_counts}")

    if featured["label"].nunique() < 2:
        raise ValueError(
            "Weak labeling produced only one class. Training requires both normal and credential-stuffing-risk rows. "
            f"Label distribution: {label_counts}"
        )

    X_behavioral = featured[FEATURE_COLUMNS]
    X_tfidf = featured[FEATURE_COLUMNS + ["user_agent"]]
    y = featured["label"]

    X_train_behavioral, X_test_behavioral, y_train, y_test = train_test_split(
        X_behavioral,
        y,
        test_size=0.2,
        random_state=RANDOM_STATE,
        stratify=y,
    )
    X_train_tfidf = X_tfidf.loc[X_train_behavioral.index]
    X_test_tfidf = X_tfidf.loc[X_test_behavioral.index]

    trained_models = {}

    model_name = "logistic_regression_behavioral"
    model = build_behavioral_logistic_regression()
    model.fit(X_train_behavioral, y_train)
    trained_models[model_name] = {
        "model": model,
        "uses_tfidf": False,
        "metrics": evaluate_model(model, X_test_behavioral, y_test, model_name),
    }

    model_name = "random_forest_behavioral"
    model = build_behavioral_random_forest()
    model.fit(X_train_behavioral, y_train)
    trained_models[model_name] = {
        "model": model,
        "uses_tfidf": False,
        "metrics": evaluate_model(model, X_test_behavioral, y_test, model_name),
    }

    if mapping.get("user_agent") and user_agent_has_signal(featured):
        model_name = "logistic_regression_behavioral_tfidf"
        model = build_behavioral_tfidf_logistic_regression()
        model.fit(X_train_tfidf, y_train)
        trained_models[model_name] = {
            "model": model,
            "uses_tfidf": True,
            "metrics": evaluate_model(model, X_test_tfidf, y_test, model_name),
        }
    else:
        print("\nSkipping logistic_regression_behavioral_tfidf: user_agent column is missing or contains no usable text.")

    best_model_name = select_best_model(trained_models)
    best_entry = trained_models[best_model_name]
    print(f"\nBest model: {best_model_name}")
    print(
        "Selection rule: highest f1_score, with recall as the tie-breaker. "
        f"Best f1={best_entry['metrics']['f1_score']:.4f}, recall={best_entry['metrics']['recall']:.4f}"
    )

    metrics = {
        "best_model_name": best_model_name,
        "dataset_path": str(dataset_path),
        "rows_used": int(len(featured)),
        "max_rows": MAX_ROWS,
        "feature_columns": FEATURE_COLUMNS,
        "uses_tfidf": bool(best_entry["uses_tfidf"]),
        "label_strategy": (
            "Weak behavioral labels: risk=1 when any Phase 1 credential-stuffing rule threshold is met; "
            "normal=0 otherwise."
        ),
        "column_mapping": mapping,
        "label_distribution": {str(key): int(value) for key, value in label_counts.items()},
        "models": {
            name: {
                "uses_tfidf": bool(entry["uses_tfidf"]),
                **entry["metrics"],
            }
            for name, entry in trained_models.items()
        },
    }
    save_outputs(best_entry["model"], metrics)


if __name__ == "__main__":
    main()
