# Models — ML Inference and Training

## Overview / Purpose
The models module contains trained machine learning artifacts and training pipelines for ACDS detection tasks. Models are exported in a backend-compatible format and loaded at runtime by the backend for real-time inference. This module manages model versioning, evaluation metrics, and dataset-to-model traceability.

Key responsibilities:
- Storage of trained model artifacts (pickled scikit-learn models, TensorFlow/PyTorch weights, etc.).
- Model metadata (performance metrics, training dataset version, creation timestamp).
- Training and evaluation scripts for retraining and hyperparameter tuning.
- Export utilities to convert models into deployment-ready formats.
- Integration point between ML pipelines and backend inference endpoints.

## Folder Structure
```
models/
├─ phishing/
│  ├─ model_v1.pkl                  # Trained phishing detection model
│  ├─ metadata.json                 # Model version, training date, metrics
│  ├─ training_log.txt              # Training run logs
│  └─ feature_names.json            # Feature indices and names for inference
├─ ransomware/
│  ├─ model_v1.pkl                  # Trained ransomware behavior model
│  ├─ metadata.json
│  └─ training_log.txt
├─ credential_abuse/
│  ├─ model_v1.pkl                  # Trained credential abuse model
│  ├─ metadata.json
│  └─ training_log.txt
├─ train_phishing_model.py           # Phishing model training script
├─ train_ransomware_model.py         # Ransomware model training script
├─ train_credential_model.py         # Credential abuse model training script
├─ export_model.py                   # Utility to export models for deployment
└─ README.md
```

## Dataset and Model Specifications

| Model | Input Features | Output | Dataset | Size |
|---|---|---|---|---|
| Phishing Detector | Email text, sender, URL | Binary (phishing/benign) | Kaggle phishing dataset | ~5000 samples |
| Ransomware Detector | Command sequence, process tree, file I/O | Binary (ransomware/clean) | Custom synthetic + public | ~3000 samples |
| Credential Abuse Detector | Login timing, geolocation, device | Binary (abuse/legitimate) | Internal logs + synthetic | ~10000 samples |

## Responsibilities and Workflow

### Training Pipeline
1. Data Preparation: Raw datasets are preprocessed using scripts in `backend/ml/preprocess.py`. Features are normalized and split into train/test sets (80/20).
2. Model Training: Training scripts (`train_*.py`) load preprocessed data, train models with hyperparameter tuning via cross-validation, and log metrics (accuracy, precision, recall, F1).
3. Model Evaluation: Trained models are evaluated on holdout test sets; metrics are recorded in `metadata.json`.
4. Model Export: The `export_model.py` utility serializes the model, feature names, and metadata into deployment format.
5. Backend Integration: The backend loads exported models at startup and uses them for inference via the `/predict` endpoint.

### Inference Workflow
1. Event arrives at backend `/ingest` endpoint.
2. Backend extracts features using feature names from `feature_names.json`.
3. Loaded model performs inference and returns score and prediction.
4. Score is passed to SOAR rule engine for orchestration.

## Model Metadata Format
Each model directory includes a `metadata.json` file:
```json
{
  "model_name": "phishing_detector",
  "version": "1.0",
  "training_date": "2025-11-14T10:30:00Z",
  "dataset_version": "phishing_kaggle_v1",
  "metrics": {
    "accuracy": 0.95,
    "precision": 0.93,
    "recall": 0.97,
    "f1_score": 0.95,
    "roc_auc": 0.96
  },
  "feature_count": 42,
  "model_type": "sklearn.ensemble.RandomForestClassifier",
  "training_samples": 4800,
  "test_samples": 1200
}
```

## Integration Points
- Backend: Imports and loads models at startup using paths defined in `backend/core/config_loader.py`.
- Preprocessing: Uses utilities from `backend/ml/preprocess.py` to ensure feature consistency between training and inference.
- Data Pipeline: Reads raw datasets from `/data/raw/` and writes processed data to `/data/processed/`.
- CI/CD: Model training tests are run in GitHub Actions; see `.github/workflows/` for build steps.

## Setup and Execution Instructions

### Training a Model
1. Prepare data:
```cmd
python backend/ml/preprocess.py --input /data/raw/phishing_dataset.csv --output /data/processed/phishing_features.pkl
```

2. Train the model:
```cmd
python models/train_phishing_model.py --data /data/processed/phishing_features.pkl --output models/phishing/
```

3. Export the trained model for deployment:
```cmd
python models/export_model.py --model models/phishing/model_v1.pkl --output models/phishing/model_v1_deployed.pkl
```

### Evaluating a Model
```cmd
python models/train_phishing_model.py --data /data/processed/phishing_features.pkl --evaluate-only --model models/phishing/model_v1.pkl
```

### Loading a Model in Backend
The backend automatically loads models specified in the configuration. Example:
```python
from backend.core.config_loader import load_config
from backend.ml.phishing_model import PhishingModel

config = load_config()
model = PhishingModel(config['models']['phishing_path'])
score = model.predict({'email_text': '...', 'sender': '...'})
```

## Future Enhancements
- Model versioning with semantic versioning (v1.0.0, v1.1.0) for clearer tracking.
- Automated retraining pipelines triggered by new labeled data from analyst feedback.
- A/B testing framework for comparing model versions in production.
- Model drift detection to alert when model performance degrades.
- Explainability features (SHAP values, LIME explanations) for analyst interpretability.
- Ensemble methods combining multiple models for improved detection robustness.
