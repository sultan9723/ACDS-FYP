# ML Models

This folder contains trained model artifacts used by the phishing detection service.

## Required Files

| File                 | Description                                   | Source                                 |
| -------------------- | --------------------------------------------- | -------------------------------------- |
| `phishing_model.pkl` | Trained TF-IDF + Logistic Regression pipeline | From `ml_training/phishingmodel.ipynb` |
| `model_info.json`    | Model metadata, metrics, and version info     | From `ml_training/phishingmodel.ipynb` |

## How to Update

1. Run `ml_training/phishingmodel.ipynb` in Google Colab
2. Download the generated model files
3. Place them in this folder (`backend/ml/models/`)
4. Restart the backend server

## Model Versioning

Update `model_info.json` with version info when retraining:

```json
{
  "model_version": "1.0.0",
  "trained_at": "2025-12-10T00:00:00Z",
  "accuracy": 0.97,
  ...
}
```
