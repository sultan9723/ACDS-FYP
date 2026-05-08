# ML Training

This folder contains Jupyter notebooks for training machine learning models.

## Contents

| File                  | Description                             |
| --------------------- | --------------------------------------- |
| `phishingmodel.ipynb` | Phishing email detection model training |

## Model Architecture

- **Vectorizer:** TF-IDF (5000 features, unigrams + bigrams)
- **Classifier:** Logistic Regression (balanced class weights)
- **Dataset:** HuggingFace `zefang-liu/phishing-email-dataset` (18,650 samples)

## Usage

1. Open `phishingmodel.ipynb` in Google Colab
2. Run all cells to train the model
3. Download trained artifacts to `backend/ml/models/`

## Output Artifacts

After training, copy these files to `../backend/ml/models/`:

- `phishing_model.pkl` - Trained TF-IDF + LogReg pipeline
- `model_info.json` - Model metadata and metrics
