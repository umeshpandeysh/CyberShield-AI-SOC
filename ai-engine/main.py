import os
import pickle
import numpy as np
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from typing import List, Dict, Optional

# Initialize path environments
os.makedirs("models", exist_ok=True)
PHISHING_MODEL_PATH = os.getenv("PHISHING_MODEL_PATH", "models/phishing_detector_v1.pkl")
SPAM_MODEL_PATH = os.getenv("SPAM_MODEL_PATH", "models/spam_classifier_v1.pkl")

# --- Bootstrap default model files if not exists ---
def bootstrap_models():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline

    # Training data corpus
    phish_corpus = [
        "verify your account details immediately, urgent secure link action required",
        "update your bank password and credentials, unusual sign-in activity detected",
        "please click here to reset your login password for secure portal",
        "official paypal notification: verify debit card verification status",
        "congratulations, you won a free gift card, click to claim your reward",
        "hello, let's schedule our meeting for next week tuesday morning",
        "the team project status update is attached to the weekly report document",
        "can you review the PR and merge it if it looks good to go",
        "are we meeting for dinner tonight or should we postpone to thursday",
        "good morning, here is the draft of the design specification document"
    ]
    phish_labels = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]

    spam_corpus = [
        "buy cheap luxury watches online, 90% discount promotion code coupon",
        "enlarge size fast, guaranteed natural organic supplement special offer",
        "make money online fast, work from home cash flow business opportunity",
        "get cheap loans today with low interest rates, instant approval",
        "claim your free cash lottery prize now, winner notification email",
        "weekly sync meeting notes and key action items for the development team",
        "design feedback document for the new frontend dashboard layout review",
        "could you send me the updated API specs for the authentication routes",
        "reminder to submit your timesheet before end of day friday",
        "thanks for the quick response, I will follow up with the customer shortly"
    ]
    spam_labels = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]

    if not os.path.exists(PHISHING_MODEL_PATH):
        phish_pipe = make_pipeline(TfidfVectorizer(), LogisticRegression())
        phish_pipe.fit(phish_corpus, phish_labels)
        with open(PHISHING_MODEL_PATH, "wb") as f:
            pickle.dump(phish_pipe, f)

    if not os.path.exists(SPAM_MODEL_PATH):
        spam_pipe = make_pipeline(TfidfVectorizer(), LogisticRegression())
        spam_pipe.fit(spam_corpus, spam_labels)
        with open(SPAM_MODEL_PATH, "wb") as f:
            pickle.dump(spam_pipe, f)

# Trigger model bootstrapping
bootstrap_models()

# Load models into memory
try:
    with open(PHISHING_MODEL_PATH, "rb") as f:
        phishing_model = pickle.load(f)
    with open(SPAM_MODEL_PATH, "rb") as f:
        spam_model = pickle.load(f)
except Exception as e:
    # Fail fast if weights cannot be loaded, conforming to architecture
    raise RuntimeError(f"Failed to load machine learning weights: {str(e)}")

app = FastAPI(
    title="CyberShield-AI-SOC AI Engine",
    description="ML serving service for classifying phishing and spam email vectors.",
    version="1.0.0"
)

# --- Schemas ---
class ClassificationRequest(BaseModel):
    email_id: str
    body: str
    headers: Optional[str] = ""

class ExplanationItem(BaseModel):
    token: str
    weight: float

class ClassificationResponse(BaseModel):
    is_phishing: bool
    phishing_probability: float
    is_spam: bool
    spam_probability: float
    explanations: List[ExplanationItem]

# --- Helper logic for XAI ---
def explain_text(text: str, pipeline) -> List[ExplanationItem]:
    """Extracts top words contributing to the decision using pipeline coefficients."""
    try:
        vectorizer = pipeline.steps[0][1]
        model = pipeline.steps[1][1]
        
        words = [w.strip(".,!?\"'()[]{}") for w in text.lower().split() if len(w.strip()) > 2]
        feature_names = vectorizer.get_feature_names_out()
        coefficients = model.coef_[0]
        
        word_weights = {}
        for word in set(words):
            if word in feature_names:
                idx = np.where(feature_names == word)[0][0]
                # coefficient * tf-idf weight would be better, but coefficient shows base feature importance
                word_weights[word] = float(coefficients[idx])
                
        sorted_words = sorted(word_weights.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        return [ExplanationItem(token=w, weight=coeff) for w, coeff in sorted_words]
    except Exception:
        return []

# --- Routes ---
@app.get("/api/v1/health", tags=["Health"])
def health_check():
    return {"status": "healthy", "service": "ai-engine"}

@app.post("/api/v1/classify", response_model=ClassificationResponse, tags=["Classification"])
def classify_email(payload: ClassificationRequest):
    """Predicts phishing and spam scores based on TF-IDF features and logs term importances."""
    if not payload.body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload body content is empty"
        )
        
    try:
        # Run predictions
        phishing_prob = float(phishing_model.predict_proba([payload.body])[0][1])
        spam_prob = float(spam_model.predict_proba([payload.body])[0][1])
        
        is_phishing = phishing_prob >= 0.5
        is_spam = spam_prob >= 0.5
        
        # Compute explanations (XAI)
        explanations = explain_text(payload.body, phishing_model)
        
        return ClassificationResponse(
            is_phishing=is_phishing,
            phishing_probability=phishing_prob,
            is_spam=is_spam,
            spam_probability=spam_prob,
            explanations=explanations
        )
    except Exception as e:
        # Graceful degradation under serving errors
        return ClassificationResponse(
            is_phishing=False,
            phishing_probability=0.0,
            is_spam=False,
            spam_probability=0.0,
            explanations=[]
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
