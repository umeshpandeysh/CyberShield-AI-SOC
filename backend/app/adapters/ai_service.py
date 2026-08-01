import os
import pickle
import logging
import numpy as np
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.pipeline import make_pipeline

logger = logging.getLogger("ai_service")

# --- Default Model Paths ---
PHISHING_MODEL_FILE = "models/phishing_detector_v1.pkl"
METADATA_MODEL_FILE = "models/metadata_classifier_v1.pkl"

def levenshtein_similarity(s1: str, s2: str) -> float:
    """Computes Levenshtein similarity distance between two string inputs."""
    s1, s2 = s1.lower(), s2.lower()
    if s1 == s2:
        return 1.0
    l1, l2 = len(s1), len(s2)
    if l1 == 0 or l2 == 0:
        return 0.0
    matrix = [[0] * (l2 + 1) for _ in range(l1 + 1)]
    for i in range(l1 + 1):
        matrix[i][0] = i
    for j in range(l2 + 1):
        matrix[0][j] = j
    for i in range(1, l1 + 1):
        for j in range(1, l2 + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            matrix[i][j] = min(matrix[i-1][j] + 1, matrix[i][j-1] + 1, matrix[i-1][j-1] + cost)
    dist = matrix[l1][l2]
    return 1.0 - (dist / max(l1, l2))


class AIInferenceService:
    def __init__(self):
        self.text_model = None
        self.meta_model = None
        self.model_version = "AI-Threat-v1.0.0"
        self.bootstrap_and_load_models()

    def bootstrap_and_load_models(self):
        """Initializes and loads the machine learning pipelines into memory.
        If files do not exist, bootstraps them with representative training datasets.
        """
        os.makedirs("models", exist_ok=True)
        
        # 1. Text classifier (DistilBERT NLP mock)
        if not os.path.exists(PHISHING_MODEL_FILE):
            logger.info("Bootstrapping default text classifier model...")
            corpus = [
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
            labels = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
            pipe = make_pipeline(TfidfVectorizer(), LogisticRegression())
            pipe.fit(corpus, labels)
            with open(PHISHING_MODEL_FILE, "wb") as f:
                pickle.dump(pipe, f)

        # 2. Metadata classifier (XGBoost mock)
        if not os.path.exists(METADATA_MODEL_FILE):
            logger.info("Bootstrapping default metadata classifier model...")
            # Features: [spf, dkim, dmarc, url_count, suspicious_tld, similarity, att_count, att_exe]
            X = np.array([
                [1, 1, 1, 5, 2, 0.2, 1, 1], # malicious
                [1, 2, 2, 4, 3, 0.1, 0, 0], # malicious
                [0, 0, 0, 0, 0, 1.0, 0, 0], # clean
                [0, 0, 0, 1, 0, 0.9, 1, 0], # clean
                [3, 1, 1, 10, 5, 0.05, 2, 1], # malicious
                [0, 0, 0, 0, 0, 1.0, 1, 0]  # clean
            ])
            y = np.array([1, 1, 0, 0, 1, 0])
            clf = GradientBoostingClassifier()
            clf.fit(X, y)
            with open(METADATA_MODEL_FILE, "wb") as f:
                pickle.dump(clf, f)
                
        # Load models
        try:
            with open(PHISHING_MODEL_FILE, "rb") as f:
                self.text_model = pickle.load(f)
            with open(METADATA_MODEL_FILE, "rb") as f:
                self.meta_model = pickle.load(f)
            logger.info("AI Threat classification models successfully loaded into memory.")
        except Exception as e:
            logger.error(f"Failed to load AI model files: {str(e)}")
            raise RuntimeError(f"AI models load failure: {str(e)}")

    def extract_metadata_features(self, headers: str, body: str, attachments: List[Dict[str, Any]]) -> np.ndarray:
        """Extracts numerical features matching XGBoost metadata architecture from headers and body."""
        headers_lower = (headers or "").lower()
        
        # 1. Parse SPF, DKIM, DMARC status
        spf = 2 # NONE
        if "spf=pass" in headers_lower:
            spf = 0
        elif "spf=fail" in headers_lower:
            spf = 1
        elif "spf=softfail" in headers_lower:
            spf = 3
            
        dkim = 2 # NONE
        if "dkim=pass" in headers_lower:
            dkim = 0
        elif "dkim=fail" in headers_lower:
            dkim = 1
            
        dmarc = 2 # NONE
        if "dmarc=pass" in headers_lower:
            dmarc = 0
        elif "dmarc=fail" in headers_lower:
            dmarc = 1

        # 2. Count URLs
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body or "")
        url_count = len(urls)

        # 3. Count suspicious TLDs
        suspicious_tld = 0
        susp_tlds = [".zip", ".ru", ".cc", ".tk", ".fit", ".gq", ".cf", ".ml"]
        for url in urls:
            if any(tld in url.lower() for tld in susp_tlds):
                suspicious_tld += 1

        # 4. Levenshtein similarity between sender and target domain
        sender_domain = ""
        if "from:" in headers_lower:
            for line in headers_lower.split("\n"):
                if line.startswith("from:"):
                    parts = line.split("@")
                    if len(parts) > 1:
                        sender_domain = parts[1].strip(" <>()\r\n\t")
                        break
        similarity = levenshtein_similarity(sender_domain, "company.com") if sender_domain else 1.0

        # 5. Attachment counts and executable extension check
        att_count = len(attachments)
        att_exe = 0
        for att in attachments:
            name = att.get("filename", "").lower()
            if any(name.endswith(ext) for ext in [".exe", ".scr", ".bat", ".cmd", ".vbs", ".msi"]):
                att_exe = 1
                break

        return np.array([[spf, dkim, dmarc, url_count, suspicious_tld, similarity, att_count, att_exe]])

    def explain_text(self, text: str) -> List[Dict[str, Any]]:
        """Computes feature word contributions via pipeline coefficients."""
        if not self.text_model or not text:
            return []
        try:
            vectorizer = self.text_model.steps[0][1]
            model = self.text_model.steps[1][1]
            
            words = [w.strip(".,!?\"'()[]{}") for w in text.lower().split() if len(w.strip()) > 2]
            feature_names = vectorizer.get_feature_names_out()
            coefficients = model.coef_[0]
            
            word_weights = {}
            for word in set(words):
                if word in feature_names:
                    idx = np.where(feature_names == word)[0][0]
                    word_weights[word] = float(coefficients[idx])
                    
            sorted_words = sorted(word_weights.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
            return [{"token": w, "weight": coeff} for w, coeff in sorted_words]
        except Exception:
            return []

    def classify_email(self, body: str, headers: str, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Computes text and metadata predictions, fuses outputs, and returns explainability results."""
        if not self.text_model or not self.meta_model:
            return {
                "phishing_probability": 0.0,
                "metadata_probability": 0.0,
                "final_risk_score": 0.0,
                "explanations": [],
                "model_version": self.model_version,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

        try:
            # 1. Text inference (phishing vs clean)
            text_prob = float(self.text_model.predict_proba([body or ""])[0][1])

            # 2. Metadata features & inference
            features = self.extract_metadata_features(headers, body, attachments)
            meta_prob = float(self.meta_model.predict_proba(features)[0][1])

            # 3. Fuzzy Decision Fusion Strategy (0.6 text + 0.4 metadata)
            final_score = 0.6 * text_prob + 0.4 * meta_prob

            # 4. Generate Explainable tokens
            explanations = self.explain_text(body)

            return {
                "phishing_probability": text_prob,
                "metadata_probability": meta_prob,
                "final_risk_score": final_score,
                "explanations": explanations,
                "model_version": self.model_version,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        except Exception as e:
            logger.error(f"Inference failure: {str(e)}")
            return {
                "phishing_probability": 0.0,
                "metadata_probability": 0.0,
                "final_risk_score": 0.0,
                "explanations": [],
                "model_version": self.model_version,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

# --- Module level regex helper import ---
import re
_ai_service_instance = None

def get_ai_service() -> AIInferenceService:
    global _ai_service_instance
    if _ai_service_instance is None:
        _ai_service_instance = AIInferenceService()
    return _ai_service_instance
