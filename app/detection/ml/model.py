"""
ML model wrapper for safe loading and prediction.
Security: Only loads from fixed local paths.
"""
import logging
import pickle
from pathlib import Path
from typing import Tuple, Dict

logger = logging.getLogger(__name__)

# Fixed model paths (never accept user input)
MODEL_DIR = Path(__file__).parent.parent.parent.parent / "models"
VECTORIZER_PATH = MODEL_DIR / "ml_vectorizer.pkl"
MODEL_PATH = MODEL_DIR / "ml_model.pkl"


def load_artifacts() -> Tuple[any, any]:
    """
    Load ML model artifacts from fixed local paths.
    
    Returns:
        Tuple of (vectorizer, model)
    
    Raises:
        FileNotFoundError: If model files don't exist
        Exception: If loading fails
    
    Security:
        - Only loads from hardcoded local paths
        - Never accepts paths from user input
        - Validates path existence before loading
    """
    if not VECTORIZER_PATH.exists():
        raise FileNotFoundError(f"Vectorizer not found: {VECTORIZER_PATH}")
    
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Model not found: {MODEL_PATH}")
    
    # Load vectorizer
    with open(VECTORIZER_PATH, 'rb') as f:
        vectorizer = pickle.load(f)
    
    # Load model
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
    
    logger.info("ML artifacts loaded successfully")
    return vectorizer, model


def predict_proba(vectorizer: any, model: any, features: Dict[str, float]) -> float:
    """
    Get malicious probability from model.
    
    Args:
        vectorizer: DictVectorizer
        model: Trained model
        features: Feature dictionary
    
    Returns:
        Probability score (0-1) for malicious class
    
    Security:
        - Bounded input (features validated in extract_features)
        - Output always in [0, 1]
    """
    try:
        # Vectorize features
        X = vectorizer.transform([features])
        
        # Get probability for malicious class (class 1)
        proba = model.predict_proba(X)[0][1]
        
        # Ensure bounded output
        return max(0.0, min(1.0, float(proba)))
    
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise
