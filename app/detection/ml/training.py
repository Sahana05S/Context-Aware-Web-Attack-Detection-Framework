"""
Optional ML model training script.
Generates synthetic training data and trains a LogisticRegression model.
This is a PoC - in production, use real labeled data.
"""
import logging
from pathlib import Path
import random
from typing import List, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_synthetic_data(n_samples: int = 1000) -> Tuple[List[dict], List[int]]:
    """
    Generate synthetic training data for PoC.
    
    Args:
        n_samples: Number of samples to generate
    
    Returns:
        Tuple of (features_list, labels_list)
    """
    features_list = []
    labels = []
    
    # Generate benign samples (label=0)
    for i in range(n_samples // 2):
        features = {
            'url_len': random.randint(10, 100),
            'query_len': random.randint(0, 50),
            'num_params': random.randint(0, 5),
            'special_char_ratio': random.uniform(0.0, 0.15),
            'pct_encoded': random.randint(0, 2),
            'count_sql_keywords': 0,
            'count_xss_tokens': 0,
            'count_traversal_tokens': 0,
            'count_cmd_tokens': 0,
            'is_suspicious_ua': 0,
            'ua_missing': 0 if random.random() > 0.1 else 1,
            'status_is_4xx': 0 if random.random() > 0.2 else 1,
            'status_is_5xx': 0 if random.random() > 0.05 else 1,
            'method_is_post': 0 if random.random() > 0.3 else 1,
            'path_depth': random.randint(1, 5),
            'has_login_keyword': 0 if random.random() > 0.1 else 1
        }
        features_list.append(features)
        labels.append(0)
    
    # Generate malicious samples (label=1)
    for i in range(n_samples // 2):
        attack_type = random.choice(['sqli', 'xss', 'traversal', 'cmd'])
        
        if attack_type == 'sqli':
            features = {
                'url_len': random.randint(50, 300),
                'query_len': random.randint(30, 200),
                'num_params': random.randint(3, 15),
                'special_char_ratio': random.uniform(0.2, 0.5),
                'pct_encoded': random.randint(5, 30),
                'count_sql_keywords': random.randint(2, 8),
                'count_xss_tokens': 0,
                'count_traversal_tokens': 0,
                'count_cmd_tokens': random.randint(0, 2),
                'is_suspicious_ua': 1 if random.random() > 0.7 else 0,
                'ua_missing': 0,
                'status_is_4xx': 0 if random.random() > 0.3 else 1,
                'status_is_5xx': 0 if random.random() > 0.2 else 1,
                'method_is_post': 1 if random.random() > 0.3 else 0,
                'path_depth': random.randint(2, 8),
                'has_login_keyword': 0 if random.random() > 0.3 else 1
            }
        elif attack_type == 'xss':
            features = {
                'url_len': random.randint(40, 250),
                'query_len': random.randint(20, 150),
                'num_params': random.randint(2, 10),
                'special_char_ratio': random.uniform(0.25, 0.6),
                'pct_encoded': random.randint(3, 25),
                'count_sql_keywords': 0,
                'count_xss_tokens': random.randint(2, 6),
                'count_traversal_tokens': 0,
                'count_cmd_tokens': 0,
                'is_suspicious_ua': 1 if random.random() > 0.8 else 0,
                'ua_missing': 0,
                'status_is_4xx': 0 if random.random() > 0.2 else 1,
                'status_is_5xx': 0,
                'method_is_post': 1 if random.random() > 0.5 else 0,
                'path_depth': random.randint(2, 6),
                'has_login_keyword': 0
            }
        elif attack_type == 'traversal':
            features = {
                'url_len': random.randint(30, 200),
                'query_len': random.randint(10, 100),
                'num_params': random.randint(1, 8),
                'special_char_ratio': random.uniform(0.2, 0.4),
                'pct_encoded': random.randint(8, 40),
                'count_sql_keywords': 0,
                'count_xss_tokens': 0,
                'count_traversal_tokens': random.randint(3, 12),
                'count_cmd_tokens': 0,
                'is_suspicious_ua': 1 if random.random() > 0.7 else 0,
                'ua_missing': 0,
                'status_is_4xx': 1 if random.random() > 0.2 else 0,
                'status_is_5xx': 0,
                'method_is_post': 0,
                'path_depth': random.randint(4, 15),
                'has_login_keyword': 0
            }
        else:  # cmd
            features = {
                'url_len': random.randint(40, 220),
                'query_len': random.randint(20, 140),
                'num_params': random.randint(2, 10),
                'special_char_ratio': random.uniform(0.3, 0.55),
                'pct_encoded': random.randint(4, 20),
                'count_sql_keywords': 0,
                'count_xss_tokens': 0,
                'count_traversal_tokens': 0,
                'count_cmd_tokens': random.randint(2, 8),
                'is_suspicious_ua': 1 if random.random() > 0.6 else 0,
                'ua_missing': 0,
                'status_is_4xx': 0 if random.random() > 0.3 else 1,
                'status_is_5xx': 1 if random.random() > 0.7 else 0,
                'method_is_post': 1 if random.random() > 0.4 else 0,
                'path_depth': random.randint(2, 7),
                'has_login_keyword': 0
            }
        
        features_list.append(features)
        labels.append(1)
    
    return features_list, labels


def train_model():
    """
    Train ML model and save artifacts.
    """
    try:
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        import pickle
    except ImportError:
        logger.error("sklearn not installed. Install with: pip install scikit-learn")
        return
    
    logger.info("Generating synthetic training data...")
    X_dict, y = generate_synthetic_data(n_samples=2000)
    
    # Split data
    X_train_dict, X_test_dict, y_train, y_test = train_test_split(
        X_dict, y, test_size=0.2, random_state=42, stratify=y
    )
    
    logger.info(f"Training samples: {len(X_train_dict)}, Test samples: {len(X_test_dict)}")
    
    # Vectorize features
    logger.info("Vectorizing features...")
    vectorizer = DictVectorizer(sparse=False)
    X_train = vectorizer.fit_transform(X_train_dict)
    X_test = vectorizer.transform(X_test_dict)
    
    # Train model
    logger.info("Training LogisticRegression model...")
    model = LogisticRegression(
        solver='liblinear',
        max_iter=1000,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    
    logger.info("=" * 50)
    logger.info("MODEL PERFORMANCE METRICS")
    logger.info("=" * 50)
    logger.info(f"Accuracy: {accuracy:.3f}")
    logger.info(f"Precision: {precision:.3f}")
    logger.info(f"Recall: {recall:.3f}")
    logger.info(f"F1 Score: {f1:.3f}")
    logger.info("=" * 50)
    
    # Save artifacts
    model_dir = Path(__file__).parent.parent.parent.parent / "models"
    model_dir.mkdir(exist_ok=True)
    
    vectorizer_path = model_dir / "ml_vectorizer.pkl"
    model_path = model_dir / "ml_model.pkl"
    
    logger.info(f"Saving artifacts to {model_dir}...")
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    logger.info("✓ Training complete! Model artifacts saved.")
    logger.info(f"  - {vectorizer_path}")
    logger.info(f"  - {model_path}")


if __name__ == "__main__":
    train_model()
