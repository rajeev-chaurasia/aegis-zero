"""XGBoost-based anomaly detection for network traffic."""

import logging
from pathlib import Path
from typing import Dict, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detects anomalous traffic patterns using Isolation Forest.
    
    The model is pre-trained on CICIDS2017 normal traffic data
    and loaded from a joblib file.
    """
    
    def __init__(self, model_path: str, threshold: float = -0.5):
        """
        Initialize the detector.
        
        Args:
            model_path: Path to the trained model (.joblib file)
            threshold: Anomaly score threshold. Scores below this are anomalies.
                      Default -0.5 is moderately strict.
        """
        self.model_path = model_path
        self.threshold = threshold
        self.model: IsolationForest = None
        self.scaler = None  # StandardScaler for feature normalization
        self._load_model()
    
    def _load_model(self) -> None:
        """Load the pre-trained Isolation Forest model."""
        path = Path(self.model_path)
        
        if not path.exists():
            logger.warning(f"Model not found at {self.model_path}, creating default model")
            self._create_default_model()
            return
        
        try:
            loaded = joblib.load(path)
            
            # Support both bundled and raw model formats
            if isinstance(loaded, dict):
                # Bundled format from Colab notebook
                self.model = loaded['model']
                self.scaler = loaded.get('scaler')
                metrics = loaded.get('metrics', {})
                logger.info(f"Loaded bundled model from {self.model_path}")
                logger.info(f"Model metrics: {metrics}")
            else:
                # Raw IsolationForest object
                self.model = loaded
                logger.info(f"Loaded raw model from {self.model_path}")
                
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self._create_default_model()
    
    def _create_default_model(self) -> None:
        """
        Create a default Isolation Forest model.
        
        This is a fallback when no pre-trained model is available.
        It uses sensible defaults but should be replaced with a
        properly trained model for production use.
        """
        logger.warning("Using default untrained model - train with real data for production!")
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.01,  # 1% of traffic expected to be anomalous
            random_state=42,
            n_jobs=-1,
        )
        
        # Fit on synthetic "normal" data
        # In production, this would be replaced with real training
        # Fit on synthetic "normal" data
        # In production, this would be replaced with real training
        # Features: [req/s, bytes/s, avg_req, std_req, avg_resp, std_resp, lat]
        normal_data = np.array([
            [1.0, 500, 500, 100, 1000, 200, 50],   # Normal browsing
            [0.5, 200, 200, 50, 500, 100, 30],     # Light usage
            [2.0, 2000, 1000, 200, 2000, 400, 100], # API usage
        ])
        # Repeat to create training set
        training_data = np.tile(normal_data, (100, 1)) + np.random.normal(0, 0.1, (300, 7))
        self.model.fit(training_data)
    
    def predict(self, features: np.ndarray) -> Tuple[bool, float]:
        """
        Predict if the given features represent anomalous behavior.
        
        Args:
            features: Feature vector of shape (7,)
        
        Returns:
            Tuple of (is_anomaly, anomaly_score)
            - is_anomaly: True if traffic is anomalous
            - anomaly_score: Raw score (lower = more anomalous)
        """
        if self.model is None:
            logger.error("Model not initialized")
            return False, 0.0
        
        # Reshape for single sample prediction
        X = features.reshape(1, -1)
        
        # Apply scaler if available (from bundled model)
        if self.scaler is not None:
            X = self.scaler.transform(X)
        
        # Get prediction
        prediction = self.model.predict(X)[0]
        
        # Handle different model types
        # Isolation Forest: -1 = Anomaly, 1 = Normal
        # Random Forest (trained on is_attack): 1 = Attack, 0 = Normal
        if hasattr(self.model, 'classes_'): # Supervised models (e.g. Random Forest) have classes_
             # For RF, "1" is the attack class
             is_anomaly = prediction == 1
             # Use probability as score if available
             if hasattr(self.model, 'predict_proba'):
                 # Probability determines confidence. High prob of class 1 = high anomaly score
                 # We negate it to match IF convention if needed, or just return raw prob
                 # Let's standardize: score > 0.5 is anomaly
                 prob_attack = self.model.predict_proba(X)[0][1]
                 score = -prob_attack # Return negative prob so lower is "worse" (more anomaly)
             else:
                 score = -1.0 if prediction == 1 else 1.0
            
             # Supervised (0=Benign, 1=Anomaly)
             # Allow manual threshold override for high sensitivity demonstrations
             # score is negative probability (e.g. -0.005). If threshold is -0.001. -0.005 < -0.001 -> Anomaly.
             is_anomaly = (prediction == 1) or (score < self.threshold)
        else: # Unsupervised (Isolation Forest)
             score = self.model.decision_function(X)[0]
             is_anomaly = prediction == -1 or score < self.threshold
        
        return is_anomaly, score
    
    def predict_batch(self, ip_features: Dict[str, np.ndarray]) -> List[Tuple[str, bool, float]]:
        """
        Predict anomalies for multiple IPs.
        
        Args:
            ip_features: Dictionary mapping IP to feature vector
        
        Returns:
            List of (ip, is_anomaly, score) tuples
        """
        results = []
        
        for ip, features in ip_features.items():
            is_anomaly, score = self.predict(features)
            results.append((ip, is_anomaly, score))
            
            logger.info(f"Analyzed IP {ip} -> Score: {score:.4f} (Anomaly: {is_anomaly})")

            if is_anomaly:
                logger.warning(f"Anomaly detected for IP {ip}: score={score:.4f}")
                
                # Simple Explainability: Log the feature vector
                feature_names = [
                    "Bwd Pkt Len Std", "Bwd Pkt Len Mean", "Avg Pkt Size", "Flow Bytes/s", "Flow Pkts/s",
                    "Fwd IAT Mean", "Fwd IAT Max", "Fwd IAT Min", "Fwd IAT Total", 
                    "Total Fwd Pkts", "Subflow Fwd Pkts", "Avg Bwd Seg Size"
                ]
                explanation = {name: val for name, val in zip(feature_names, features)}
                logger.warning(f"  Feature Vector: {explanation}")
        
        return results
    
    def get_feature_importances(self) -> Dict[str, float]:
        """
        Get relative importance of each feature.
        
        Note: Isolation Forest doesn't have direct feature importances,
        so we return the feature names for reference.
        """
        feature_names = [
            "bwd_packet_length_std",
            "bwd_packet_length_mean",
            "avg_packet_size",
            "flow_bytes_s",
            "flow_packets_s",
            "fwd_iat_mean",
            "fwd_iat_max",
            "fwd_iat_min",
            "fwd_iat_total",
            "total_fwd_packets",
            "subflow_fwd_packets",
            "avg_bwd_segment_size",
        ]
        
        # Return placeholder importances (would need SHAP for real values)
        return {name: 1.0 / len(feature_names) for name in feature_names}
