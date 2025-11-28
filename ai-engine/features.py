"""
Feature Engineering Module for Aegis Zero.

This module is responsible for parsing raw Kafka logs and constructing
numerical feature vectors required by the anomaly detection model.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class RequestLog:
    """Represents a single parsed request log entry."""
    timestamp: datetime
    client_ip: str
    method: str
    url: str
    user_agent: str
    status_code: int
    duration_ms: int
    request_size: int
    response_size: int
    features: Optional[dict] = None  # Pre-calculated features from the proxy


@dataclass
class IPFeatures:
    """Maintains feature state for a specific client IP."""
    ip: str
    latest_features: Optional[dict] = None
    
    def to_vector(self) -> np.ndarray:
        """
        Convert stored features into the 12-dimensional vector expected by XGBoost.
        
        Vector Layout:
        [
            Bwd Packet Length Std,
            Bwd Packet Length Mean,
            Avg Packet Size,
            Flow Bytes/s,
            Flow Packets/s,
            Fwd IAT Mean,
            Fwd IAT Max,
            Fwd IAT Min,
            Fwd IAT Total,
            Total Fwd Packets,
            Subflow Fwd Packets,
            Avg Bwd Segment Size
        ]
        """
        if not self.latest_features:
            return np.zeros(12)
        
        f = self.latest_features
        
        return np.array([
            f.get("bwd_packet_length_std", 0.0),
            f.get("bwd_packet_length_mean", 0.0),
            f.get("avg_packet_size", 0.0),
            f.get("flow_bytes_s", 0.0),
            f.get("flow_packets_s", 0.0),
            f.get("fwd_iat_mean", 0.0),
            f.get("fwd_iat_max", 0.0),
            f.get("fwd_iat_min", 0.0),
            f.get("fwd_iat_total", 0.0),
            float(f.get("total_fwd_packets", 0)),
            float(f.get("subflow_fwd_packets", 0)),
            f.get("bwd_packet_length_mean", 0.0), # Avg Bwd Segment Size ~= Bwd Mean
        ])


class FeatureEngine:
    """
    Manages the parsing and aggregation of traffic features.
    """
    
    def __init__(self, window_size_seconds: int = 5):
        self.window_size_seconds = window_size_seconds
        self.ip_features: Dict[str, IPFeatures] = defaultdict(lambda: IPFeatures(ip=""))
        
    def parse_log(self, log_data: dict) -> Optional[RequestLog]:
        """
        Parses a dictionary log from Kafka into a strongly-typed RequestLog.
        Gracefully handles missing fields or schema mismatches.
        """
        try:
            # Handle potential timezone strings (Z vs +00:00)
            ts_str = log_data.get("timestamp", "")
            if ts_str.endswith("Z"):
                ts_str = ts_str.replace("Z", "+00:00")
            
            return RequestLog(
                timestamp=datetime.fromisoformat(ts_str),
                client_ip=log_data.get("client_ip", "unknown"),
                method=log_data.get("method", "UNKNOWN"),
                url=log_data.get("url", ""),
                user_agent=log_data.get("user_agent", ""),
                status_code=log_data.get("status", 0),      # Updated from Go: "status"
                duration_ms=log_data.get("duration_ms", 0), # Updated from Go: "duration_ms"
                request_size=log_data.get("request_size", 0),
                response_size=log_data.get("response_size", 0),
                features=log_data.get("features"),
            )
        except Exception as e:
            logger.debug(f"Log parsing failed: {e} | Data: {str(log_data)[:100]}...")
            return None
    
    def add_request(self, log: RequestLog) -> None:
        """Updates feature state for the given request."""
        ip = log.client_ip
        if ip not in self.ip_features:
            self.ip_features[ip] = IPFeatures(ip=ip)
        
        # In this architecture, we rely on the proxy's real-time calculation.
        # We just need to persist the latest snapshot for inference.
        if log.features:
            self.ip_features[ip].latest_features = log.features
    
    def get_features(self) -> Dict[str, np.ndarray]:
        """Returns the current feature vectors for all active IPs."""
        result = {}
        for ip, features in self.ip_features.items():
            result[ip] = features.to_vector()
        return result
    
    def reset(self) -> None:
        """Clears current state (called at the start of a window)."""
        self.ip_features.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Returns metadata about the current window state."""
        return {
            "unique_ips": len(self.ip_features),
        }
