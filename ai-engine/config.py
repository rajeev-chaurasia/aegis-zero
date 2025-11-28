"""
Aegis Zero AI Engine - Configuration
"""

import os
from dataclasses import dataclass
from typing import List


@dataclass
class Config:
    """Configuration for the AI Engine."""
    
    # Kafka
    kafka_brokers: List[str]
    kafka_topic: str
    kafka_group_id: str
    
    # Redis
    redis_url: str
    block_ttl_seconds: int
    
    # Model
    model_path: str
    
    # Detection
    window_size_seconds: int
    anomaly_threshold: float
    min_requests_for_detection: int
    
    # Logging
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            kafka_brokers=os.getenv("KAFKA_BROKERS", "localhost:9092").split(","),
            kafka_topic=os.getenv("KAFKA_TOPIC", "request-logs"),
            kafka_group_id=os.getenv("KAFKA_GROUP_ID", "ai-engine-group"),
            redis_url=os.getenv("REDIS_URL", "localhost:6379"),
            block_ttl_seconds=int(os.getenv("BLOCK_TTL_SECONDS", "300")),
            model_path=os.getenv("MODEL_PATH", "models/xgboost_final.joblib"),
            window_size_seconds=int(os.getenv("WINDOW_SIZE_SECONDS", "5")),
            anomaly_threshold=float(os.getenv("ANOMALY_THRESHOLD", "-0.5")),
            min_requests_for_detection=int(os.getenv("MIN_REQUESTS_FOR_DETECTION", "10")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )
