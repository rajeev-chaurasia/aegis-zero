"""
Aegis Zero AI Engine - Main Entry Point

Orchestrates the threat detection pipeline by consuming logs from Kafka,
generating features, and performing real-time inference.
"""

import logging
import signal
import sys
from typing import List

from config import Config
from consumer import RequestLogConsumer
from features import FeatureEngine
from detector import AnomalyDetector
from blocker import IPBlocker

# Configure standard logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aegis")


class AegisEngine:
    """
    Core engine that coordinates the detection loop.
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.running = False
        
        # Components
        self.consumer: RequestLogConsumer = None
        self.feature_engine: FeatureEngine = None
        self.detector: AnomalyDetector = None
        self.blocker: IPBlocker = None
        
    def initialize(self) -> None:
        """Sets up all subsystems (Kafka, Redis, Models)."""
        logger.info("Initializing Aegis Zero Engine...")
        
        try:
            # 1. Feature Engineering (Stateful)
            self.feature_engine = FeatureEngine(
                window_size_seconds=self.config.window_size_seconds
            )
            
            # 2. Anomaly Detector
            self.detector = AnomalyDetector(
                model_path=self.config.model_path,
                threshold=self.config.anomaly_threshold,
            )
            
            # 3. IP Blocker (Redis)
            self.blocker = IPBlocker(
                redis_url=self.config.redis_url,
                default_ttl=self.config.block_ttl_seconds,
            )
            
            # 4. Kafka Consumer
            self.consumer = RequestLogConsumer(
                brokers=self.config.kafka_brokers,
                topic=self.config.kafka_topic,
                group_id=self.config.kafka_group_id,
                window_size_seconds=self.config.window_size_seconds,
            )
            self.consumer.connect()
            
            logger.info("All systems initialized successfully.")
            
        except Exception as e:
            logger.critical(f"Initialization failed: {e}")
            sys.exit(1)
        
    def process_batch(self, messages: List[dict]) -> None:
        """
        Callback to process a batch of Kafka messages.
        """
        self.feature_engine.reset()
        
        # 1. Ingest
        count = 0
        for msg in messages:
            log = self.feature_engine.parse_log(msg)
            if log:
                self.feature_engine.add_request(log)
                count += 1
        
        if count == 0:
            return

        # 2. Analyze
        ip_features = self.feature_engine.get_features()
        
        for ip, features in ip_features.items():
            # Skip noise (insufficient data points)
            req_count = int(features[0] * self.config.window_size_seconds) # Rough estimate from req/s * window
            # Actually, `features[0]` is NOT req/s wait.
            # features[0] is `Bwd Packet Length Std`.
            # features[4] is `Flow Packets/s`.
            # Let's use Flow Packets/s * window to estimate count.
            est_count = features[4] * self.config.window_size_seconds
            
            # if est_count < self.config.min_requests_for_detection:
            #     continue
            
            # 3. Predict
            is_anomaly, score = self.detector.predict(features)
            
            # DIAGNOSTIC: Log every score to prove AI is used
            logger.info(f"Analyzed IP {ip} -> Score: {score:.4f} (Anomaly: {is_anomaly})")
            
            if is_anomaly:
                logger.warning(f"THREAT DETECTED [IP: {ip}] Score: {score:.4f}")
                
                # 4. Mitigate
                self.blocker.block_ip(
                    ip=ip,
                    reason="ai_anomaly_detection",
                    score=score,
                )
    
    def run(self) -> None:
        """Starts the main event loop."""
        self.running = True
        logger.info(f"Starting detection loop (Topic: {self.config.kafka_topic})...")
        
        try:
            # Blocking call
            self.consumer.consume(self.process_batch)
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
        except Exception as e:
            logger.error(f"Runtime error: {e}")
        finally:
            self.shutdown()
    
    def shutdown(self) -> None:
        """Cleanup resources."""
        logger.info("Stopping services...")
        self.running = False
        
        if self.consumer:
            self.consumer.stop()
        if self.blocker:
            self.blocker.close()
            
        logger.info("Shutdown complete.")


def main():
    config = Config.from_env()
    
    # Adjust log level based on config
    logging.getLogger().setLevel(getattr(logging, config.log_level.upper()))
    
    engine = AegisEngine(config)
    
    # Register signal handlers
    def handle_exit(sig, frame):
        engine.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)
    
    engine.initialize()
    engine.run()


if __name__ == "__main__":
    main()
