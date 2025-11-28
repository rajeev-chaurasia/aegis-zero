"""Kafka consumer for processing request logs in batches."""

import json
import logging
import time
from datetime import datetime
from typing import Callable, List, Optional

from kafka import KafkaConsumer
from kafka.errors import KafkaError

logger = logging.getLogger(__name__)


class RequestLogConsumer:
    """Batches Kafka messages by time window for analysis."""
    
    def __init__(
        self,
        brokers: List[str],
        topic: str,
        group_id: str,
        window_size_seconds: int = 5,
    ):
        """
        Initialize the consumer.
        
        Args:
            brokers: List of Kafka broker addresses
            topic: Kafka topic to consume from
            group_id: Consumer group ID
            window_size_seconds: Size of processing window in seconds
        """
        self.brokers = brokers
        self.topic = topic
        self.group_id = group_id
        self.window_size_seconds = window_size_seconds
        self.consumer: Optional[KafkaConsumer] = None
        self.running = False
        
    def connect(self) -> None:
        """Establish connection to Kafka."""
        logger.info(f"Connecting to Kafka at {self.brokers}...")
        
        self.consumer = KafkaConsumer(
            self.topic,
            bootstrap_servers=self.brokers,
            group_id=self.group_id,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            auto_offset_reset="latest",
            enable_auto_commit=True,
            max_poll_records=500,
            consumer_timeout_ms=1000,  # 1 second timeout for windowing
        )
        
        logger.info(f"Connected to Kafka, consuming from topic: {self.topic}")
    
    def consume(self, process_batch: Callable[[List[dict]], None]) -> None:
        """
        Start consuming messages with windowed batching.
        
        Args:
            process_batch: Callback function to process each batch of messages
        """
        if self.consumer is None:
            self.connect()
        
        self.running = True
        batch: List[dict] = []
        window_start = time.time()
        
        logger.info("Starting message consumption...")
        
        while self.running:
            try:
                # Poll for messages (with timeout)
                message_batch = self.consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        batch.append(message.value)
                
                # Check if window has elapsed
                elapsed = time.time() - window_start
                
                if elapsed >= self.window_size_seconds and batch:
                    logger.info(f"Processing window: {len(batch)} messages in {elapsed:.1f}s")
                    
                    try:
                        process_batch(batch)
                    except Exception as e:
                        logger.error(f"Error processing batch: {e}")
                    
                    # Reset for next window
                    batch = []
                    window_start = time.time()
                
                # Also process if batch is large enough
                elif len(batch) >= 1000:
                    logger.info(f"Processing large batch: {len(batch)} messages")
                    
                    try:
                        process_batch(batch)
                    except Exception as e:
                        logger.error(f"Error processing batch: {e}")
                    
                    batch = []
                    window_start = time.time()
                    
            except KafkaError as e:
                logger.error(f"Kafka error: {e}")
                time.sleep(1)
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                time.sleep(1)
        
        # Process any remaining messages
        if batch:
            try:
                process_batch(batch)
            except Exception as e:
                logger.error(f"Error processing final batch: {e}")
    
    def stop(self) -> None:
        """Stop the consumer."""
        logger.info("Stopping consumer...")
        self.running = False
        
        if self.consumer:
            self.consumer.close()
            logger.info("Consumer closed")
