"""IP blocking service backed by Redis."""

import logging
import time
from typing import Optional

import redis

logger = logging.getLogger(__name__)


class IPBlocker:
    """Handles adding/removing IPs from Redis blocklist with auto-expiry."""
    
    BLOCKLIST_PREFIX = "blocklist:ip:"
    STATS_KEY = "aegis:stats:blocked_ips"
    
    def __init__(self, redis_url: str, default_ttl: int = 300):
        """
        Initialize the IP blocker.
        
        Args:
            redis_url: Redis connection URL (host:port)
            default_ttl: Default block duration in seconds (default 5 minutes)
        """
        self.default_ttl = default_ttl
        
        # Parse host:port
        host, port = redis_url.split(":")
        self.client = redis.Redis(
            host=host,
            port=int(port),
            decode_responses=True,
        )
        
        # Test connection with retries
        import time
        max_retries = 5
        base_delay = 2
        
        for attempt in range(max_retries):
            try:
                self.client.ping()
                logger.info(f"Connected to Redis at {redis_url}")
                break
            except (redis.ConnectionError, redis.RedisError) as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to connect to Redis after {max_retries} attempts: {e}")
                    raise
                wait_time = base_delay * (2 ** attempt)
                logger.warning(f"Failed to connect to Redis (attempt {attempt+1}/{max_retries}). Retrying in {wait_time}s... Error: {e}")
                time.sleep(wait_time)
    
    def block_ip(
        self,
        ip: str,
        reason: str = "anomaly_detected",
        score: float = 0.0,
        ttl: Optional[int] = None
    ) -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            score: Anomaly score that triggered the block
            ttl: Block duration in seconds (uses default if not specified)
        
        Returns:
            True if successfully blocked, False otherwise
        """
        if ttl is None:
            ttl = self.default_ttl
        
        key = f"{self.BLOCKLIST_PREFIX}{ip}"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        value = f'{{"reason": "{reason}", "score": {score:.4f}, "blocked_at": "{timestamp}"}}'
        
        try:
            # SETEX: Set with expiration
            self.client.setex(key, ttl, value)
            
            # Store in set for history (Grafana supports SMEMBERS)
            log_entry = f"{ip} | {timestamp} | score={score:.4f}"
            self.client.sadd("aegis:blocked_set", log_entry)
            
            # Increment blocked IP counter
            self.client.incr(self.STATS_KEY)
            
            logger.info(f"Blocked IP {ip} for {ttl}s: {reason} (score={score:.4f})")
            return True
            
        except redis.RedisError as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: IP address to unblock
        
        Returns:
            True if successfully unblocked, False otherwise
        """
        key = f"{self.BLOCKLIST_PREFIX}{ip}"
        
        try:
            result = self.client.delete(key)
            if result:
                logger.info(f"Unblocked IP {ip}")
            return result > 0
            
        except redis.RedisError as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """
        Check if an IP is currently blocked.
        
        Args:
            ip: IP address to check
        
        Returns:
            True if blocked, False otherwise
        """
        key = f"{self.BLOCKLIST_PREFIX}{ip}"
        
        try:
            return self.client.exists(key) > 0
        except redis.RedisError as e:
            logger.error(f"Failed to check IP {ip}: {e}")
            return False
    
    def get_blocked_count(self) -> int:
        """
        Get the total number of IPs that have been blocked.
        
        Returns:
            Total blocked IP count
        """
        try:
            count = self.client.get(self.STATS_KEY)
            return int(count) if count else 0
        except redis.RedisError as e:
            logger.error(f"Failed to get blocked count: {e}")
            return 0
    
    def get_active_blocks(self) -> int:
        """
        Get the number of currently active blocks.
        
        Returns:
            Number of currently blocked IPs
        """
        try:
            pattern = f"{self.BLOCKLIST_PREFIX}*"
            keys = self.client.keys(pattern)
            return len(keys)
        except redis.RedisError as e:
            logger.error(f"Failed to get active blocks: {e}")
            return 0
    
    def close(self) -> None:
        """Close the Redis connection."""
        self.client.close()
        logger.info("Redis connection closed")
