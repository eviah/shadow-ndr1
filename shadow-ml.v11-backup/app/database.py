# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║   Shadow NDR – Database Layer                                             ║
║   Ultra‑resilient ClickHouse + Redis connections with pooling, metrics   ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple, Union

import pandas as pd
from clickhouse_driver import Client as SyncClickHouseClient
from clickhouse_driver.errors import Error as ClickHouseError
from loguru import logger
from prometheus_client import Counter, Gauge, Histogram
from pydantic import BaseModel, Field, ValidationError
from redis.asyncio import Redis as AsyncRedis
from redis.asyncio import ConnectionPool as RedisPool
from redis.exceptions import RedisError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
    before_sleep_log,
)

from .config import settings

# =============================================================================
# Prometheus metrics
# =============================================================================

ch_queries_total = Counter(
    "clickhouse_queries_total",
    "Total number of ClickHouse queries",
    ["operation", "status"],
)
ch_query_duration = Histogram(
    "clickhouse_query_duration_seconds",
    "ClickHouse query duration",
    ["operation"],
)
ch_connections_active = Gauge("clickhouse_connections_active", "Active ClickHouse connections")
ch_connections_total = Counter("clickhouse_connections_total", "Total ClickHouse connections created")

redis_commands_total = Counter(
    "redis_commands_total",
    "Total Redis commands",
    ["command", "status"],
)
redis_command_duration = Histogram(
    "redis_command_duration_seconds",
    "Redis command duration",
    ["command"],
)
redis_connections_active = Gauge("redis_connections_active", "Active Redis connections")
redis_connections_total = Counter("redis_connections_total", "Total Redis connections created")

# =============================================================================
# Pydantic models for packet structure
# =============================================================================

class PacketSchema(BaseModel):
    """Represents a parsed packet from the database."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    proto: int
    size: int
    attack_types: Optional[List[str]] = Field(default_factory=list)
    score: Optional[float] = 0.0

    model_config = {"extra": "ignore"}


# =============================================================================
# ClickHouse Async Wrapper (using thread pool)
# =============================================================================

class AsyncClickHouseClient:
    """
    Asynchronous wrapper for clickhouse-driver using a thread pool.
    Provides connection pooling and automatic retries.
    """

    def __init__(
        self,
        host: str,
        port: int,
        database: str,
        user: str = "default",
        password: str = "",
        connect_timeout: int = 10,
        send_receive_timeout: int = 30,
        pool_size: int = 5,
        **kwargs,
    ):
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.connect_timeout = connect_timeout
        self.send_receive_timeout = send_receive_timeout
        self.pool_size = pool_size
        self.extra_kwargs = kwargs

        self._pool: List[SyncClickHouseClient] = []
        self._lock = asyncio.Lock()
        self._executor = None  # will be created on first use
        self._closed = False

        # Metrics
        ch_connections_total.inc()

    async def _get_connection(self) -> SyncClickHouseClient:
        """Get a connection from the pool or create a new one."""
        async with self._lock:
            if self._pool:
                conn = self._pool.pop()
                ch_connections_active.inc()
                return conn

        # Create new connection (blocking operation – run in thread)
        loop = asyncio.get_event_loop()
        try:
            conn = await loop.run_in_executor(
                self._executor,
                lambda: SyncClickHouseClient(
                    host=self.host,
                    port=self.port,
                    database=self.database,
                    user=self.user,
                    password=self.password,
                    connect_timeout=self.connect_timeout,
                    send_receive_timeout=self.send_receive_timeout,
                    **self.extra_kwargs,
                ),
            )
        except Exception as e:
            logger.error(f"❌ ClickHouse connection failed: {e}")
            ch_queries_total.labels(operation="connect", status="error").inc()
            raise
        ch_connections_total.inc()
        ch_connections_active.inc()
        return conn

    async def _release_connection(self, conn: SyncClickHouseClient) -> None:
        """Return a connection to the pool or close if pool is full."""
        async with self._lock:
            if len(self._pool) < self.pool_size:
                self._pool.append(conn)
                return
        # Pool full – close the connection
        await asyncio.get_event_loop().run_in_executor(self._executor, conn.disconnect)
        ch_connections_active.dec()

    async def execute(
        self,
        query: str,
        params: Optional[Dict] = None,
        with_column_types: bool = False,
        stream: bool = False,
    ) -> Union[List[tuple], Tuple[List[tuple], List[tuple]]]:
        """
        Execute a query and return results.
        Automatically retries on transient errors.
        """
        operation = "execute"
        start = datetime.now()
        try:
            return await self._execute_with_retry(query, params, with_column_types, stream)
        except Exception as e:
            ch_queries_total.labels(operation=operation, status="error").inc()
            raise
        finally:
            duration = (datetime.now() - start).total_seconds()
            ch_query_duration.labels(operation=operation).observe(duration)

    @retry(
        retry=retry_if_exception_type((ClickHouseError, ConnectionError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        before_sleep=before_sleep_log(logger, "DEBUG"),
    )
    async def _execute_with_retry(self, query, params, with_column_types, stream):
        conn = await self._get_connection()
        try:
            loop = asyncio.get_event_loop()
            if stream:
                # For large results, we use execute_iter which returns a generator.
                # However, the generator is not awaitable, so we need to run it in thread
                # and then iterate. For simplicity, we return all rows at once.
                # In production, you might want to yield rows as they come.
                result = await loop.run_in_executor(
                    self._executor,
                    lambda: conn.execute(query, params=params, with_column_types=with_column_types),
                )
            else:
                result = await loop.run_in_executor(
                    self._executor,
                    lambda: conn.execute(query, params=params, with_column_types=with_column_types),
                )
            ch_queries_total.labels(operation="execute", status="success").inc()
            return result
        finally:
            await self._release_connection(conn)

    async def close(self):
        """Close all connections in the pool."""
        async with self._lock:
            for conn in self._pool:
                await asyncio.get_event_loop().run_in_executor(self._executor, conn.disconnect)
            self._pool.clear()
            ch_connections_active.set(0)
            self._closed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


# =============================================================================
# Redis Async Client with Pool and Retries
# =============================================================================

class AsyncRedisClient:
    """
    Enhanced Redis client with connection pooling, retries, and metrics.
    """

    def __init__(self, url: str, max_connections: int = 20, **kwargs):
        self.url = url
        self.max_connections = max_connections
        self.kwargs = kwargs
        self.pool: Optional[RedisPool] = None
        self.client: Optional[AsyncRedis] = None
        self._closed = False

    async def connect(self):
        """Initialize connection pool and client."""
        try:
            self.pool = RedisPool.from_url(
                self.url,
                max_connections=self.max_connections,
                decode_responses=True,  # we want strings, not bytes
                **self.kwargs,
            )
            self.client = AsyncRedis(connection_pool=self.pool)
            # Test connection
            await self.client.ping()
            logger.info(f"✅ Redis connected: {self.url.split('@')[-1]}")
            redis_connections_total.inc()
            redis_connections_active.set(self.max_connections)  # approximate
        except Exception as e:
            logger.error(f"❌ Redis connection failed: {e}")
            raise

    @retry(
        retry=retry_if_exception_type((RedisError, ConnectionError, TimeoutError)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        before_sleep=before_sleep_log(logger, "DEBUG"),
    )
    async def execute_command(self, command: str, *args, **kwargs) -> Any:
        """Execute a Redis command with retries and metrics."""
        if self.client is None or self._closed:
            raise RuntimeError("Redis client not connected or already closed")
        start = datetime.now()
        try:
            method = getattr(self.client, command)
            result = await method(*args, **kwargs)
            redis_commands_total.labels(command=command, status="success").inc()
            return result
        except Exception as e:
            redis_commands_total.labels(command=command, status="error").inc()
            raise
        finally:
            duration = (datetime.now() - start).total_seconds()
            redis_command_duration.labels(command=command).observe(duration)

    async def get_json(self, key: str) -> Optional[Dict]:
        """Get a JSON value and parse it."""
        data = await self.execute_command("get", key)
        if data:
            return json.loads(data)
        return None

    async def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a JSON value (serialized)."""
        serialized = json.dumps(value, default=str)
        if ttl:
            return await self.execute_command("setex", key, ttl, serialized)
        else:
            return await self.execute_command("set", key, serialized)

    async def close(self):
        """Close the connection pool."""
        if self.client and not self._closed:
            await self.client.close()
            await self.pool.disconnect()
            self._closed = True
            redis_connections_active.set(0)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.close()


# =============================================================================
# Main Database Facade
# =============================================================================

class Database:
    """
    Unified database interface for ClickHouse and Redis.
    Provides high‑level methods for ML training data and packet caching.
    """

    def __init__(self):
        self._ch: Optional[AsyncClickHouseClient] = None
        self._redis: Optional[AsyncRedisClient] = None
        self._initialized = False

    # -------------------------------------------------------------------------
    # Compatibility methods
    # -------------------------------------------------------------------------

    async def connect(self):
        """Alias for initialize() – called from main.py."""
        await self.initialize()

    async def initialize(self):
        """Create connections and pools."""
        if self._initialized:
            return

        # ClickHouse connection
        self._ch = AsyncClickHouseClient(
            host=settings.database.host,
            port=settings.database.port,
            database=settings.database.database,
            user=settings.database.user,
            password=settings.database.password,
            connect_timeout=settings.database.connect_timeout,
            pool_size=10,
        )

        # Redis connection
        redis_url = (
            f"redis://{settings.redis.host}:{settings.redis.port}/{settings.redis.db}"
        )
        if settings.redis.password:
            redis_url = f"redis://:{settings.redis.password}@{settings.redis.host}:{settings.redis.port}/{settings.redis.db}"
        self._redis = await AsyncRedisClient(
            url=redis_url,
            max_connections=settings.redis.max_connections,
        ).__aenter__()

        self._initialized = True
        logger.success("✅ Database layer initialized")

    async def close(self):
        """Close all connections."""
        if self._ch:
            await self._ch.close()
        if self._redis:
            await self._redis.close()
        self._initialized = False
        logger.info("Database connections closed")

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, *args):
        await self.close()

    # -------------------------------------------------------------------------
    # ClickHouse data fetching
    # -------------------------------------------------------------------------

    async def fetch_training_data(
        self,
        hours: int = 24,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        """
        Fetch historical packet data for model training.
        Supports time range and optional limit.
        """
        if not self._ch:
            raise RuntimeError("Database not initialized")

        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=hours)
        if end_time is None:
            end_time = datetime.utcnow()

        # Build query with proper time zone handling
        query = """
        SELECT
            timestamp,
            src_ip,
            dst_ip,
            proto,
            size,
            attack_types,
            score
        FROM packets
        WHERE timestamp >= %(start)s AND timestamp < %(end)s
        ORDER BY timestamp
        """
        params = {
            "start": start_time.isoformat(sep=" ")[:19],
            "end": end_time.isoformat(sep=" ")[:19],
        }

        if limit:
            query += " LIMIT %(limit)s"
            params["limit"] = limit

        try:
            data = await self._ch.execute(query, params=params, with_column_types=True)
            rows, columns = data
            df = pd.DataFrame(rows, columns=[col[0] for col in columns])
            logger.info(f"📊 Fetched {len(df)} records from ClickHouse")
            return df
        except Exception as e:
            logger.error(f"❌ ClickHouse query failed: {e}")
            return pd.DataFrame()

    async def stream_packets(
        self,
        start_time: datetime,
        end_time: datetime,
        batch_size: int = 10000,
    ) -> AsyncGenerator[List[PacketSchema], None]:
        """
        Stream packets in batches using OFFSET pagination.
        Yields lists of parsed packets.
        """
        if not self._ch:
            raise RuntimeError("Database not initialized")

        offset = 0
        while True:
            query = """
            SELECT
                timestamp,
                src_ip,
                dst_ip,
                proto,
                size,
                attack_types,
                score
            FROM packets
            WHERE timestamp >= %(start)s AND timestamp < %(end)s
            ORDER BY timestamp
            LIMIT %(limit)s OFFSET %(offset)s
            """
            params = {
                "start": start_time.isoformat(sep=" ")[:19],
                "end": end_time.isoformat(sep=" ")[:19],
                "limit": batch_size,
                "offset": offset,
            }
            try:
                rows = await self._ch.execute(query, params=params)
                if not rows:
                    break
                batch = []
                for row in rows:
                    try:
                        packet = PacketSchema(
                            timestamp=row[0],
                            src_ip=row[1],
                            dst_ip=row[2],
                            proto=row[3],
                            size=row[4],
                            attack_types=json.loads(row[5]) if row[5] else [],
                            score=row[6],
                        )
                        batch.append(packet)
                    except (ValidationError, json.JSONDecodeError) as e:
                        logger.warning(f"Skipping malformed packet: {e}")
                yield batch
                offset += batch_size
            except Exception as e:
                logger.error(f"Streaming error: {e}")
                break

    # -------------------------------------------------------------------------
    # Redis caching / buffering
    # -------------------------------------------------------------------------

    async def cache_packet(self, packet: PacketSchema, ttl_seconds: int = 300):
        """
        Store a single packet in Redis (JSON) with TTL.
        """
        if not self._redis:
            raise RuntimeError("Database not initialized")

        key = f"packet:{packet.timestamp.timestamp()}:{packet.src_ip}"
        await self._redis.set_json(key, packet.model_dump(), ttl=ttl_seconds)

    async def get_recent_packets(
        self,
        minutes: int = 5,
        limit: int = 1000,
        pattern: str = "packet:*",
    ) -> List[PacketSchema]:
        """
        Retrieve recent packets from Redis cache.
        Uses pattern matching and sorted by key (which includes timestamp).
        """
        if not self._redis:
            raise RuntimeError("Database not initialized")

        try:
            keys = await self._redis.execute_command("keys", pattern)
            if not keys:
                return []
            # keys are strings like "packet:1234567890.123:1.2.3.4"
            def sort_key(k):
                try:
                    return float(k.split(":")[1])
                except:
                    return 0.0

            sorted_keys = sorted(keys, key=sort_key, reverse=True)[:limit]
            packets = []
            for key in sorted_keys:
                data = await self._redis.get_json(key)
                if data:
                    try:
                        p = PacketSchema(**data)
                        packets.append(p)
                    except ValidationError as e:
                        logger.warning(f"Invalid packet data in Redis: {e}")
            return packets
        except Exception as e:
            logger.error(f"Failed to get recent packets: {e}")
            return []

    async def flush_old_packets(self, max_age_seconds: int = 600):
        """
        Remove packets older than max_age from Redis.
        Can be run periodically.
        """
        if not self._redis:
            return
        cutoff = datetime.utcnow().timestamp() - max_age_seconds
        try:
            keys = await self._redis.execute_command("keys", "packet:*")
            deleted = 0
            for key in keys:
                try:
                    ts = float(key.split(":")[1])
                    if ts < cutoff:
                        await self._redis.execute_command("del", key)
                        deleted += 1
                except:
                    pass
            if deleted:
                logger.info(f"🧹 Flushed {deleted} old packets from Redis")
        except Exception as e:
            logger.error(f"Flush error: {e}")

    # -------------------------------------------------------------------------
    # Health checks
    # -------------------------------------------------------------------------

    async def health_check(self) -> Dict[str, Any]:
        """
        Check connectivity to both databases.
        Returns a dictionary with statuses and details.
        """
        status = {"clickhouse": False, "redis": False}
        details = {}

        # ClickHouse ping
        if self._ch:
            try:
                await self._ch.execute("SELECT 1")
                status["clickhouse"] = True
                details["clickhouse"] = "ok"
            except Exception as e:
                details["clickhouse"] = str(e)
        else:
            details["clickhouse"] = "not initialized"

        # Redis ping
        if self._redis and self._redis.client:
            try:
                pong = await self._redis.execute_command("ping")
                status["redis"] = pong == "PONG"
                details["redis"] = "ok" if status["redis"] else "ping failed"
            except Exception as e:
                details["redis"] = str(e)
        else:
            details["redis"] = "not initialized"

        return {"status": "healthy" if all(status.values()) else "degraded", **details}


# =============================================================================
# Global singleton instance
# =============================================================================

db = Database()


# =============================================================================
# Example usage (if run directly)
# =============================================================================
if __name__ == "__main__":
    import asyncio

    async def test():
        await db.initialize()
        # test fetch
        df = await db.fetch_training_data(hours=1)
        print(df.head())
        # test recent packets
        packets = await db.get_recent_packets(minutes=10)
        print(f"Got {len(packets)} packets from Redis")
        await db.close()

    asyncio.run(test())