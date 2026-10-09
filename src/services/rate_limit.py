import time
import uuid

from src.core.errors import AegisError
from src.services.telemetry import RATE_LIMITED


async def enforce_rate_limit(redis, *, key: str, limit: int, window_seconds: int = 60) -> None:
    now = time.time()
    member = f"{now:.6f}:{uuid.uuid4().hex}"
    cutoff = now - window_seconds
    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, cutoff)
    pipe.zadd(key, {member: now})
    pipe.zcard(key)
    pipe.expire(key, window_seconds)
    _removed, _added, count, _ttl = await pipe.execute()
    if int(count) > limit:
        await redis.zrem(key, member)
        RATE_LIMITED.labels(bucket=key.split(":")[2] if key.count(":") >= 2 else "unknown").inc()
        raise AegisError(429, "RATE_LIMITED", "too many requests")
