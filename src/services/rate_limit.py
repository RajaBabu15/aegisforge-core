from src.core.errors import AegisError


async def enforce_rate_limit(redis, *, key: str, limit: int, window_seconds: int = 60) -> None:
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)
    if count > limit:
        raise AegisError(429, "RATE_LIMITED", "too many requests")
