import time
import uuid

from src.core.errors import AegisError
from src.services.telemetry import RATE_LIMITED

_WINDOW_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local count = redis.call('ZCARD', key)
if count >= limit then
  redis.call('EXPIRE', key, math.ceil(window))
  return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window))
return 1
"""


async def enforce_rate_limit(redis, *, key: str, limit: int, window_seconds: int = 60) -> None:
    now = time.time()
    member = f"{now:.6f}:{uuid.uuid4().hex}"
    allowed = await redis.eval(_WINDOW_SCRIPT, 1, key, now, window_seconds, limit, member)
    if int(allowed) != 1:
        RATE_LIMITED.labels(bucket=key.split(":")[2] if key.count(":") >= 2 else "unknown").inc()
        raise AegisError(429, "RATE_LIMITED", "too many requests")
