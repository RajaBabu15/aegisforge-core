from typing import Any


class RevocationStore:
    def __init__(self, redis: Any, access_ttl_seconds: int, family_ttl_seconds: int) -> None:
        self.redis = redis
        self.access_ttl_seconds = access_ttl_seconds
        self.family_ttl_seconds = family_ttl_seconds

    async def remember_access(self, user_id: str, jti: str) -> None:
        key = f"af:user:access:{user_id}"
        pipe = self.redis.pipeline()
        pipe.sadd(key, jti)
        pipe.expire(key, self.family_ttl_seconds)
        await pipe.execute()

    async def is_revoked(self, jti: str, family_id: str) -> bool:
        pipe = self.redis.pipeline()
        pipe.exists(f"af:family:revoked:{family_id}")
        pipe.exists(f"af:access:revoked:{jti}")
        family_hit, access_hit = await pipe.execute()
        return bool(family_hit or access_hit)

    async def revoke_families(self, user_id: str, family_ids: list[str], reason: str) -> None:
        del reason
        access_key = f"af:user:access:{user_id}"
        pipe = self.redis.pipeline()
        for family_id in family_ids:
            pipe.set(f"af:family:revoked:{family_id}", "1", ex=self.family_ttl_seconds)
        await pipe.execute()
        await self._drain_access_set(access_key)

    async def _drain_access_set(self, access_key: str) -> None:
        while True:
            member = await self.redis.spop(access_key)
            if member is None:
                return
            jti = member.decode() if isinstance(member, bytes) else member
            await self.redis.set(f"af:access:revoked:{jti}", "1", ex=self.access_ttl_seconds)
