import asyncio
from collections import defaultdict


class LiveSessions:
    def __init__(self) -> None:
        self._sockets: dict[str, set] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def add(self, user_id: str, socket) -> None:
        async with self._lock:
            self._sockets[user_id].add(socket)

    async def discard(self, user_id: str, socket) -> None:
        async with self._lock:
            self._sockets[user_id].discard(socket)
            if not self._sockets[user_id]:
                self._sockets.pop(user_id, None)

    async def close_user(self, user_id: str, reason: str) -> None:
        async with self._lock:
            sockets = list(self._sockets.pop(user_id, ()))
        for socket in sockets:
            await socket.close(code=4401, reason=reason[:120])
