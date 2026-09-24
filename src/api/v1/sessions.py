from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from src.core.errors import AegisError
from src.core.security import decode_access_token

router = APIRouter()


@router.websocket("/api/v1/sessions/stream")
async def stream(websocket: WebSocket) -> None:
    await websocket.accept()
    token = websocket.query_params.get("access_token", "")
    header = websocket.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        token = header.split(" ", 1)[1].strip()
    try:
        claims = decode_access_token(websocket.app.state.settings.aegis_jwt_secret, token)
        if await websocket.app.state.revocation.is_revoked(claims["jti"], claims["family_id"]):
            raise AegisError(401, "UNAUTHORIZED", "token revoked")
    except AegisError:
        await websocket.close(code=4401)
        return
    user_id = claims["sub"]
    hub = websocket.app.state.sessions
    await hub.add(user_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await hub.discard(user_id, websocket)
