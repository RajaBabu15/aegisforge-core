import pytest
from pydantic import ValidationError

from src.core.config import Settings
from src.main import create_app


def test_short_secret_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            aegis_jwt_secret="short",
            aegis_approval_secret="y" * 32,
        )


def test_create_app_requires_secret(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.delenv("AEGIS_JWT_SECRET", raising=False)
    monkeypatch.delenv("AEGIS_APPROVAL_SECRET", raising=False)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValidationError):
        create_app()
