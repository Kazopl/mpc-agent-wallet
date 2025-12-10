"""Storage module for key shares."""

from abc import ABC, abstractmethod
from typing import Protocol
import json
import hashlib
import base64
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ..keygen import KeyShare


class KeyShareStore(Protocol):
    """Protocol for key share storage backends."""

    def store(self, share_id: str, share: KeyShare, password: str) -> None:
        """Store a key share."""
        ...

    def load(self, share_id: str, password: str) -> KeyShare:
        """Load a key share."""
        ...

    def delete(self, share_id: str) -> bool:
        """Delete a key share."""
        ...

    def exists(self, share_id: str) -> bool:
        """Check if a share exists."""
        ...

    def list_shares(self) -> list[str]:
        """List all share IDs."""
        ...


class MemoryStore:
    """In-memory store for testing."""

    def __init__(self) -> None:
        self._shares: dict[str, tuple[str, str]] = {}  # id -> (encrypted, salt)

    def store(self, share_id: str, share: KeyShare, password: str) -> None:
        """Store a key share."""
        salt = secrets.token_hex(32)
        encrypted = _encrypt(json.dumps(share.__dict__), password, salt)
        self._shares[share_id] = (encrypted, salt)

    def load(self, share_id: str, password: str) -> KeyShare:
        """Load a key share."""
        if share_id not in self._shares:
            raise KeyError(f"Share not found: {share_id}")
        encrypted, salt = self._shares[share_id]
        data = json.loads(_decrypt(encrypted, password, salt))
        return KeyShare(**data)

    def delete(self, share_id: str) -> bool:
        """Delete a key share."""
        if share_id in self._shares:
            del self._shares[share_id]
            return True
        return False

    def exists(self, share_id: str) -> bool:
        """Check if a share exists."""
        return share_id in self._shares

    def list_shares(self) -> list[str]:
        """List all share IDs."""
        return list(self._shares.keys())

    def clear(self) -> None:
        """Clear all shares."""
        self._shares.clear()


class FileSystemStore:
    """File system store for key shares."""

    def __init__(self, base_path: str | Path) -> None:
        self._base_path = Path(base_path)
        self._base_path.mkdir(parents=True, exist_ok=True)

    def _share_path(self, share_id: str) -> Path:
        # Sanitize ID
        safe_id = share_id.replace("/", "_").replace("\\", "_").replace(".", "_")
        return self._base_path / f"{safe_id}.share"

    def store(self, share_id: str, share: KeyShare, password: str) -> None:
        """Store a key share."""
        salt = secrets.token_hex(32)
        encrypted = _encrypt(json.dumps(share.__dict__), password, salt)

        path = self._share_path(share_id)
        path.write_text(json.dumps({"encrypted": encrypted, "salt": salt}))

        # Set restrictive permissions
        try:
            path.chmod(0o600)
        except (OSError, AttributeError):
            pass  # Windows doesn't support chmod

    def load(self, share_id: str, password: str) -> KeyShare:
        """Load a key share."""
        path = self._share_path(share_id)
        if not path.exists():
            raise KeyError(f"Share not found: {share_id}")

        data = json.loads(path.read_text())
        decrypted = _decrypt(data["encrypted"], password, data["salt"])
        return KeyShare(**json.loads(decrypted))

    def delete(self, share_id: str) -> bool:
        """Delete a key share."""
        path = self._share_path(share_id)
        if path.exists():
            # Overwrite with zeros before deleting
            size = path.stat().st_size
            path.write_bytes(b"\x00" * size)
            path.unlink()
            return True
        return False

    def exists(self, share_id: str) -> bool:
        """Check if a share exists."""
        return self._share_path(share_id).exists()

    def list_shares(self) -> list[str]:
        """List all share IDs."""
        return [p.stem for p in self._base_path.glob("*.share")]


def _encrypt(data: str, password: str, salt: str) -> str:
    """Encrypt data with password."""
    salt_bytes = bytes.fromhex(salt)
    nonce = secrets.token_bytes(12)

    # Derive key
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100000, dklen=32)

    # Encrypt
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, data.encode(), None)

    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt(encrypted: str, password: str, salt: str) -> str:
    """Decrypt data with password."""
    salt_bytes = bytes.fromhex(salt)
    data = base64.b64decode(encrypted)
    nonce = data[:12]
    ciphertext = data[12:]

    # Derive key
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt_bytes, 100000, dklen=32)

    # Decrypt
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None).decode()


def create_backup(shares: list[KeyShare], password: str) -> str:
    """Create a backup of multiple shares."""
    import time

    salt = secrets.token_hex(32)
    data = json.dumps([s.__dict__ for s in shares])
    encrypted = _encrypt(data, password, salt)

    return json.dumps({
        "version": 1,
        "created_at": int(time.time()),
        "share_count": len(shares),
        "salt": salt,
        "encrypted": encrypted,
    })


def restore_backup(backup: str, password: str) -> list[KeyShare]:
    """Restore shares from a backup."""
    data = json.loads(backup)
    decrypted = _decrypt(data["encrypted"], password, data["salt"])
    return [KeyShare(**s) for s in json.loads(decrypted)]


__all__ = [
    "KeyShareStore",
    "MemoryStore",
    "FileSystemStore",
    "create_backup",
    "restore_backup",
]
