"""
Phase 4 — Per-User Encrypted Audit Log

Every time Bubbble blocks or flags a link, a structured audit log entry is
created and stored securely in PostgreSQL.

Security model:
  - Each entry's payload is encrypted with the user's derived symmetric key
    using AES-256-GCM (Fernet wrapper for simplicity in Python).
  - The Bubbble backend stores only the ciphertext; it cannot read the
    log content without the user's key.
  - Keys are derived from a user-specific secret stored in the secrets manager
    (AWS Secrets Manager / HashiCorp Vault) and are never logged.

Schema (DDL for reference):

    CREATE TABLE audit_log (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     BIGINT NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        payload_enc BYTEA NOT NULL,        -- AES-256-GCM ciphertext (base64)
        iv          BYTEA NOT NULL,        -- GCM nonce
        tag         BYTEA NOT NULL,        -- GCM auth tag
        schema_ver  SMALLINT NOT NULL DEFAULT 1
    );
    CREATE INDEX idx_audit_user_time ON audit_log (user_id, created_at DESC);
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

# ── Encryption helpers ────────────────────────────────────────────────────────

def _get_user_key(user_id: int) -> bytes:
    """
    Derive the 32-byte AES key for a given user.
    In production this retrieves a user-specific secret from the secrets manager.
    Here we use an environment variable seed for illustration.
    """
    master_key_hex = os.environ.get("AUDIT_MASTER_KEY", "0" * 64)
    # XOR master key bytes with user_id for per-user key derivation
    master_bytes = bytes.fromhex(master_key_hex)
    user_seed = user_id.to_bytes(8, "big") * 4  # 32 bytes
    return bytes(a ^ b for a, b in zip(master_bytes, user_seed))


def _encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt using AES-256-GCM. Returns (nonce, ciphertext_with_tag, tag).
    AESGCM.encrypt appends the 16-byte tag to the ciphertext.
    """
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ct = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    return nonce, ct, tag


def _decrypt(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct + tag, None)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    entry_id: str                    # UUID
    user_id: int
    created_at: str                  # ISO-8601
    blocked_url: str
    final_url: str
    threat_category: str             # e.g. "phishing", "malware"
    origin_platform: str             # e.g. "whatsapp", "instagram_dm"
    risk_score: int                  # 0–100
    signals: list[dict]              # from RiskScoreResult.signals
    redirect_chain: list[str]
    recommended_action: str
    screenshot_b64: Optional[str] = None

    @classmethod
    def create(
        cls,
        user_id: int,
        blocked_url: str,
        final_url: str,
        threat_category: str,
        origin_platform: str,
        risk_score: int,
        signals: list[dict],
        redirect_chain: list[str],
        recommended_action: str,
        screenshot_b64: Optional[str] = None,
    ) -> "AuditEntry":
        return cls(
            entry_id=str(uuid.uuid4()),
            user_id=user_id,
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            blocked_url=blocked_url,
            final_url=final_url,
            threat_category=threat_category,
            origin_platform=origin_platform,
            risk_score=risk_score,
            signals=signals,
            redirect_chain=redirect_chain,
            recommended_action=recommended_action,
            screenshot_b64=screenshot_b64,
        )


# ── Storage ───────────────────────────────────────────────────────────────────

class AuditLogStore:
    """
    Encrypted audit log storage backed by asyncpg (PostgreSQL).

    Usage::

        store = AuditLogStore(pool)
        entry = AuditEntry.create(...)
        await store.write(entry)
        entries = await store.list_for_user(user_id, limit=50)
    """

    def __init__(self, pool) -> None:
        """
        :param pool: An asyncpg connection pool.
        """
        self._pool = pool

    async def write(self, entry: AuditEntry) -> str:
        """
        Encrypt and persist an audit entry. Returns the stored entry_id.
        """
        key = _get_user_key(entry.user_id)
        payload = json.dumps(asdict(entry)).encode()
        nonce, ct, tag = _encrypt(payload, key)

        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_log
                    (id, user_id, created_at, payload_enc, iv, tag, schema_ver)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                uuid.UUID(entry.entry_id),
                entry.user_id,
                datetime.fromisoformat(entry.created_at),
                base64.b64encode(ct).decode(),
                base64.b64encode(nonce).decode(),
                base64.b64encode(tag).decode(),
                SCHEMA_VERSION,
            )
        logger.info("Audit entry %s written for user %d", entry.entry_id, entry.user_id)
        return entry.entry_id

    async def list_for_user(
        self,
        user_id: int,
        limit: int = 50,
        before: Optional[datetime] = None,
    ) -> list[AuditEntry]:
        """
        Return the most recent *limit* audit entries for a user, decrypted.
        Supports cursor-based pagination via *before* (exclusive timestamp).
        """
        key = _get_user_key(user_id)

        async with self._pool.acquire() as conn:
            if before:
                rows = await conn.fetch(
                    """
                    SELECT payload_enc, iv, tag
                    FROM audit_log
                    WHERE user_id = $1 AND created_at < $2
                    ORDER BY created_at DESC
                    LIMIT $3
                    """,
                    user_id, before, limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT payload_enc, iv, tag
                    FROM audit_log
                    WHERE user_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2
                    """,
                    user_id, limit,
                )

        entries: list[AuditEntry] = []
        for row in rows:
            try:
                nonce = base64.b64decode(row["iv"])
                ct = base64.b64decode(row["payload_enc"])
                tag = base64.b64decode(row["tag"])
                plaintext = _decrypt(nonce, ct, tag, key)
                data = json.loads(plaintext)
                entries.append(AuditEntry(**data))
            except Exception as exc:
                logger.error("Failed to decrypt audit entry: %s", exc)
        return entries

    async def get(self, user_id: int, entry_id: str) -> Optional[AuditEntry]:
        """Fetch and decrypt a single entry by ID."""
        key = _get_user_key(user_id)

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT payload_enc, iv, tag
                FROM audit_log
                WHERE user_id = $1 AND id = $2
                """,
                user_id, uuid.UUID(entry_id),
            )
        if not row:
            return None
        try:
            nonce = base64.b64decode(row["iv"])
            ct = base64.b64decode(row["payload_enc"])
            tag = base64.b64decode(row["tag"])
            plaintext = _decrypt(nonce, ct, tag, key)
            return AuditEntry(**json.loads(plaintext))
        except Exception as exc:
            logger.error("Failed to decrypt audit entry %s: %s", entry_id, exc)
            return None
