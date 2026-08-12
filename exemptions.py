#!/usr/bin/env python3
"""
Security Group Risk Dashboard — exemption management

Stores security finding exemptions locally using SQLite.

An exemption does not delete a finding. Instead, it records why the
finding is intentionally ignored and optionally when that exemption
expires.

This module is deliberately independent of AWS account/session logic so
that multi-account support can be integrated later without changing the
exemption storage model.
"""

import hashlib
import os
import sqlite3
from datetime import datetime, timezone


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get(
    "EXEMPTIONS_DB_PATH",
    os.path.join(BASE_DIR, "exemptions.db"),
)


def _utc_now():
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _get_connection():
    """Create a SQLite connection and initialize the database."""
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS exemptions (
            finding_key TEXT PRIMARY KEY,
            account_id TEXT,
            account_name TEXT,
            region TEXT NOT NULL,
            sg_id TEXT NOT NULL,
            sg_name TEXT,
            title TEXT,
            severity TEXT,
            port INTEGER,
            reason TEXT NOT NULL,
            expires_at TEXT,
            source TEXT NOT NULL DEFAULT 'manual',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    return connection


def build_finding_key(finding):
    """
    Build a stable identifier for a finding.

    Account and region are included so the same Security Group ID in
    different AWS accounts/regions does not collide.
    """

    parts = [
        str(finding.get("account_id") or ""),
        str(finding.get("region") or ""),
        str(finding.get("sg_id") or ""),
        str(finding.get("title") or ""),
        str(finding.get("port") or ""),
    ]

    raw_key = "|".join(parts)

    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def save_exemption(
    finding,
    reason,
    expires_at=None,
    source="manual",
):
    """
    Create or update an exemption for a finding.

    reason is mandatory because an exemption without a documented reason
    should not be allowed.
    """

    if not reason or not reason.strip():
        raise ValueError("Exemption reason is required.")

    finding_key = build_finding_key(finding)
    now = _utc_now()

    connection = _get_connection()

    try:
        connection.execute(
            """
            INSERT INTO exemptions (
                finding_key,
                account_id,
                account_name,
                region,
                sg_id,
                sg_name,
                title,
                severity,
                port,
                reason,
                expires_at,
                source,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_key)
            DO UPDATE SET
                account_id = excluded.account_id,
                account_name = excluded.account_name,
                region = excluded.region,
                sg_id = excluded.sg_id,
                sg_name = excluded.sg_name,
                title = excluded.title,
                severity = excluded.severity,
                port = excluded.port,
                reason = excluded.reason,
                expires_at = excluded.expires_at,
                source = excluded.source,
                updated_at = excluded.updated_at
            """,
            (
                finding_key,
                finding.get("account_id"),
                finding.get("account_name"),
                finding.get("region", ""),
                finding.get("sg_id", ""),
                finding.get("sg_name"),
                finding.get("title"),
                finding.get("severity"),
                finding.get("port"),
                reason.strip(),
                expires_at,
                source,
                now,
                now,
            ),
        )

        connection.commit()

    finally:
        connection.close()

    return finding_key


def remove_exemption(finding):
    """Remove an exemption from a finding."""

    finding_key = build_finding_key(finding)

    connection = _get_connection()

    try:
        cursor = connection.execute(
            "DELETE FROM exemptions WHERE finding_key = ?",
            (finding_key,),
        )

        connection.commit()

        return cursor.rowcount > 0

    finally:
        connection.close()


def get_exemption(finding):
    """
    Return the active exemption for a finding.

    Expired exemptions are not considered active.
    """

    finding_key = build_finding_key(finding)

    connection = _get_connection()

    try:
        row = connection.execute(
            """
            SELECT *
            FROM exemptions
            WHERE finding_key = ?
            """,
            (finding_key,),
        ).fetchone()

    finally:
        connection.close()

    if row is None:
        return None

    exemption = dict(row)

    expires_at = exemption.get("expires_at")

    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at)
            now = datetime.now(timezone.utc)

            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            if expiry <= now:
                return None

        except ValueError:
            # Invalid expiration dates should not silently exempt a finding.
            return None

    return exemption


def apply_exemption(finding):
    """
    Add exemption information to a finding.

    The original finding remains intact.
    """

    exemption = get_exemption(finding)

    if exemption is None:
        finding["exempted"] = False
        finding["status"] = "ACTIVE"
        finding["exemption_reason"] = None
        finding["exemption_expires"] = None
        finding["exemption_source"] = None
        return finding

    finding["exempted"] = True
    finding["status"] = "EXEMPTED"
    finding["exemption_reason"] = exemption["reason"]
    finding["exemption_expires"] = exemption["expires_at"]
    finding["exemption_source"] = exemption["source"]

    return finding


def list_exemptions():
    """Return all stored exemptions for audit/review purposes."""

    connection = _get_connection()

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM exemptions
            ORDER BY updated_at DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
