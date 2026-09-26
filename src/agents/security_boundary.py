"""Reference security boundary for the Day 11 Guards Agent.

This is deliberately framework-independent so students can inspect the policy
and reason about the difference between untrusted content and an authorised
action. It is not a solution for the TODOs in ``src/assignment``.
"""
from __future__ import annotations

import re
import unicodedata
import base64
import binascii
import hashlib
import html
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse, unquote

from core.config import load_protected_payload


TRUSTED_EGRESS_HOSTS = frozenset({"api.vinbank.example", "cases.vinbank.example"})
HIGH_RISK_ACTIONS = frozenset({
    "transfer_money", "close_account", "change_password",
    "delete_data", "update_personal_info",
})
ALLOWED_ACTIONS = HIGH_RISK_ACTIONS | frozenset({
    "read_balance", "lookup_account", "create_case",
})
SECRET_PATTERNS = (
    r"\badmin123\b",
    r"sk-[a-z0-9-]{8,}",
    r"db\.vinbank\.internal(?::\d+)?",
    r"(?:password|mật\s*khẩu)\s*[:=]\s*\S+",
)
PII_PATTERNS = (
    r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b",
    r"(?<!\d)(?:\+84|0)(?:\d[ .-]?){8,9}\d(?!\d)",
    r"(?<!\d)(?:\d{9}|\d{12})(?!\d)",
)
INSTRUCTION_OVERRIDE_PATTERNS = (
    r"ignore\s+(?:all\s+)?(?:previous|above|prior)?\s*instructions?",
    r"(?:system|developer)\s+(?:prompt|instruction)|system\s+override",
    r"(?:reveal|disclose|translate|encode|summarize)\b.*(?:secret|password|credential|api\s*key|internal)",
    r"bỏ\s+qua\s+(?:mọi\s+)?hướng\s+dẫn|tiết\s+lộ\s+(?:mật\s*khẩu|api|thông\s*tin\s*nội\s*bộ)",
)


@dataclass(frozen=True)
class ExternalContent:
    """Data retrieved from email/RAG/web; never an instruction authority."""

    source: str
    text: str
    trusted: bool = False


@dataclass(frozen=True)
class ActionRequest:
    """A proposed side effect awaiting deterministic policy and human approval."""

    action: str
    destination: str
    payload: str
    approval_id: str | None = None
    reviewer_id: str | None = None


@dataclass(frozen=True)
class ActionDecision:
    allowed: bool
    reason: str
    requires_human: bool


@dataclass(frozen=True)
class VerifiedApproval:
    """Approval supplied by a trusted HITL store, bound to one exact action."""

    approval_id: str
    reviewer_id: str
    action: str
    destination: str
    payload_sha256: str


def normalize_for_security(text: str) -> str:
    """Canonicalize Unicode and remove invisible separators before policy checks."""
    normalized = unicodedata.normalize("NFKC", text or "")
    return "".join(ch for ch in normalized if unicodedata.category(ch) != "Cf")


def security_views(text: str) -> set[str]:
    """Bounded decoding of common textual encodings used to hide lab secrets."""
    raw = normalize_for_security(text)
    views = {raw}
    for _ in range(2):
        for value in tuple(views):
            views.add(normalize_for_security(unquote(html.unescape(value))))
            views.add(re.sub(
                r"\\u([0-9a-fA-F]{4})",
                lambda match: chr(int(match.group(1), 16)), value,
            ))
    for value in tuple(views):
        for token in re.findall(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])", value):
            if len(token) > 8192:
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            views.add(normalize_for_security(decoded))
        for token in re.findall(r"\b(?:[0-9a-fA-F]{2}){4,}\b", value):
            if len(token) > 8192:
                continue
            try:
                views.add(normalize_for_security(bytes.fromhex(token).decode("utf-8")))
            except (ValueError, UnicodeDecodeError):
                continue
    return views


def contains_protected_secret(text: str) -> bool:
    """Find exact demo values, including spacing and common textual encodings."""
    secrets = (load_protected_payload().get("secrets") or {}).values()
    needles = [re.sub(r"[^a-z0-9]", "", str(value).casefold()) for value in secrets if value]
    for view in security_views(text):
        flattened = re.sub(r"[^a-z0-9]", "", view.casefold())
        if any(needle and needle in flattened for needle in needles):
            return True
    return False


def contains_secret(text: str) -> bool:
    """Detect a synthetic lab secret even when punctuation/spacing is altered."""
    return contains_protected_secret(text) or any(
        re.search(pattern, view, re.IGNORECASE)
        for view in security_views(text)
        for pattern in SECRET_PATTERNS
    )


def contains_sensitive_data(text: str) -> bool:
    """Detect protected values, credentials and PII in clear or encoded text."""
    return contains_secret(text) or any(
        re.search(pattern, view, re.IGNORECASE)
        for view in security_views(text)
        for pattern in PII_PATTERNS
    )


def contains_instruction_override(text: str) -> bool:
    """Identify instruction-like text after Unicode normalization."""
    for view in security_views(text):
        normalized = re.sub(r"[-_/–—]+", " ", view)
        skeleton = re.sub(r"[^a-z0-9]", "", normalized.casefold())
        if "ignoreallpreviousinstructions" in skeleton or "ignorepreviousinstructions" in skeleton:
            return True
        if any(re.search(pattern, normalized, re.IGNORECASE)
               for pattern in INSTRUCTION_OVERRIDE_PATTERNS):
            return True
    return False


def assess_external_content(content: ExternalContent) -> ActionDecision:
    """Treat third-party content as data and reject attempts to change policy."""
    if contains_instruction_override(content.text):
        return ActionDecision(False, "untrusted content contains an instruction override", False)
    return ActionDecision(True, "content is data only", False)


def authorize_action(
    request: ActionRequest,
    *,
    verified_approvals: Mapping[str, VerifiedApproval] | None = None,
) -> ActionDecision:
    """Enforce exact destination allowlist, secret egress block and HITL for risk."""
    if request.action not in ALLOWED_ACTIONS:
        return ActionDecision(False, "action is not allowlisted", False)
    try:
        destination = urlparse(request.destination)
        destination_ok = (destination.scheme == "https" and destination.hostname in TRUSTED_EGRESS_HOSTS
                          and not destination.username and not destination.password
                          and destination.port in (None, 443))
    except ValueError:
        destination_ok = False
    if not destination_ok:
        return ActionDecision(False, "destination is not allowlisted", False)
    if contains_sensitive_data(request.payload) or contains_sensitive_data(request.destination):
        return ActionDecision(False, "outbound request contains sensitive data", False)
    if request.action in HIGH_RISK_ACTIONS:
        approval = (verified_approvals or {}).get(request.approval_id or "")
        approved = bool(approval and request.approval_id and request.reviewer_id
                        and re.fullmatch(r"HITL-[A-Z0-9]{8}", request.approval_id)
                        and approval == VerifiedApproval(
                            approval_id=request.approval_id,
                            reviewer_id=request.reviewer_id,
                            action=request.action,
                            destination=request.destination,
                            payload_sha256=hashlib.sha256(request.payload.encode("utf-8")).hexdigest(),
                        ))
        if not approved:
            return ActionDecision(False, "high-risk action needs verified human approval", True)
    return ActionDecision(True, "least-privilege policy permits this action", False)
