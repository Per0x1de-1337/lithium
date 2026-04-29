from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import stable_json
from .models import ScanReport


def generate_keypair(private_path: str, public_path: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(private_path).write_bytes(private_bytes)
    Path(public_path).write_bytes(public_bytes)


def build_manifest(report: ScanReport) -> dict[str, Any]:
    return {
        "manifest_version": "1",
        "scanner": {"name": "lithium", "version": report.scanner_version},
        "rule_pack_version": report.rule_pack_version,
        "server": report.server,
        "transport": report.transport,
        "scanned_at": report.scanned_at,
        "server_hash": report.server_hash,
        "tool_hashes": report.tool_hashes,
        "risk_score": report.risk_score,
        "verdict": report.verdict,
        "findings": [finding.to_dict() for finding in report.findings],
    }


def sign_manifest(report: ScanReport, private_key_path: str) -> dict[str, Any]:
    manifest = build_manifest(report)
    private_key = _load_private_key(private_key_path)
    payload = _payload(manifest)
    signature = private_key.sign(payload)
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "value": base64.b64encode(signature).decode("ascii"),
        "public_key_pem": public_key_bytes.decode("ascii"),
    }
    return manifest


def verify_manifest_file(path: str, public_key_path: str | None = None) -> bool:
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    signature_block = manifest.get("signature")
    if not isinstance(signature_block, dict):
        return False
    value = signature_block.get("value")
    if not isinstance(value, str):
        return False
    signature = base64.b64decode(value)

    if public_key_path:
        public_key = _load_public_key(public_key_path)
    else:
        embedded = signature_block.get("public_key_pem")
        if not isinstance(embedded, str):
            return False
        public_key = serialization.load_pem_public_key(embedded.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False

    unsigned = dict(manifest)
    unsigned.pop("signature", None)
    try:
        public_key.verify(signature, _payload(unsigned))
    except InvalidSignature:
        return False
    return True


def diff_manifests(old_path: str, new_path: str) -> dict[str, Any]:
    old = json.loads(Path(old_path).read_text(encoding="utf-8"))
    new = json.loads(Path(new_path).read_text(encoding="utf-8"))
    old_hashes = dict(old.get("tool_hashes") or {})
    new_hashes = dict(new.get("tool_hashes") or {})
    old_names = set(old_hashes)
    new_names = set(new_hashes)
    changed = sorted(name for name in old_names & new_names if old_hashes[name] != new_hashes[name])
    return {
        "old_server_hash": old.get("server_hash"),
        "new_server_hash": new.get("server_hash"),
        "server_hash_changed": old.get("server_hash") != new.get("server_hash"),
        "added_tools": sorted(new_names - old_names),
        "removed_tools": sorted(old_names - new_names),
        "changed_tools": changed,
        "old_verdict": old.get("verdict"),
        "new_verdict": new.get("verdict"),
    }


def _payload(manifest: dict[str, Any]) -> bytes:
    return stable_json(manifest).encode("utf-8")


def _load_private_key(path: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key must be Ed25519")
    return key


def _load_public_key(path: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return key

