# =============================================================================
# CyberToolkit Pro — Hash Cracker
# =============================================================================
# Dictionary-based hash cracking for MD5, SHA1, and SHA256 hashes.
# Supports single hash or hash file input. LAB USE ONLY.
# =============================================================================

import hashlib
from core.models import ToolResult, Finding, Severity

TOOL_INFO = {
    "name": "hash_cracker",
    "category": "passwords",
    "description": "Dictionary-based hash cracker (MD5, SHA1, SHA256)",
    "author": "CyberToolkit Pro",
    "version": "1.0.0",
    "args": [
        {"name": "target", "required": True, "description": "Hash to crack or path to hash file"},
        {"name": "hash_type", "required": False, "default": "auto",
         "description": "Hash type: md5, sha1, sha256, auto (detect by length)"},
        {"name": "wordlist", "required": False, "default": "",
         "description": "Path to password wordlist"},
    ],
    "tags": ["passwords", "hash", "cracking", "md5", "sha1", "sha256", "lab-only"],
}

DEFAULT_WORDLIST = [
    "admin", "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "admin123", "letmein", "welcome", "monkey", "dragon",
    "master", "login", "princess", "passw0rd", "shadow", "sunshine",
    "trustno1", "iloveyou", "batman", "access", "hello", "charlie",
    "root", "toor", "test", "guest", "secret", "changeme",
    "1234", "12345", "123456789", "1234567890", "000000", "111111",
    "666666", "888888", "987654321", "password123", "Pa$$w0rd",
]

HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def _detect_hash_type(hash_str):
    """Auto-detect hash type by length."""
    hash_str = hash_str.strip().lower()
    return HASH_LENGTHS.get(len(hash_str), "unknown")


def _crack_hash(target_hash, hash_type, wordlist):
    """Attempt to crack a single hash."""
    target_hash = target_hash.strip().lower()
    hash_funcs = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
    }

    hash_fn = hash_funcs.get(hash_type)
    if not hash_fn:
        return None

    for word in wordlist:
        computed = hash_fn(word.encode("utf-8")).hexdigest()
        if computed == target_hash:
            return word

    return None


def run(args):
    target = args.get("target", "")
    if not target:
        return ToolResult(tool_name="hash_cracker", status="error", error="No hash specified")

    hash_type = args.get("hash_type", "auto").lower()

    # Load wordlist
    wordlist = DEFAULT_WORDLIST[:]
    wordlist_path = args.get("wordlist", "")
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            pass

    # Determine if target is a file or a single hash
    hashes = []
    try:
        with open(target, "r", encoding="utf-8") as f:
            hashes = [line.strip() for line in f if line.strip()]
    except (FileNotFoundError, OSError):
        hashes = [target.strip()]

    results = []
    findings = []

    for h in hashes:
        if not h:
            continue

        # Auto-detect hash type if needed
        ht = hash_type if hash_type != "auto" else _detect_hash_type(h)
        if ht == "unknown":
            results.append({"hash": h, "type": "unknown", "cracked": False, "plaintext": ""})
            continue

        plaintext = _crack_hash(h, ht, wordlist)
        cracked = plaintext is not None

        results.append({
            "hash": h,
            "type": ht,
            "cracked": cracked,
            "plaintext": plaintext or "",
        })

        if cracked:
            findings.append(Finding(
                title=f"Hash cracked: {ht.upper()} → '{plaintext}'",
                severity=Severity.HIGH,
                description=f"The {ht.upper()} hash was cracked using a common password dictionary",
                evidence=f"Hash: {h}\nPlaintext: {plaintext}",
                remediation="Use strong, unique passwords and modern hashing (bcrypt/argon2) with salts",
            ))

    cracked_count = sum(1 for r in results if r["cracked"])

    return ToolResult(
        tool_name="hash_cracker",
        target=target,
        status="success",
        data={
            "hashes_tested": len(results),
            "hashes_cracked": cracked_count,
            "wordlist_size": len(wordlist),
            "results": results,
        },
        findings=findings,
    )
