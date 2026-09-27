"""Advanced feature engineering for WAF ML analysis.

Extracts 50+ features from payloads, responses, and context.
All feature computation is centralized here — single source of truth
for both training and inference (prevents training-serving skew).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

import numpy as np

# ============================================================================
# Attack pattern dictionaries — scored by severity
# ============================================================================

XSS_PATTERNS: list[tuple[str, float]] = [
    (r"<script", 3.0), (r"onerror\s*=", 2.5), (r"onload\s*=", 2.5),
    (r"onclick\s*=", 2.0), (r"onmouse\w+\s*=", 2.0), (r"onfocus\s*=", 2.0),
    (r"alert\s*\(", 2.0), (r"prompt\s*\(", 2.0), (r"confirm\s*\(", 2.0),
    (r"document\.\w+", 2.0), (r"window\.\w+", 1.5), (r"javascript:", 3.0),
    (r"<img\s", 1.5), (r"<svg[\s/>]", 1.5), (r"<iframe", 2.5),
    (r"eval\s*\(", 2.5), (r"fromCharCode", 2.0), (r"innerHTML", 2.0),
    (r"String\.fromCharCode", 2.5), (r"atob\s*\(", 1.5),
    (r"constructor\s*\(", 2.0), (r"__proto__", 2.0),
]

SQLI_PATTERNS: list[tuple[str, float]] = [
    (r"union\s+select", 3.0), (r"union\s+all\s+select", 3.0),
    (r"or\s+\d+=\d+", 2.0), (r"'\s*or\s+", 2.0), (r"'\s*and\s+", 2.0),
    (r"information_schema", 3.0), (r"sleep\s*\(", 2.5), (r"benchmark\s*\(", 2.5),
    (r"waitfor\s+delay", 3.0), (r"pg_sleep", 2.5),
    (r";\s*drop\s", 3.0), (r";\s*delete\s", 2.5), (r";\s*update\s", 2.5),
    (r"exec\s*\(", 2.0), (r"xp_cmdshell", 3.0),
    (r"load_file\s*\(", 2.5), (r"into\s+outfile", 3.0),
    (r"group\s+by\s+\d", 1.5), (r"order\s+by\s+\d", 1.5),
    (r"having\s+\d", 1.5), (r"extractvalue\s*\(", 2.0),
]

RCE_PATTERNS: list[tuple[str, float]] = [
    (r"/etc/passwd", 3.0), (r"/etc/shadow", 3.0),
    (r"/bin/(sh|bash|cat|nc|wget|curl)", 3.0), (r"cmd\.exe", 3.0),
    (r";\s*(ls|cat|id|whoami|uname)", 2.5), (r"\|\s*(ls|cat|id|whoami)", 2.5),
    (r"`[^`]+`", 2.0), (r"\$\([^)]+\)", 2.0),
    (r"ping\s+-[nc]\s+", 1.5), (r"curl\s+\S+", 1.5), (r"wget\s+\S+", 1.5),
    (r"\$\{jndi:", 3.0), (r"Runtime\.getRuntime", 3.0),
    (r"ProcessBuilder", 2.5), (r"os\.system\s*\(", 2.5),
]

LFI_PATTERNS: list[tuple[str, float]] = [
    (r"\.\.\/\.\.\/", 3.0), (r"\.\.\\\.\.\\", 3.0),
    (r"/etc/(passwd|shadow|hosts)", 3.0), (r"c:\\\\windows", 2.5),
    (r"file:\/\/", 2.5), (r"php:\/\/filter", 3.0), (r"php:\/\/input", 3.0),
    (r"data:\/\/text", 2.0), (r"expect:\/\/", 2.5),
    (r"\.\.%2f", 2.0), (r"\.\.%5c", 2.0), (r"%2e%2e", 2.0),
]

XXE_PATTERNS: list[tuple[str, float]] = [
    (r"<!ENTITY", 3.0), (r"SYSTEM\s+[\"']file:", 3.0),
    (r"<!DOCTYPE", 2.0), (r"SYSTEM\s+[\"']http", 2.5),
]

SSTI_PATTERNS: list[tuple[str, float]] = [
    (r"\{\{.*\}\}", 2.5), (r"\{%.*%\}", 2.5), (r"\$\{.*\}", 2.0),
    (r"__class__", 3.0), (r"__mro__", 3.0), (r"__subclasses__", 3.0),
    (r"__globals__", 3.0), (r"__builtins__", 3.0),
]

# Encoder/placeholder mappings for one-hot encoding
ENCODER_MAP: dict[str, int] = {
    "Plain": 0, "URL": 1, "Base64": 2, "JSUnicode": 3,
    "XMLEntity": 4, "Base64Flat": 5,
}

PLACEHOLDER_MAP: dict[str, int] = {
    "URLParam": 0, "Header": 1, "RequestBody": 2, "JSONBody": 3,
    "JSONRequest": 4, "XMLBody": 5, "SOAPBody": 6, "HTMLForm": 7,
    "HTMLMultipartForm": 8, "URLPath": 9, "UserAgent": 10,
    "RawRequest": 11, "GraphQL": 12, "gRPC": 13,
}

# Feature vector dimension
PAYLOAD_FEATURE_DIM = 52
RESPONSE_FEATURE_DIM = 20
TOTAL_FEATURE_DIM = PAYLOAD_FEATURE_DIM + RESPONSE_FEATURE_DIM


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _byte_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    counts = np.zeros(256, dtype=np.float64)
    for b in data:
        counts[b] += 1.0
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def _score_patterns(text: str, patterns: list[tuple[str, float]]) -> float:
    """Score text against pattern list, normalized to 0-1."""
    if not text:
        return 0.0
    total = 0.0
    max_possible = sum(w for _, w in patterns)
    for pattern, weight in patterns:
        if re.search(pattern, text, re.I):
            total += weight
    return total / max_possible if max_possible > 0 else 0.0


def _case_mixing_score(text: str) -> float:
    """Measure case alternation frequency (evasion technique indicator)."""
    if not text:
        return 0.0
    alpha_chars = [c for c in text if c.isalpha()]
    if len(alpha_chars) < 2:
        return 0.0
    transitions = sum(
        1 for i in range(1, len(alpha_chars))
        if alpha_chars[i].isupper() != alpha_chars[i - 1].isupper()
    )
    return transitions / (len(alpha_chars) - 1)


def _jaccard_similarity(a: bytes, b: bytes, shingle_size: int = 8) -> float:
    """Jaccard similarity between two byte sequences using shingling."""
    if not a or not b:
        return 0.0
    sa = {a[i:i + shingle_size] for i in range(max(1, len(a) - shingle_size + 1))}
    sb = {b[i:i + shingle_size] for i in range(max(1, len(b) - shingle_size + 1))}
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union > 0 else 0.0


def extract_payload_features(
    payload: str,
    encoder_name: str = "Plain",
    placeholder_name: str = "URLParam",
) -> np.ndarray:
    """Extract 52-dimensional feature vector from a payload.

    Features are grouped:
        [0-6]   Character composition ratios
        [7-8]   Length and entropy
        [9-19]  Structural boolean indicators
        [20-25] Attack type scores (0-1 normalized)
        [26-31] Evasion technique indicators
        [32-37] Encoder one-hot (6 values)
        [38-51] Placeholder one-hot (14 values)

    All features are deterministic — same input always produces same output.
    """
    f = np.zeros(PAYLOAD_FEATURE_DIM, dtype=np.float64)

    n = len(payload)
    if n == 0:
        # Still set encoder/placeholder one-hot
        enc_idx = ENCODER_MAP.get(encoder_name, 0)
        f[32 + enc_idx] = 1.0
        ph_idx = PLACEHOLDER_MAP.get(placeholder_name, 0)
        f[38 + ph_idx] = 1.0
        return f

    # [0-6] Character composition
    f[0] = sum(1 for c in payload if c.isalpha()) / n
    f[1] = sum(1 for c in payload if c.isdigit()) / n
    f[2] = sum(1 for c in payload if not c.isalnum() and not c.isspace()) / n
    f[3] = sum(1 for c in payload if c.isspace()) / n
    f[4] = sum(1 for c in payload if c.isupper()) / max(1, sum(1 for c in payload if c.isalpha()))
    f[5] = sum(1 for c in payload if c in '<>(){}[]') / n
    f[6] = sum(1 for c in payload if ord(c) > 127) / n  # Non-ASCII ratio

    # [7-8] Length and entropy
    f[7] = min(n / 10000.0, 1.0)  # Normalized length (cap at 10K)
    f[8] = _shannon_entropy(payload) / 8.0  # Normalized entropy (max ~8 bits)

    # [9-19] Structural indicators
    pl = payload.lower()
    f[9] = 1.0 if re.search(r"<[a-z]", pl) else 0.0  # HTML tags
    f[10] = 1.0 if "<script" in pl else 0.0
    f[11] = 1.0 if re.search(r"\b(select|union|insert|update|delete|drop|exec)\b", pl) else 0.0
    f[12] = 1.0 if ("../" in payload or "..\\" in payload) else 0.0
    f[13] = 1.0 if re.search(r"[;|`$]", payload) else 0.0  # Command chars
    f[14] = 1.0 if re.search(r"%[0-9a-fA-F]{2}", payload) else 0.0  # URL encoding
    f[15] = 1.0 if "\\u" in payload else 0.0  # Unicode escapes
    f[16] = 1.0 if ("\x00" in payload or "\\0" in payload) else 0.0  # Null bytes
    f[17] = 1.0 if ("/*" in payload or "--" in payload) else 0.0  # Comments
    f[18] = 1.0 if re.search(r"<!ENTITY|<!DOCTYPE", payload, re.I) else 0.0  # XML entities
    f[19] = 1.0 if ("{{" in payload or "{%" in payload) else 0.0  # Template syntax

    # [20-25] Attack type scores
    f[20] = _score_patterns(payload, XSS_PATTERNS)
    f[21] = _score_patterns(payload, SQLI_PATTERNS)
    f[22] = _score_patterns(payload, RCE_PATTERNS)
    f[23] = _score_patterns(payload, LFI_PATTERNS)
    f[24] = _score_patterns(payload, XXE_PATTERNS)
    f[25] = _score_patterns(payload, SSTI_PATTERNS)

    # [26-31] Evasion technique indicators
    f[26] = _case_mixing_score(payload)
    f[27] = min(1.0, payload.count("<x>") / max(1, n) * 10)  # Tag fragmentation (capped)
    f[28] = min(payload.count("%") / max(1, n) * 10, 1.0)  # Encoding density
    f[29] = 1.0 if re.search(r"&#x?[0-9a-fA-F]+;", payload) else 0.0  # HTML entities
    f[30] = 1.0 if re.search(r"\\x[0-9a-fA-F]{2}", payload) else 0.0  # Hex escapes
    # Combined obfuscation score
    f[31] = min(1.0, (f[14] + f[15] + f[26] + f[27] + f[29] + f[30]) / 6.0)

    # [32-37] Encoder one-hot (handle encoding chains like "URL+Base64")
    if "+" in encoder_name:
        # For chains, set bits for ALL stages (multi-hot encoding)
        for stage in encoder_name.split("+"):
            enc_idx = ENCODER_MAP.get(stage.strip(), -1)
            if 0 <= enc_idx <= 5:
                f[32 + enc_idx] = 1.0
    else:
        enc_idx = ENCODER_MAP.get(encoder_name, -1)
        if 0 <= enc_idx <= 5:
            f[32 + enc_idx] = 1.0

    # [38-51] Placeholder one-hot
    ph_idx = PLACEHOLDER_MAP.get(placeholder_name, -1)
    if 0 <= ph_idx <= 13:
        f[38 + ph_idx] = 1.0

    return f


def extract_response_features(
    status_code: int,
    headers: dict[str, list[str]],
    body: bytes,
    baseline_status: int = 200,
    baseline_body: bytes = b"",
) -> np.ndarray:
    """Extract 20-dimensional feature vector from an HTTP response.

    Features:
        [0]     Status code (normalized)
        [1]     Content length (log-scaled)
        [2-5]   Content type indicators
        [6-9]   Server type indicators
        [10-11] WAF/bot signature counts
        [12-14] Body content indicators
        [15]    Body entropy
        [16-19] Baseline comparison features
    """
    f = np.zeros(RESPONSE_FEATURE_DIM, dtype=np.float64)

    # [0] Status code normalized
    f[0] = status_code / 600.0

    # [1] Content length (log-scaled, capped)
    f[1] = min(math.log1p(len(body)) / 15.0, 1.0)

    # [2-5] Content type
    ct_values = headers.get("content-type", headers.get("Content-Type", []))
    ct = ct_values[0].lower() if ct_values else ""
    f[2] = 1.0 if "html" in ct else 0.0
    f[3] = 1.0 if "json" in ct else 0.0
    f[4] = 1.0 if "xml" in ct else 0.0
    f[5] = 1.0 if "text/plain" in ct else 0.0

    # [6-9] Server type
    server_values = headers.get("server", headers.get("Server", []))
    server = server_values[0].lower() if server_values else ""
    f[6] = 1.0 if "cloudflare" in server else 0.0
    f[7] = 1.0 if "nginx" in server else 0.0
    f[8] = 1.0 if "apache" in server else 0.0
    f[9] = 1.0 if server else 0.0

    # [10-11] Signature counts
    body_text = body.decode("utf-8", errors="replace").lower()
    waf_sigs = [
        r"access\s*denied", r"forbidden", r"blocked", r"request\s*rejected",
        r"security\s*violation", r"attack\s*detected", r"error\s*1020",
        r"attention\s*required", r"modsecurity", r"cloudflare",
    ]
    bot_sigs = [
        r"captcha", r"challenge", r"robot", r"verify.*human",
        r"javascript.*required", r"sgcaptcha", r"recaptcha",
    ]
    f[10] = min(sum(1.0 for s in waf_sigs if re.search(s, body_text)) / len(waf_sigs), 1.0)
    f[11] = min(sum(1.0 for s in bot_sigs if re.search(s, body_text)) / len(bot_sigs), 1.0)

    # [12-14] Body indicators
    f[12] = 1.0 if "<form" in body_text else 0.0
    f[13] = 1.0 if "<script" in body_text else 0.0
    f[14] = _byte_entropy(body) / 8.0 if body else 0.0

    # [15] Body word count (normalized)
    f[15] = min(len(body_text.split()) / 5000.0, 1.0)

    # [16-19] Baseline comparison
    f[16] = 1.0 if status_code == baseline_status else 0.0
    f[17] = len(body) / max(len(baseline_body), 1) if baseline_body else 0.0
    f[17] = min(f[17], 5.0) / 5.0  # Cap and normalize
    f[18] = _jaccard_similarity(body, baseline_body) if baseline_body else 0.0
    f[19] = 1.0 if abs(len(body) - len(baseline_body)) < 100 else 0.0

    return f


PAYLOAD_FEATURE_NAMES: list[str] = [
    "alpha_ratio", "digit_ratio", "special_ratio", "space_ratio",
    "upper_ratio", "bracket_ratio", "nonascii_ratio",
    "norm_length", "norm_entropy",
    "has_html_tags", "has_script", "has_sql_kw", "has_path_trav",
    "has_cmd_chars", "has_url_enc", "has_unicode_esc", "has_null_bytes",
    "has_comments", "has_xml_entity", "has_template",
    "xss_score", "sqli_score", "rce_score", "lfi_score", "xxe_score", "ssti_score",
    "case_mix", "tag_frag", "enc_density", "html_entities", "hex_escapes", "obfuscation",
    "enc_plain", "enc_url", "enc_b64", "enc_jsunicode", "enc_xmlentity", "enc_b64flat",
    "ph_urlparam", "ph_header", "ph_reqbody", "ph_jsonbody", "ph_jsonreq",
    "ph_xmlbody", "ph_soapbody", "ph_htmlform", "ph_multipart", "ph_urlpath",
    "ph_useragent", "ph_rawrequest", "ph_graphql", "ph_grpc",
]

RESPONSE_FEATURE_NAMES: list[str] = [
    "status_norm", "content_len_log", "ct_html", "ct_json", "ct_xml", "ct_text",
    "srv_cloudflare", "srv_nginx", "srv_apache", "srv_present",
    "waf_sig_score", "bot_sig_score",
    "has_form", "has_script_body", "body_entropy", "word_count_norm",
    "status_match_base", "size_ratio_base", "jaccard_base", "size_close_base",
]
