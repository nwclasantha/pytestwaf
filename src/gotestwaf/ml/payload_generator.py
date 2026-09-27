"""AI-powered payload generation engine.

Analyzes bypass patterns from scan results and generates NEW payloads
that are likely to bypass the WAF. Uses pattern learning, not just
static mutations.

Techniques:
1. Pattern extraction — finds what bypassed payloads have in common
2. Encoding chain discovery — finds which encoding combos bypass
3. Placement exploitation — finds which delivery methods are unprotected
4. Structural mutation — generates variations of successful bypasses
5. Cross-category transfer — applies bypass patterns from one attack type to another
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gotestwaf.db.database import DB
    from gotestwaf.db.models import Info


@dataclass
class GeneratedPayload:
    """A newly generated payload with metadata."""
    payload: str
    encoder: str
    placeholder: str
    source_payload: str = ""
    generation_technique: str = ""
    predicted_bypass_prob: float = 0.0
    attack_type: str = ""


# ── Mutation templates ──

# XSS event handlers that WAFs often miss
XSS_RARE_EVENTS = [
    "onpointerrawupdate", "onbeforetoggle", "ontransitionend",
    "onanimationstart", "onsecuritypolicyviolation", "oncontextlost",
    "onscrollend", "onslotchange", "oncontentvisibilityautostatechange",
]

# SQLi comment/whitespace alternatives
SQLI_WHITESPACE = ["/**/", "/*!*/", "%09", "%0a", "%0d", "%0b", "%a0", "/*!", "*/"]

# RCE command separators
RCE_SEPARATORS = [";", "|", "||", "&&", "\n", "`", "$(", "${"]

# Encoding transformations
ENCODING_CHAINS = [
    "URL+Base64", "Base64+URL", "URL+URL", "JSUnicode+URL",
    "URL+Base64Flat", "Base64Flat+URL",
]


def generate_ai_payloads(db: DB, max_payloads: int = 200) -> list[GeneratedPayload]:
    """Analyze scan results and generate new bypass payloads.

    This is the core AI: it learns what patterns bypass the WAF
    and generates new payloads exploiting those patterns.
    """
    generated: list[GeneratedPayload] = []

    # Analyze what bypassed vs what was blocked
    bypass_patterns = _analyze_bypass_patterns(db)

    # 1. Generate from successful bypass patterns
    generated.extend(_generate_from_patterns(bypass_patterns, max_payloads // 4))

    # 2. Generate encoding chain variants
    generated.extend(_generate_encoding_variants(db, max_payloads // 4))

    # 3. Generate cross-category payloads
    generated.extend(_generate_cross_category(db, max_payloads // 4))

    # 4. Generate structural mutations
    generated.extend(_generate_structural_mutations(db, max_payloads // 5))

    # 5. ML decision boundary exploration — perturb bypassed payloads
    generated.extend(_generate_boundary_payloads(db, max_payloads // 5))

    # Deduplicate
    seen: set[str] = set()
    unique: list[GeneratedPayload] = []
    for gp in generated:
        key = f"{gp.payload}|{gp.encoder}|{gp.placeholder}"
        if key not in seen:
            seen.add(key)
            unique.append(gp)

    return unique[:max_payloads]


@dataclass
class BypassPattern:
    """A pattern extracted from successful bypasses."""
    encoder: str = ""
    placeholder: str = ""
    bypass_count: int = 0
    block_count: int = 0
    bypass_rate: float = 0.0
    sample_payloads: list[str] = field(default_factory=list)
    attack_types: set[str] = field(default_factory=set)


def _analyze_bypass_patterns(db: DB) -> dict[str, BypassPattern]:
    """Extract patterns from what bypassed vs what was blocked."""
    combos: dict[str, BypassPattern] = {}

    for t in db.passed_tests:
        key = f"{t.encoder}|{t.placeholder}"
        if key not in combos:
            combos[key] = BypassPattern(encoder=t.encoder, placeholder=t.placeholder)
        combos[key].bypass_count += 1
        if len(combos[key].sample_payloads) < 10:
            combos[key].sample_payloads.append(t.payload)
        combos[key].attack_types.add(t.type or "unknown")

    for t in db.blocked_tests:
        key = f"{t.encoder}|{t.placeholder}"
        if key not in combos:
            combos[key] = BypassPattern(encoder=t.encoder, placeholder=t.placeholder)
        combos[key].block_count += 1

    for bp in combos.values():
        total = bp.bypass_count + bp.block_count
        bp.bypass_rate = bp.bypass_count / total if total > 0 else 0

    return combos


def _generate_from_patterns(patterns: dict[str, BypassPattern], max_count: int) -> list[GeneratedPayload]:
    """Generate payloads using encoder+placeholder combos that have high bypass rates."""
    generated: list[GeneratedPayload] = []

    # Sort by bypass rate — focus on what works
    sorted_patterns = sorted(patterns.values(), key=lambda p: -p.bypass_rate)

    for bp in sorted_patterns:
        if bp.bypass_rate < 0.1 or bp.bypass_count < 1:
            continue

        # For each successful combo, generate variations of the bypassed payloads
        for payload in bp.sample_payloads[:5]:
            mutations = _mutate_payload(payload)
            for mutated, technique in mutations:
                generated.append(GeneratedPayload(
                    payload=mutated,
                    encoder=bp.encoder,
                    placeholder=bp.placeholder,
                    source_payload=payload[:100],
                    generation_technique=technique,
                    predicted_bypass_prob=bp.bypass_rate * 0.8,
                    attack_type=next(iter(bp.attack_types), "unknown"),
                ))
                if len(generated) >= max_count:
                    return generated

    return generated


def _generate_encoding_variants(db: DB, max_count: int) -> list[GeneratedPayload]:
    """Try encoding chains on payloads that were blocked with simple encoding."""
    generated: list[GeneratedPayload] = []

    # Find payloads blocked with Plain/URL but not tested with chains
    blocked_payloads: dict[str, Info] = {}
    for t in db.blocked_tests:
        if t.encoder in ("Plain", "URL") and len(t.payload) < 2000:
            if t.payload not in blocked_payloads:
                blocked_payloads[t.payload] = t

    for payload, info in list(blocked_payloads.items())[:30]:
        for chain in ENCODING_CHAINS:
            generated.append(GeneratedPayload(
                payload=payload,
                encoder=chain,
                placeholder=info.placeholder,
                source_payload=payload[:100],
                generation_technique=f"encoding_chain_{chain}",
                predicted_bypass_prob=0.4,
                attack_type=info.type or "unknown",
            ))
            if len(generated) >= max_count:
                return generated

    return generated


def _generate_cross_category(db: DB, max_count: int) -> list[GeneratedPayload]:
    """Apply bypass patterns from one attack category to another.

    If Header placement bypasses for XSS, try Header for SQLi too.
    """
    generated: list[GeneratedPayload] = []

    # Find which placements bypass
    bypass_placements: set[str] = set()
    for t in db.passed_tests:
        bypass_placements.add(t.placeholder)

    # Find blocked payloads not tested with bypass placements
    for t in db.blocked_tests:
        if t.placeholder not in bypass_placements and len(t.payload) < 2000:
            for placement in bypass_placements:
                if placement not in ("gRPC", "GraphQL", "RawRequest"):
                    generated.append(GeneratedPayload(
                        payload=t.payload,
                        encoder=t.encoder,
                        placeholder=placement,
                        source_payload=t.payload[:100],
                        generation_technique=f"cross_category_{placement}",
                        predicted_bypass_prob=0.3,
                        attack_type=t.type or "unknown",
                    ))
                    if len(generated) >= max_count:
                        return generated

    return generated


def _generate_structural_mutations(db: DB, max_count: int) -> list[GeneratedPayload]:
    """Generate structural variations of bypassed payloads."""
    generated: list[GeneratedPayload] = []

    for t in db.passed_tests:
        if len(t.payload) > 2000 or len(t.payload) < 3:
            continue

        mutations = _mutate_payload(t.payload)
        for mutated, technique in mutations[:3]:
            generated.append(GeneratedPayload(
                payload=mutated,
                encoder=t.encoder,
                placeholder=t.placeholder,
                source_payload=t.payload[:100],
                generation_technique=technique,
                predicted_bypass_prob=0.5,
                attack_type=t.type or "unknown",
            ))
            if len(generated) >= max_count:
                return generated

    return generated


def _mutate_payload(payload: str) -> list[tuple[str, str]]:
    """Generate structural mutations of a single payload."""
    mutations: list[tuple[str, str]] = []
    pl = payload

    # 1. Case randomization
    randomized = "".join(
        c.upper() if random.random() > 0.5 else c.lower()
        for c in pl
    )
    if randomized != pl:
        mutations.append((randomized, "case_randomize"))

    # 2. Whitespace substitution (SQLi)
    for ws in random.sample(SQLI_WHITESPACE, min(3, len(SQLI_WHITESPACE))):
        if " " in pl:
            mutations.append((pl.replace(" ", ws, 1), f"whitespace_{ws[:4]}"))

    # 3. HTML tag mutation (XSS)
    if "<" in pl and ">" in pl:
        # Add junk attributes
        mutations.append((re.sub(r"<(\w+)", r"<\1/x=1", pl, count=1), "junk_attr"))
        # Tab/newline in tag
        mutations.append((re.sub(r"<(\w+)", r"<\1\t", pl, count=1), "tab_in_tag"))

    # 4. Rare event handler substitution (XSS)
    for event in ["onerror", "onload", "onclick", "onfocus", "onmouseover"]:
        if event in pl.lower():
            rare = random.choice(XSS_RARE_EVENTS)
            mutations.append((re.sub(event, rare, pl, flags=re.I), f"rare_event_{rare}"))
            break

    # 5. Null byte injection (before extension/path)
    if "/" in pl or "." in pl:
        mutations.append((pl + "%00", "null_byte_append"))

    # 6. URL-encoded homoglyph substitution (safe for HTTP — no raw Unicode)
    url_homoglyphs = {"a": "%C4%B0", "e": "%C3%A9", "o": "%C3%B6", "s": "%C5%9F"}
    if any(c in pl.lower() for c in url_homoglyphs):
        homoglyphed = pl
        for orig, repl in random.sample(list(url_homoglyphs.items()), min(2, len(url_homoglyphs))):
            homoglyphed = homoglyphed.replace(orig, repl, 1)
        if homoglyphed != pl:
            mutations.append((homoglyphed, "url_encoded_homoglyph"))

    # 7. Double encoding
    mutations.append((pl.replace("<", "%253C").replace(">", "%253E"), "double_encode_tags"))

    # 8. Comment insertion (SQLi/XSS)
    if len(pl) > 10:
        mid = len(pl) // 2
        mutations.append((pl[:mid] + "/**/" + pl[mid:], "comment_mid_insert"))

    return mutations


def _generate_boundary_payloads(db: DB, max_count: int) -> list[GeneratedPayload]:
    """ML decision boundary exploration.

    Takes payloads that were blocked but CLOSE to bypassing (similar to
    bypassed payloads) and perturbs them to push across the decision boundary.

    The idea: find blocked payloads that are structurally similar to bypassed
    payloads, then apply the minimum mutation needed to flip the classification.
    """
    generated: list[GeneratedPayload] = []

    if not db.passed_tests or not db.blocked_tests:
        return generated

    # Get bypass encoders and placements that work
    bypass_encoders: set[str] = set()
    bypass_placements: set[str] = set()
    for t in db.passed_tests:
        bypass_encoders.add(t.encoder)
        bypass_placements.add(t.placeholder)

    # For each blocked payload, try the exact encoder+placement combos
    # that worked for OTHER payloads — this is the "boundary" approach
    blocked_seen: set[str] = set()
    for bt in db.blocked_tests:
        if bt.payload in blocked_seen or len(bt.payload) > 2000:
            continue
        blocked_seen.add(bt.payload)

        # Try each successful encoder with each successful placement
        for enc in bypass_encoders:
            if enc == bt.encoder:
                continue  # Already tested this combo
            for ph in bypass_placements:
                if ph in ("RawRequest", "gRPC", "GraphQL"):
                    continue
                generated.append(GeneratedPayload(
                    payload=bt.payload,
                    encoder=enc,
                    placeholder=ph,
                    source_payload=bt.payload[:80],
                    generation_technique="ml_boundary_swap",
                    predicted_bypass_prob=0.6,
                    attack_type=bt.type or "unknown",
                ))
                if len(generated) >= max_count:
                    return generated

    return generated
