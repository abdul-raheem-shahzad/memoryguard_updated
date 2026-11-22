"""MemoryGuard security engine. Pure functions, no database access.

Pipeline: normalize -> trust (with lineage) -> detectors -> facts/conflicts/grounding
          -> risk score -> policy decision.

Key design rules
- Trust is bound to origin. A derived memory never has more trust than its least
  trusted parent, so an agent summary cannot launder untrusted content.
- Low risk does not mean trusted. Only memories at or above `actionable_trust`
  may justify actions (see /v1/authorize).
- Detectors are rules in v0.1. They are the weakest layer: plain false facts carry
  no injection wording, which is why conflict and grounding checks exist.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import math
import pathlib
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

import yaml

POLICY_PATH = pathlib.Path(__file__).with_name("policy.yaml")


def load_policy(path: pathlib.Path = POLICY_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------- normalize
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\ufeff]")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- detectors
DETECTORS: dict[str, tuple[int, list[str]]] = {
    "instruction_override": (90, [
        r"\b(ignore|disregard|forget|override)\b.{0,30}\b(instructions?|rules?|polic(y|ies)|guidelines?|permissions?)\b",
        r"\bfrom now on\b.{0,40}\b(you|the (assistant|agent))\b.{0,20}\b(must|should|will)\b",
        r"\bnew (rule|instruction|policy)\s*:",
        # the same override in French, Spanish, German, Portuguese and Italian
        r"\b(ignorez|ignore[zr]?|oubliez|ignora|ignore|olvida|ignoriere|vergiss|esquece|dimentica)\b"
        r".{0,40}\b(instructions?|consignes|r[eè]gles|instrucciones|reglas|anweisungen|regeln|"
        r"instru[cç][oõ]es|regras|istruzioni|regole)\b",
    ]),
    "fake_system": (85, [
        r"^\s*\[?(system|developer|admin)( message| note| prompt)?\]?\.?\s*:",
        r"<\s*/?\s*(system|developer|sys)\s*>",                  # <system> ... </system>
        r"#+\s*system\s+(prompt|message|instructions?)\b",       # ### SYSTEM PROMPT ###
        # "system prompt" only where it is used to give orders, not merely mentioned
        r"\b(new|updated|real|actual|true|hidden|secret|override|overriding)\s+system\s+"
        r"(prompt|message|instructions?)\b",
        r"\byour\s+system\s+prompt\s+(is|says|now|has been|was)\b",
        r"\[(system|developer)( message| prompt)?\]",
    ]),
    "privilege_claim": (90, [
        r"\b(is|am|are|as)\s+(an?\s+)?(admin|administrator|root|superuser|super-?\s?admin|sysadmin|owner)\b",
        r"\b(promoted|elevated|upgraded|made|appointed)\b.{0,20}\b(to|as)\s+(an?\s+)?"
        r"(admin|administrator|root|superuser|super-?\s?admin|sysadmin|owner)\b",
        r"\b(grant(ed)?|give[ns]?|has|have|gets?)\s+((this|the)\s+(user|customer|account)\s+|"
        r"me\s+|him\s+|her\s+|them\s+)?(full\s+)?(admin|administrator|root|superuser|owner)\s+"
        r"(rights|access|privileges?|permissions?|role)\b",
        r"\b(made|named|appointed)\s+(an?\s+)?(admin|administrator|superuser|super-?\s?admin)\b",
        # authority claims used to authorise something: "as the CEO I authorize..."
        r"\b(i am|i'm|as)\s+(the\s+)?(store\s+|shop\s+|general\s+)?(manager|ceo|owner|director|"
        r"supervisor|boss)\b.{0,40}\b(authori[sz]e|approve|allowed|permit|override)",
        r"\b(unrestricted|full|elevated)\s+(database\s+)?(access|privileges?|permissions?)\b",
        r"\b(bypass|skip|disable)\b.{0,20}\b(permission|auth\w*|approval|security|verification)s?\b",
    ]),
    "exfiltration": (80, [
        r"\b(always|every|all)\b.{0,40}\b(send|forward|email|upload|post|share|cc|bcc)\b.{0,40}[\w.+-]+@[\w-]+\.[\w.]+",
        # standing forwarding rules to a bare domain or URL, not just an address
        r"\b(always|every|all|each)\b.{0,40}\b(send|forward|upload|post|share|cc|bcc|copy)\b.{0,40}"
        r"\b(to|at)\s+(https?://)?[\w-]+(\.[\w-]+)*\.[a-z]{2,}\b",
        r"\b(send|forward|email|upload|post|share|cc|bcc|copy)\b.{0,15}\b(every|all|each|any)\b.{0,40}"
        r"\b(to|at)\s+([\w.+-]+@)?(https?://)?[\w-]+(\.[\w-]+)*\.[a-z]{2,}\b",
        # passive standing rules: "all future reports should be sent to x@y"
        r"\b(always|every|all|each)\b.{0,40}\b(sent|forwarded|emailed|copied|uploaded)\b.{0,20}"
        r"\bto\s+[\w.+-]+@[\w-]+\.[\w.]+",
        # bulk customer data going anywhere
        r"\b(send|forward|email|share|upload|export|copy)\b.{0,30}\b(customer|client|user)s?\b.{0,15}"
        r"\b(list|data|records|database|emails|details)\b.{0,40}\bto\b",
        # payouts redirected to an account
        r"\b(send|wire|transfer|pay|deposit|route)\b.{0,40}\b(to|into)\s+(account|acct|iban)\b",
        r"\b(send|share|reveal|post|upload)\b.{0,30}\b(api key|password|secret|token|credentials?)\b",
        r"\b(reveal|print|show|leak|repeat|output|dump)\b.{0,20}\bsystem\s+prompt\b",
    ]),
    "concealment": (75, [
        r"\b(do not|don'?t|never)\s+(tell|inform|notify|alert|mention\s+(this|it)\s+to)\b.{0,20}"
        r"\b(the )?(user|customer|admin|administrator|anyone|staff|manager)\b",
        r"\b(hide|conceal)\b.{0,20}\bfrom\b.{0,20}\b(user|customer|admin|administrator|logs?|audit)\b",
        r"\bkeep\b.{0,15}\b(secret|quiet|hidden)\b.{0,10}\bfrom\b.{0,20}"
        r"\b(user|customer|admin|administrator|staff|manager|logs?)\b",
    ]),
}
_COMPILED = {k: (w, [re.compile(p, re.I | re.M) for p in ps]) for k, (w, ps) in DETECTORS.items()}
# Signals that mean "this text tries to manipulate the agent". Any of them caps trust
# below actionable_trust (see analyze).
ATTACK_SIGNALS = frozenset(DETECTORS) | {"obfuscation"}


def run_detectors(text: str) -> dict[str, int]:
    out = {}
    for name, (weight, pats) in _COMPILED.items():
        if any(p.search(text) for p in pats):
            out[name] = weight
    return out


# ---------------------------------------------------------------- de-obfuscation
# The detectors run on extra "views" of the text that undo cheap tricks. The stored
# content is never changed; only what the regexes see.

# Cyrillic and Greek letters that render like Latin ones. NFKC already folds
# full-width and mathematical alphanumerics, so only cross-script look-alikes remain.
_CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
    "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})
_LATIN = re.compile(r"[A-Za-z]")
_NON_LATIN_LETTER = re.compile(r"[Ͱ-ϿЀ-ӿԀ-ԯ]")
_WORD = re.compile(r"\w+")
# "i g n o r e" / "i.g.n.o.r.e" / "d o": 2+ single letters, one separator each.
# Word gaps (two or more spaces) end a run, so spaced words stay apart.
_SPACED = re.compile(r"(?<![A-Za-z])[A-Za-z](?:[ .\-_*·][A-Za-z]){1,}(?![A-Za-z])")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# "1gn0r3", "4dm1n": digits standing in for letters, only inside words that also
# contain letters, so order numbers and prices are left alone.
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
_LEET_WORD = re.compile(r"\b(?=[\w$]*[A-Za-z])(?=[\w$]*[013457$])[\w$]+\b")

# For text whose spacing was destroyed entirely ("ignoreallpreviousinstructions"):
# a few high-value phrases matched without word boundaries, on joined runs only.
_COMPACT = {
    "instruction_override": re.compile(
        r"(ignore|disregard|forget|override)[a-z]{0,25}?(instructions?|rules|polic(y|ies)|guidelines)"),
    "fake_system": re.compile(r"(systemprompt|systemmessage|developermessage)"),
    "privilege_claim": re.compile(r"(iam|youare|useris)(now)?(an?)?(admin|administrator|root|superuser|superadmin)"),
}


def mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin letters with Cyrillic/Greek ones: almost never innocent."""
    return [w for w in _WORD.findall(text) if _LATIN.search(w) and _NON_LATIN_LETTER.search(w)]


def _decode_b64(text: str) -> list[str]:
    out = []
    for tok in _B64.findall(text):
        try:
            raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
            s = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() for ch in s)
        if len(s) >= 8 and printable / len(s) >= 0.9 and re.search(r"[a-zA-Z]{2,}\s+[a-zA-Z]{2,}", s):
            out.append(s)
    return out


def detection_views(raw: str) -> list[tuple[str, str]]:
    """(label, text) pairs for the detectors. `raw` is the content before whitespace
    is collapsed, so spaced-out letters can still be told apart from word gaps."""
    base = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", raw))
    views = []
    mapped = base.translate(_CONFUSABLES)
    if mapped != base:
        views.append(("look-alike letters", mapped))
    runs = _SPACED.findall(mapped)
    if runs:
        joined = _SPACED.sub(lambda m: re.sub(r"[^A-Za-z]", "", m.group(0)), mapped)
        views.append(("spaced-out letters", joined))
        views.append(("spaced-out letters", " ".join(re.sub(r"[^a-z]", "", r.lower()) for r in runs)))
    for decoded in _decode_b64(base):
        views.append(("base64", decoded))
    leet = _LEET_WORD.sub(lambda m: m.group(0).translate(_LEET), mapped)
    if leet != mapped:
        views.append(("leetspeak", leet))
    return [(label, re.sub(r"\s+", " ", t).strip()) for label, t in views]


def run_all_detectors(raw: str, text: str) -> tuple[dict[str, int], list[str]]:
    """Detectors over the plain text plus every de-obfuscated view.
    Returns (signals, reasons)."""
    signals, reasons = {}, []
    for name, w in run_detectors(text).items():
        signals[name] = w
        reasons.append(f"Detector matched: {name.replace('_', ' ')}")
    for label, view in detection_views(raw):
        hits = run_detectors(view)
        if label == "spaced-out letters":
            compact = re.sub(r"[^a-z]", "", view.lower())
            for name, pat in _COMPACT.items():
                if pat.search(compact):
                    hits[name] = DETECTORS[name][0]
        for name, w in hits.items():
            if name not in signals:
                signals[name] = w
                reasons.append(f"Detector matched: {name.replace('_', ' ')} (hidden with {label})")
    odd = mixed_script_words(text)
    if odd:
        signals["obfuscation"] = 60
        reasons.append("Mixes Latin with Cyrillic/Greek look-alike letters: " + ", ".join(odd[:3]))
    return signals, reasons


# ---------------------------------------------------------------- facts
ROLE_RANK = {"guest": 0, "viewer": 1, "student": 1, "member": 2, "user": 2, "editor": 3,
             "moderator": 4, "owner": 5, "admin": 6, "administrator": 6, "sysadmin": 6,
             "superuser": 7, "superadmin": 7, "super admin": 7, "super-admin": 7, "root": 7}
_SENT = re.compile(r"(?<=[.!?])\s+")
_VAL = r"(?P<val>(?:[^.!?]|\.(?=\S)){1,60}?)[.!?]?$"
_FACT = re.compile(r"^(?P<key>[a-z0-9 '\u2019_-]{2,80}?)\s+(?:is|are|=)\s+" + _VAL, re.I)
# "Key: value". Too loose for conflicts ("Note: ..." everywhere), so it is used only
# to check claims against ground_truth.
_COLON_FACT = re.compile(r"^(?P<key>[a-z0-9 '\u2019_-]{2,80}?)\s*:\s+" + _VAL, re.I)


def _fact_key(raw: str) -> str:
    key = re.sub(r"['\u2019]s\b", "", raw.lower())
    key = re.sub(r"^(a|an|the|our|my|your)\s+", "", key.strip())
    return re.sub(r"\s+", " ", key).strip()


def _fact_val(raw: str) -> str:
    return re.sub(r"^(a|an|the)\s+", "", raw.lower().strip())


def extract_facts(text: str) -> list[tuple[str, str]]:
    facts = []
    for s in _SENT.split(text):
        m = _FACT.match(s.strip())
        if not m:
            continue
        key, val = _fact_key(m.group("key")), _fact_val(m.group("val"))
        if val in ROLE_RANK and not key.endswith("role"):
            key = f"{key} role"
        facts.append((key, val))
    return facts


def extract_claims(text: str) -> list[tuple[str, str]]:
    """Facts plus "Key: value" statements, for grounding checks only."""
    claims = list(extract_facts(text))
    for s in _SENT.split(text):
        m = _COLON_FACT.match(s.strip())
        if m:
            claims.append((_fact_key(m.group("key")), _fact_val(m.group("val"))))
    return claims


# ---------------------------------------------------------------- similarity
def tokens(t: str) -> list[str]:
    return re.findall(r"[a-z0-9@._-]+", t.lower())


def cosine(a: list[str], b: list[str]) -> float:
    ca, cb = Counter(a), Counter(b)
    dot = sum(ca[k] * cb[k] for k in ca)
    na = math.sqrt(sum(v * v for v in ca.values()))
    nb = math.sqrt(sum(v * v for v in cb.values()))
    return dot / (na * nb) if na and nb else 0.0


# ---------------------------------------------------------------- copy detection
# Provenance is declared by the caller, so a trusted key can relay untrusted text
# simply by leaving out parent_ids. These checks find the parent it did not declare.
# They catch copying, not paraphrase: a rewording that keeps no 3-word phrase and
# no address slips through until embeddings land (0.3).

_EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_URL = re.compile(r"https?://[^\s<>\"']+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"']+", re.I)


@dataclass
class Candidate:
    """An existing memory the new write might have copied from."""
    memory_id: str
    trust: int
    status: str
    content: str


def indicators(text: str) -> set[str]:
    """Payload-bearing strings: full email addresses and full URLs (with a scheme or
    a path). Bare domains are left out on purpose: sharing "gmail.com" or
    "github.com" with an untrusted memory says nothing about copying, and treating it
    as evidence would quarantine everything that mentions a common domain."""
    t = text.lower()
    found = {m.group(0).rstrip(".") for m in _EMAIL.finditer(t)}
    for m in _URL.finditer(_EMAIL.sub(" ", t)):
        found.add(m.group(0).rstrip(".,;)"))
    return found


def fact_claim(key: str, val: str) -> str:
    return f"fact:{key}={val}"


def payloads(text: str) -> set[str]:
    """What a copy carries that matters: addresses, and "X is Y" claims."""
    return indicators(text) | {fact_claim(k, v) for k, v in extract_facts(normalize(text))}


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9@]+(?:[._-][a-z0-9@]+)*", text.lower())


def shingles(text: str, n: int = 3) -> set[tuple[str, ...]]:
    toks = _words(text)
    return {tuple(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def phrase_keys(text: str) -> set[str]:
    """Shingles in the same string form as payloads(), so trusted memories can
    vouch for wording as well as for claims."""
    return {"sh:" + " ".join(s) for s in shingles(text)}


def _describe(payload: str) -> str:
    if payload.startswith("fact:"):
        k, _, v = payload[5:].partition("=")
        return f"the claim '{k} = {v}'"
    return payload


MIN_PHRASES = 4    # 6+ words: shorter texts share phrases by coincidence


def find_copies(text: str, candidates: list[Candidate], vouched: set[str],
                policy: dict) -> list[tuple[Candidate, str]]:
    """Candidates the text was evidently copied from, each with the evidence.

    Two tests, either is enough:
      phrase overlap  at least `copy_threshold` of the new text's 3-word phrases occur
                      in the candidate (only for 6+ words, so a short line such as
                      "Order 5521 shipped today." is never matched on wording alone)
      payload reuse   the new text repeats an email address, URL or "X is Y" claim
                      that the candidate makes and that no trusted memory or
                      ground-truth entry vouches for (`vouched`, from payloads())
    Phrases a trusted memory also contains (phrase_keys() in `vouched`) never count.
    """
    cfg = policy.get("laundering") or {}
    threshold = float(cfg.get("copy_threshold", 0.6))
    mine = shingles(text)
    unvouched = {s for s in mine if "sh:" + " ".join(s) not in vouched}
    my_payloads = payloads(text) - vouched
    hits = []
    for cand in candidates:
        evidence = None
        if len(mine) >= MIN_PHRASES:
            # wording a trusted memory also uses is not evidence of laundering
            overlap = len(unvouched & shingles(cand.content)) / len(mine)
            if overlap >= threshold:
                evidence = f"{round(overlap * 100)}% of its phrases appear in"
        if evidence is None and my_payloads:
            shared = my_payloads & payloads(cand.content)
            if shared:
                evidence = "repeats " + ", ".join(_describe(s) for s in sorted(shared)[:2]) + " from"
        if evidence:
            hits.append((cand, evidence))
    return hits


# ---------------------------------------------------------------- analysis
@dataclass
class ExistingFact:
    memory_id: str
    key: str
    val: str
    trust: int


@dataclass
class ParentInfo:
    memory_id: str
    trust: int
    status: str  # active | review | quarantined | deleted | missing


@dataclass
class Analysis:
    content: str
    content_hash: str
    declared_trust: int
    trust: int
    signals: dict = field(default_factory=dict)
    risk: int = 0
    decision: str = "allow"
    status: str = "active"
    reasons: list = field(default_factory=list)
    facts: list = field(default_factory=list)
    supersede: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    copied_from: list = field(default_factory=list)   # undeclared parents found by copy detection


def declared_trust(policy: dict, source_type: str, parents: list[ParentInfo]) -> int:
    table = policy["source_trust"]
    if source_type not in table:
        raise ValueError(f"unknown source_type '{source_type}'. Allowed: {sorted(table)}")
    if source_type == "agent_generated" and parents:
        return min(p.trust for p in parents)
    return int(table[source_type])


def analyze(content: str, source_type: str, policy: dict,
            parents: list[ParentInfo] | None = None,
            existing_facts: list[ExistingFact] | None = None,
            prior_trust: int | None = None,
            ceiling: int | None = None,
            candidates: list[Candidate] | None = None,
            vouched: set[str] | None = None) -> Analysis:
    """`ceiling` is the trust level of the key making the write. Nothing a key writes
    may start above it, including an agent_generated memory whose parents are more
    trusted than the key itself.

    `candidates` are less trusted memories of the same agent. If the content was
    copied from one, that memory is treated as an undeclared parent: the write takes
    its trust, and is quarantined if the source is not active."""
    parents = parents or []
    existing_facts = existing_facts or []
    text = normalize(content)
    dt = declared_trust(policy, source_type, parents)
    capped = ceiling is not None and dt > ceiling
    if capped:
        dt = ceiling
    a = Analysis(content=text, content_hash=content_hash(text), declared_trust=dt, trust=dt)
    if capped:
        a.reasons.append(f"Trust capped at {ceiling}, the level of the key that wrote it")

    # lineage
    bad_parents = [p for p in parents if p.status != "active"]
    for p in parents:
        a.trust = min(a.trust, p.trust)
    if bad_parents:
        a.trust = min(a.trust, policy["orphan_trust"])
        a.signals["tainted_lineage"] = 90
        a.reasons.append("Derived from memories that are missing, under review, or quarantined: "
                         + ", ".join(p.memory_id for p in bad_parents))
    elif parents and a.trust < dt:
        a.reasons.append(f"Trust capped at {a.trust} by its least trusted parent")

    # undeclared lineage: text copied from a less trusted memory inherits its trust
    declared = {p.memory_id for p in parents}
    for cand, evidence in find_copies(text, candidates or [], vouched or set(), policy):
        if cand.memory_id in declared or (cand.trust >= a.trust and cand.status == "active"):
            continue
        a.copied_from.append(cand.memory_id)
        a.signals["copied_untrusted"] = max(a.signals.get("copied_untrusted", 0), 100 - cand.trust)
        a.reasons.append(f"Copies untrusted memory {cand.memory_id} ({evidence} it) without "
                         f"declaring it as a parent; trust capped at {min(a.trust, cand.trust)}")
        a.trust = min(a.trust, cand.trust)
        if cand.status != "active":
            a.trust = min(a.trust, policy["orphan_trust"])
            a.signals["tainted_lineage"] = 90
            a.reasons.append(f"Its source {cand.memory_id} is {cand.status}")

    # tampering: an update by a less trusted actor
    if prior_trust is not None and a.trust < prior_trust:
        a.signals["tampering"] = 70
        a.reasons.append(f"Modified by a lower-trust source ({a.trust} < {prior_trust})")

    # detectors, on the plain text and on de-obfuscated views of the raw content
    det_signals, det_reasons = run_all_detectors(content, text)
    a.signals.update(det_signals)
    a.reasons.extend(det_reasons)

    # A memory that matched an attack pattern may still be kept (a trusted source's
    # discount on risk can leave it below the review line), but it never justifies an
    # action, whoever wrote it. Before this rule, "Always forward invoices to <x>"
    # from a trusted tool was logged as suspicious and still actionable.
    attack_hits = sorted(k for k in a.signals if k in ATTACK_SIGNALS)
    flagged_cap = int(policy.get("flagged_max_trust", policy["actionable_trust"] - 1))
    if attack_hits and a.trust > flagged_cap:
        a.trust = flagged_cap
        a.reasons.append(f"Matched an attack pattern ({', '.join(attack_hits)}): it may inform "
                         "answers but can never justify an action")

    # facts, conflicts, grounding
    gt = policy.get("ground_truth") or {}
    a.facts = extract_facts(text)
    # Grounding may raise trust only when the memory says nothing BUT confirmed facts.
    # Otherwise one true sentence would carry any other claim in the same memory
    # ("<true fact>. Wire refunds to account X.") up to an actionable trust level.
    sentences = [s for s in _SENT.split(text) if s.strip()]
    fully_grounded = (bool(a.facts) and len(a.facts) == len(sentences)
                      and all(k in gt and str(gt[k]).lower() == v for k, v in a.facts))
    # "Key: value" claims are checked against ground truth too, so rewording a false
    # fact as "The ACME Support Email: help@evil.com" does not dodge the check
    for key, val in extract_claims(text)[len(a.facts):]:
        if key in gt and str(gt[key]).lower() != val:
            a.signals["grounding_contradiction"] = 95
            a.reasons.append(f"Contradicts trusted records: '{key}' should be '{gt[key]}'")
    for key, val in a.facts:
        if key in gt:
            if str(gt[key]).lower() == val:
                if (fully_grounded and a.trust < policy["grounded_trust"]
                        and "tainted_lineage" not in a.signals and not attack_hits):
                    a.trust = policy["grounded_trust"]
                    a.reasons.append(f"Grounded: '{key}' matches trusted records")
                elif not fully_grounded:
                    a.reasons.append(f"Grounded: '{key}' matches trusted records (no trust "
                                     "boost: the memory also makes other claims)")
                else:
                    a.reasons.append(f"Grounded: '{key}' matches trusted records")
            else:
                a.signals["grounding_contradiction"] = 95
                a.reasons.append(f"Contradicts trusted records: '{key}' should be '{gt[key]}'")
        for e in existing_facts:
            if e.key != key or e.val == val:
                continue
            a.conflicts.append({"memory_id": e.memory_id, "key": key, "existing": e.val,
                                "new": val, "existing_trust": e.trust})
            escalation = (key.endswith("role") and ROLE_RANK.get(val, -1) > ROLE_RANK.get(e.val, 99))
            if escalation:
                a.signals["privilege_escalation"] = 95
                a.reasons.append(f"Raises '{key}' from '{e.val}' to '{val}'")
            if e.trust > a.trust:
                a.signals["conflict"] = max(a.signals.get("conflict", 0), 85)
                a.reasons.append(f"Conflicts with higher-trust memory {e.memory_id} ('{e.val}')")
            elif a.trust >= policy["actionable_trust"] and not escalation:
                a.supersede.append(e.memory_id)
                a.reasons.append(f"Supersedes lower- or equal-trust memory {e.memory_id}")
            else:
                a.signals["conflict"] = max(a.signals.get("conflict", 0), 60)
                a.reasons.append(f"Conflicts with memory {e.memory_id} at similar trust")

    # risk
    a.signals["source"] = 100 - a.trust
    # copied_untrusted is evidence, not a threat by itself: its effect is the trust cap
    threat = max((v for k, v in a.signals.items() if k not in ("source", "copied_untrusted")),
                 default=0)
    if threat == 0:
        a.risk = round(a.signals["source"] * 0.3)
    else:
        a.risk = round(threat * (0.6 + 0.4 * a.signals["source"] / 100))
    a.risk = max(0, min(100, a.risk))

    # decision
    th = policy["thresholds"]
    if "tainted_lineage" in a.signals:
        a.decision, a.status = "quarantine", "quarantined"
    elif a.risk < th["allow"]:
        a.decision, a.status = "allow", "active"
    elif a.risk < th["allow_log"]:
        a.decision, a.status = "allow_log", "active"
    elif a.risk < th["review"]:
        a.decision, a.status = "review", "review"
    else:
        a.decision, a.status = "quarantine", "quarantined"
    if a.status != "active":
        a.supersede = []
    return a


def severity(risk: int) -> str:
    if risk >= 90:
        return "critical"
    if risk >= 80:
        return "high"
    if risk >= 60:
        return "medium"
    if risk >= 30:
        return "low"
    return "info"
