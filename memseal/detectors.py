"""Deterministic form detectors (no ML, no LLM).

* Imperative / instruction-form detection, English and Japanese.
* Secret-shape detection and redaction.

All patterns are plain data (``IMPERATIVE_PATTERNS``, ``SECRET_PATTERNS``) and
can be extended at runtime with :func:`register_imperative_pattern` /
:func:`register_secret_pattern`.

These are *form* detectors: they flag text that is shaped like an instruction
or a credential. They do not judge intent; false positives and negatives are
expected and are measured by the bench.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Imperative detection
# --------------------------------------------------------------------------

# Base-form verbs that, at the start of a sentence, almost always signal an
# imperative. Extend via register_imperative_verbs().
EN_IMPERATIVE_VERBS = [
    "add", "answer", "approve", "ask", "assume", "attach", "avoid", "bcc", "book",
    "buy", "call", "cancel", "cc", "change", "check", "click", "consider", "contact",
    "copy", "delete", "disable", "disclose", "disregard", "do", "don't", "dont",
    "download", "email", "enable", "execute", "follow", "forget", "forward", "give",
    "grant", "ignore", "include", "install", "keep", "let", "make", "mark",
    "mention", "notify", "open", "order", "override", "pay", "post", "prefer",
    "prioritize", "prioritise", "provide", "publish", "recommend", "record",
    "redirect", "refer", "remember", "remove", "reply", "report", "respond",
    "reveal", "route", "run", "save", "say", "send", "set", "share", "sign",
    "start", "stop", "store", "suggest", "tell", "transfer", "treat", "update",
    "upload", "use", "visit", "wire",
]

_EN_PREFIX = (
    r"(?:(?:note|important|reminder|system|instruction|instructions|todo|nb|p\.s\.)\s*[:\-]\s*)?"
    r"(?:(?:from now on|going forward|in (?:the )?future|next time|henceforth|for all future \w+)\s*,?\s*)?"
    r"(?:please\s+|kindly\s+)?"
)


@dataclass(frozen=True)
class ImperativePattern:
    id: str
    lang: str            # "en" | "ja"
    scope: str           # "sentence" (applied per sentence) | "text"
    regex: re.Pattern
    description: str


@dataclass(frozen=True)
class DetectorMatch:
    pattern_id: str
    lang: str
    text: str


def _verb_alt(verbs) -> str:
    return "|".join(sorted((re.escape(v) for v in verbs), key=len, reverse=True))


def _build_en_patterns(verbs) -> list[ImperativePattern]:
    v = _verb_alt(verbs)
    flags = re.IGNORECASE
    return [
        ImperativePattern("EN-VERB-START", "en", "sentence",
                          re.compile(rf"^\W*{_EN_PREFIX}(?:{v})\b", flags),
                          "sentence starts with a base-form imperative verb"),
        ImperativePattern("EN-ALWAYS-NEVER", "en", "sentence",
                          re.compile(rf"^\W*{_EN_PREFIX}(?:always|never)\b", flags),
                          "sentence starts with always/never"),
        ImperativePattern("EN-TRIGGER", "en", "sentence",
                          re.compile(rf"\b(?:when|whenever|if|once|after|before|as soon as)\b[^.;!?]{{1,160}}?"
                                     rf"(?:,|\bthen\b)\s*(?:please\s+|always\s+|also\s+|then\s+|immediately\s+)*(?:{v})\b",
                                     flags),
                          "'when X, do Y' trigger form"),
        ImperativePattern("EN-MODAL-DIRECTIVE", "en", "text",
                          re.compile(r"\b(?:you|the assistant|assistant|the agent|agent|the ai|ai)\s+"
                                     r"(?:must|should|shall|need to|have to|are required to|is required to)\b",
                                     flags),
                          "directive addressed to the assistant"),
        ImperativePattern("EN-MAKE-SURE", "en", "text",
                          re.compile(r"\b(?:make sure to|be sure to|don't forget to|do not forget to)\b", flags),
                          "make sure / don't forget to"),
    ]


_JA_U = "るうくぐすつぬぶむ"

JA_PATTERNS_DATA = [
    ("JA-KOTO", "sentence", rf"(?:[{_JA_U}]|ない)こと$", "「〜すること」文末"),
    ("JA-KUDASAI", "text", r"(?:て|で)(?:ください|下さい|くれ(?:$|[。、]))", "「〜してください」"),
    ("JA-ONEGAI", "text", r"お願い(?:します|いたします|致します)", "「〜をお願いします」"),
    ("JA-KANARAZU", "text", r"必ず", "「必ず〜」"),
    ("JA-PROHIBIT", "text", r"(?:て|で)は(?:いけない|いけません|ならない|なりません|だめ|ダメ)", "「〜してはいけない」"),
    ("JA-NA", "sentence", r"[るくすつむぶぐぬ]な$", "「〜するな」文末"),
    ("JA-NASAI", "sentence", r"(?:なさい|せよ|しろ|してくれ)$", "「〜しなさい/せよ」"),
    ("JA-BEKI", "sentence", r"べき(?:だ|です|である)?$", "「〜すべき」"),
    ("JA-TRIGGER", "sentence",
     r"(?:たら|ときは|時は|場合は|際は)[、,]?.{0,80}?(?:送信|転送|送付|共有|削除|実行|送って|伝えて|添付|知らせて)",
     "「〜したら…送信」型トリガー"),
    ("JA-HENCEFORTH", "sentence",
     r"^(?:今後|これから|以後|次回から)は?[、,]?.*(?:する|送る|使う|含める|勧める|入れる|返す|答える)$",
     "「今後は〜する」"),
]


def _build_ja_patterns() -> list[ImperativePattern]:
    return [ImperativePattern(pid, "ja", scope, re.compile(rx), desc)
            for pid, scope, rx, desc in JA_PATTERNS_DATA]


IMPERATIVE_PATTERNS: list[ImperativePattern] = _build_en_patterns(EN_IMPERATIVE_VERBS) + _build_ja_patterns()


def register_imperative_pattern(pattern_id: str, lang: str, regex: str, *, scope: str = "text",
                                description: str = "", flags: int = 0) -> ImperativePattern:
    if any(p.id == pattern_id for p in IMPERATIVE_PATTERNS):
        raise ValueError(f"duplicate pattern id {pattern_id}")
    p = ImperativePattern(pattern_id, lang, scope, re.compile(regex, flags), description)
    IMPERATIVE_PATTERNS.append(p)
    return p


def register_imperative_verbs(verbs) -> None:
    """Add English base-form verbs and rebuild the EN patterns."""
    for verb in verbs:
        if verb.lower() not in EN_IMPERATIVE_VERBS:
            EN_IMPERATIVE_VERBS.append(verb.lower())
    builtin_ids = {p.id for p in _build_en_patterns(EN_IMPERATIVE_VERBS)}
    rest = [p for p in IMPERATIVE_PATTERNS if p.id not in builtin_ids]
    IMPERATIVE_PATTERNS[:] = _build_en_patterns(EN_IMPERATIVE_VERBS) + rest


_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+|[。！？!?\n]+|;\s*")


def split_sentences(text: str) -> list[str]:
    text = unicodedata.normalize("NFKC", text)
    parts = [s.strip().rstrip(".!?。！？") for s in _SENT_SPLIT.split(text)]
    return [p.strip() for p in parts if p and p.strip()]


def detect_imperative(text: str) -> list[DetectorMatch]:
    norm = unicodedata.normalize("NFKC", text)
    sentences = split_sentences(norm)
    found: list[DetectorMatch] = []
    for p in IMPERATIVE_PATTERNS:
        targets = sentences if p.scope == "sentence" else [norm]
        for t in targets:
            m = p.regex.search(t)
            if m:
                found.append(DetectorMatch(p.id, p.lang, m.group(0)))
                break
    return found


def is_imperative(text: str) -> bool:
    return bool(detect_imperative(text))


# --------------------------------------------------------------------------
# Secret-shape detection
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretPattern:
    id: str
    regex: re.Pattern   # if it has a named group 'secret', only that span is redacted
    description: str


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    start: int
    end: int
    fingerprint: str  # sha256 prefix of the secret; the plaintext is never kept


_PRINTABLE_PW = r"(?=[!-~]*[0-9!@#$%^&*_\-+=])[!-~]{6,}"

SECRET_PATTERNS_DATA = [
    ("PRIVATE-KEY", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", 0,
     "PEM private key block"),
    ("ANTHROPIC-STYLE-KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 0, "sk-ant-… API key"),
    ("OPENAI-STYLE-KEY", r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,}", 0, "sk-… API key"),
    ("GITHUB-TOKEN", r"\bgh[pousr]_[A-Za-z0-9]{36,}", 0, "GitHub token"),
    ("AWS-ACCESS-KEY", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", 0, "AWS access key id"),
    ("SLACK-TOKEN", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}", 0, "Slack token"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", 0, "JSON Web Token"),
    ("BEARER", r"(?i)\bbearer\s+(?P<secret>[A-Za-z0-9._\-~+/]{20,}=*)", 0, "Bearer token"),
    ("KEY-ASSIGNMENT",
     r"(?i)\b(?:api[_ \-]?key|access[_ \-]?token|secret[_ \-]?key|auth[_ \-]?token|client[_ \-]?secret|token)"
     r"\b\s*(?:is|=|:|：|は)\s*[\"']?(?P<secret>[A-Za-z0-9_\-./+]{16,})", 0, "key/token assignment"),
    ("JA-KEY-ASSIGNMENT", r"(?:APIキー|アクセストークン|トークン|シークレット)\s*(?:は|:|：|=)\s*[\"'「]?(?P<secret>[A-Za-z0-9_\-./+]{16,})",
     0, "キー/トークンの代入"),
    ("PASSWORD-ASSIGNMENT", rf"(?i)\b(?:password|passwd|pwd|passcode)\b\s*(?:is|=|:|：)\s*[\"']?(?P<secret>{_PRINTABLE_PW})",
     0, "password assignment"),
    ("JA-PASSWORD-ASSIGNMENT", rf"(?:パスワード|暗証番号)\s*(?:は|:|：|=)\s*[\"'「]?(?P<secret>{_PRINTABLE_PW})",
     0, "パスワードの代入"),
]

SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(pid, re.compile(rx, flags), desc) for pid, rx, flags, desc in SECRET_PATTERNS_DATA
]


def register_secret_pattern(pattern_id: str, regex: str, *, description: str = "", flags: int = 0) -> SecretPattern:
    if any(p.id == pattern_id for p in SECRET_PATTERNS):
        raise ValueError(f"duplicate pattern id {pattern_id}")
    p = SecretPattern(pattern_id, re.compile(regex, flags), description)
    SECRET_PATTERNS.append(p)
    return p


def _fingerprint(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


REDACTION_MARKER = re.compile(r"\[REDACTED:[A-Z\-]+:[0-9a-f]{8}\]")


def find_secrets(text: str) -> list[SecretFinding]:
    spans: list[SecretFinding] = []
    markers = [m.span() for m in REDACTION_MARKER.finditer(text)]
    for p in SECRET_PATTERNS:
        for m in p.regex.finditer(text):
            if "secret" in p.regex.groupindex and m.group("secret") is not None:
                s, e = m.span("secret")
            else:
                s, e = m.span(0)
            if any(s < f.end and f.start < e for f in spans):
                continue  # overlapping a span already claimed by an earlier pattern
            if any(s < me and ms < e for ms, me in markers):
                continue  # an existing redaction marker is not a secret
            spans.append(SecretFinding(p.id, s, e, _fingerprint(text[s:e])))
    return sorted(spans, key=lambda f: f.start)


def has_secret(text: str) -> bool:
    return bool(find_secrets(text))


def redact(text: str) -> tuple[str, list[SecretFinding]]:
    """Replace each secret span with ``[REDACTED:<kind>:<fp8>]``."""
    findings = find_secrets(text)
    out, pos = [], 0
    for f in findings:
        out.append(text[pos:f.start])
        out.append(f"[REDACTED:{f.kind}:{f.fingerprint}]")
        pos = f.end
    out.append(text[pos:])
    return "".join(out), findings
