from __future__ import annotations

import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

from astp.models import (
    Constraints,
    Decision,
    Engagement,
    MethodPolicy,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)


class CompilationStatus(str, Enum):
    CLEAN = "clean"
    NEEDS_REVIEW = "needs_review"


class IssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"


class CompilerIssue(BaseModel):
    code: str
    severity: IssueSeverity
    message: str
    source_text: str = ""


class ExtractedRule(BaseModel):
    rule_type: str
    value: str
    source_text: str


class ScopeCompilation(BaseModel):
    status: CompilationStatus
    engagement: Engagement
    extracted_rules: list[ExtractedRule] = Field(default_factory=list)
    issues: list[CompilerIssue] = Field(default_factory=list)


_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?![\w.-])"
)
_URL_RE = re.compile(r"https?://[^\s,;()<>]+", re.IGNORECASE)
_CIDR_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d)")
_RATE_RE = re.compile(
    r"(?:not\s+exceed|no\s+more\s+than|maximum(?:\s+of)?|max(?:imum)?[:\s]+)?\s*"
    r"(\d+(?:\.\d+)?)\s*(?:requests?|req(?:uests?)?)\s*(?:per|/)\s*(?:second|sec|s)\b",
    re.IGNORECASE,
)

_ALLOW_CUES = (
    "in scope",
    "included in scope",
    "may be tested",
    "testing is allowed",
    "testing allowed",
)
_DENY_CUES = (
    "out of scope",
    "excluded from scope",
    "must not be tested",
    "do not test",
    "testing is prohibited",
    "testing prohibited",
)
_AMBIGUITY_CUES = (
    "maybe",
    "possibly",
    "generally",
    "normally",
    "unless",
    "case by case",
    "contact us",
    "contact before",
    "ask before",
    "prior approval",
    "prior authorization",
    "with permission",
)


def _sentences(text: str) -> list[str]:
    normalized = re.sub(r"\r\n?", "\n", text)
    parts = re.split(r"(?<=[.!?])\s+|\n+", normalized)
    return [part.strip() for part in parts if part.strip()]


def _extract_targets(sentence: str) -> list[tuple[ScopeKind, str]]:
    sentence = sentence.strip().rstrip(".,;:!?")
    results: list[tuple[ScopeKind, str]] = []
    occupied: list[tuple[int, int]] = []

    for match in _URL_RE.finditer(sentence):
        value = match.group(0).rstrip(".")
        results.append((ScopeKind.URL_PREFIX, value))
        occupied.append(match.span())

    for match in _CIDR_RE.finditer(sentence):
        results.append((ScopeKind.CIDR, match.group(0)))
        occupied.append(match.span())

    for match in _DOMAIN_RE.finditer(sentence):
        if any(start <= match.start() < end for start, end in occupied):
            continue
        value = match.group(0).rstrip(".")
        kind = ScopeKind.WILDCARD_DOMAIN if value.startswith("*.") else ScopeKind.DOMAIN
        results.append((kind, value))

    return results


def _append_unique(rules: list[ScopeRule], rule: ScopeRule) -> None:
    if not any(
        existing.kind == rule.kind and existing.value.lower() == rule.value.lower()
        for existing in rules
    ):
        rules.append(rule)


def _add_issue(
    issues: list[CompilerIssue],
    code: str,
    message: str,
    source_text: str,
    severity: IssueSeverity = IssueSeverity.WARNING,
) -> None:
    issues.append(
        CompilerIssue(
            code=code,
            severity=severity,
            message=message,
            source_text=source_text,
        )
    )


def _compile_scope_sentence(
    sentence: str,
    allowed: list[ScopeRule],
    denied: list[ScopeRule],
    approval_required: list[ScopeRule],
    extracted: list[ExtractedRule],
    issues: list[CompilerIssue],
) -> None:
    lowered = sentence.lower()
    targets = _extract_targets(sentence)
    if not targets:
        return

    approval_cues = ("prior approval", "prior authorization", "with permission")
    if any(cue in lowered for cue in approval_cues) and any(cue in lowered for cue in _ALLOW_CUES):
        for kind, value in targets:
            rule = ScopeRule(kind=kind, value=value)
            _append_unique(approval_required, rule)
            extracted.append(
                ExtractedRule(
                    rule_type="scope.approval_required",
                    value=value,
                    source_text=sentence,
                )
            )
        return

    ambiguous = any(cue in lowered for cue in _AMBIGUITY_CUES)
    if ambiguous:
        _add_issue(
            issues,
            "ambiguous_scope_language",
            "Potential scope rule contains conditional or ambiguous language; "
            "no permission was inferred.",
            sentence,
        )
        return

    # Handle common "X is in scope except Y" construction first so that the exception wins.
    if " except " in lowered and any(cue in lowered for cue in _ALLOW_CUES):
        before, after = re.split(r"\bexcept\b", sentence, maxsplit=1, flags=re.IGNORECASE)
        before_targets = _extract_targets(before)
        after_targets = _extract_targets(after)
        for kind, value in before_targets:
            rule = ScopeRule(kind=kind, value=value)
            _append_unique(allowed, rule)
            extracted.append(
                ExtractedRule(rule_type="scope.allow", value=value, source_text=sentence)
            )
        for kind, value in after_targets:
            rule = ScopeRule(kind=kind, value=value)
            _append_unique(denied, rule)
            extracted.append(
                ExtractedRule(rule_type="scope.deny", value=value, source_text=sentence)
            )
        return

    if any(cue in lowered for cue in _DENY_CUES):
        for kind, value in targets:
            rule = ScopeRule(kind=kind, value=value)
            _append_unique(denied, rule)
            extracted.append(
                ExtractedRule(rule_type="scope.deny", value=value, source_text=sentence)
            )
        return

    if any(cue in lowered for cue in _ALLOW_CUES):
        for kind, value in targets:
            rule = ScopeRule(kind=kind, value=value)
            _append_unique(allowed, rule)
            extracted.append(
                ExtractedRule(rule_type="scope.allow", value=value, source_text=sentence)
            )
        return

    _add_issue(
        issues,
        "unclassified_target",
        "A target-like value was found without an explicit allow/deny scope statement.",
        sentence,
    )


def compile_scope_text(
    text: str,
    *,
    engagement_id: str = "compiled-engagement",
    engagement_name: str = "Compiled Engagement",
) -> ScopeCompilation:
    allowed: list[ScopeRule] = []
    denied: list[ScopeRule] = []
    approval_required: list[ScopeRule] = []
    extracted: list[ExtractedRule] = []
    issues: list[CompilerIssue] = []
    constraints = Constraints()
    methods = MethodPolicy()

    for sentence in _sentences(text):
        lowered = sentence.lower()
        _compile_scope_sentence(
            sentence, allowed, denied, approval_required, extracted, issues
        )

        rate_match = _RATE_RE.search(sentence)
        if rate_match:
            rate = float(rate_match.group(1))
            if rate <= 0 or rate > 1000:
                _add_issue(
                    issues,
                    "invalid_rate_limit",
                    "The extracted request rate is outside ASTP's accepted range.",
                    sentence,
                    IssueSeverity.ERROR,
                )
            else:
                constraints.max_requests_per_second = rate
                extracted.append(
                    ExtractedRule(
                        rule_type="constraint.max_requests_per_second",
                        value=str(rate),
                        source_text=sentence,
                    )
                )

        prohibition_words = ("prohibited", "forbidden", "not allowed", "do not")
        if ("dos" in lowered or "denial of service" in lowered) and any(
            word in lowered for word in prohibition_words
        ):
            constraints.no_dos = True
            methods.intrusive = Decision.DENY
            extracted.append(
                ExtractedRule(
                    rule_type="constraint.no_dos",
                    value="true",
                    source_text=sentence,
                )
            )

        if "social engineering" in lowered and any(
            word in lowered for word in prohibition_words
        ):
            constraints.no_social_engineering = True
            extracted.append(
                ExtractedRule(
                    rule_type="constraint.no_social_engineering",
                    value="true",
                    source_text=sentence,
                )
            )

        production_data_terms = (
            "production data",
            "customer data",
            "user data",
            "data destruction",
            "delete data",
        )
        if any(term in lowered for term in production_data_terms) and any(
            word in lowered for word in prohibition_words
        ):
            constraints.no_data_destruction = True
            extracted.append(
                ExtractedRule(
                    rule_type="constraint.no_data_destruction",
                    value="true",
                    source_text=sentence,
                )
            )

    if not allowed and not approval_required:
        _add_issue(
            issues,
            "no_explicit_allowed_scope",
            "No explicit in-scope asset was extracted. ASTP will not infer authorization.",
            "",
            IssueSeverity.ERROR,
        )

    conflicts = {
        (rule.kind, rule.value.lower()) for rule in allowed
    } & {(rule.kind, rule.value.lower()) for rule in denied}
    for kind, value in sorted(conflicts, key=lambda item: (item[0].value, item[1])):
        _add_issue(
            issues,
            "conflicting_scope_rule",
            f"The same {kind.value} is both allowed and denied: {value}. "
            "Deny will take precedence.",
            value,
            IssueSeverity.ERROR,
        )

    engagement = Engagement(
        id=engagement_id,
        name=engagement_name,
        scope=ScopePolicy(
            allowed=allowed,
            denied=denied,
            approval_required=approval_required,
        ),
        methods=methods,
        constraints=constraints,
    )
    status = CompilationStatus.NEEDS_REVIEW if issues else CompilationStatus.CLEAN
    return ScopeCompilation(
        status=status,
        engagement=engagement,
        extracted_rules=extracted,
        issues=issues,
    )


def compile_scope_file(
    path: Path,
    *,
    engagement_id: str = "compiled-engagement",
    engagement_name: str = "Compiled Engagement",
) -> ScopeCompilation:
    return compile_scope_text(
        path.read_text(encoding="utf-8"),
        engagement_id=engagement_id,
        engagement_name=engagement_name,
    )
