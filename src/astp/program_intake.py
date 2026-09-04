from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from astp.models import (
    Constraints,
    Engagement,
    MethodPolicy,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
    SemanticExclusionKind,
    SemanticExclusionRule,
)
from astp.program_models import (
    BugBountyProgram,
    ProgramConstraint,
    ProgramIssue,
    ProgramIssueResolution,
    ProgramOperationalStatus,
    ProgramScopeEntry,
    ProgramSourceSnapshot,
    ProgramVisibility,
    RuleEffect,
    RuleProvenance,
)

_URL_RE = re.compile(r"https?://[^\s)\]>*]+", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"\*\.([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)
_NUMBERED_RULE_RE = re.compile(r"^(\d+)(?:[.,]\d+)+(?:[.)])?\s*")
_NUMBERED_HEADING_RE = re.compile(r"^(\d+(?:\.\d+)*)[.)]?\s+(.+)$")

_EXCLUDED_FINDING_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("self_xss", ("self-xss", "self xss", "auto-xss", "auto xss")),
    ("clickjacking", ("clickjacking",)),
    ("login_logout_csrf", ("csrf em login", "csrf de login", "csrf em logout", "csrf de logout")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("missing_security_headers", ("headers de segurança", "security headers")),
    (
        "unvalidated_scanner_report",
        ("scanner sem valida", "scanner não valida", "scanner nao valida"),
    ),
    ("tabnabbing", ("tabnabbing",)),
    ("autocomplete", ("autocomplete", "auto-complete")),
)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return result or "program"


def _provenance(
    text: str,
    *,
    source_type: str,
    source_url: str | None,
    section: str | None = None,
    captured_at: datetime | None = None,
) -> RuleProvenance:
    return RuleProvenance(
        source_type=source_type,
        source_url=source_url,
        section=section,
        source_text=text.strip(),
        captured_at=captured_at,
    )


def _scope_rule(raw: str) -> ScopeRule | None:
    value = raw.strip().strip("`_[]()<>.,;:")
    if not value:
        return None
    if value.startswith("*."):
        return ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value=value)
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        if parsed.path in {"", "/"} and not parsed.query:
            return ScopeRule(kind=ScopeKind.DOMAIN, value=parsed.hostname or value)
        return ScopeRule(kind=ScopeKind.URL_PREFIX, value=value)
    if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", value, re.IGNORECASE):
        return ScopeRule(kind=ScopeKind.DOMAIN, value=value)
    return None


def _extract_scope_candidates(text: str) -> list[str]:
    values = list(_WILDCARD_RE.findall(text))
    wildcards = [f"*.{value.rstrip('.')}" for value in values]
    urls = [match.rstrip(".,;") for match in _URL_RE.findall(text)]
    return [*wildcards, *urls]


def _is_denial_context(line: str) -> bool:
    lowered = line.lower()
    markers = (
        "exclu",
        "fora do escopo",
        "out of scope",
        "não prossiga",
        "nao prossiga",
        "proibido",
    )
    return any(marker in lowered for marker in markers)


def _plain_section(line: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9áàâãéêíóôõúç ]+", " ", line.lower())
    normalized = re.sub(r"\s+", " ", normalized).strip()
    if normalized in {"escopo", "scope"} or normalized.startswith("lista de escopo"):
        return "scope"
    if "exclusão de endpoints" in normalized or "exclusao de endpoints" in normalized:
        return "deny"
    exclusion_section_markers = (
        "não aceito",
        "nao aceito",
        "não são aceitos",
        "nao sao aceitos",
        "itens excluídos",
        "itens excluidos",
        "vulnerabilidades excluídas",
        "vulnerabilidades excluidas",
    )
    if any(marker in normalized for marker in exclusion_section_markers):
        return "finding_exclusions"
    if normalized in {"recompensas", "rewards", "política do programa", "politica do programa"}:
        return "other"
    other_sections = (
        "política geral",
        "politica geral",
        "política de comportamento",
        "politica de comportamento",
    )
    if normalized.startswith(other_sections):
        return "other"
    return None


def _looks_like_heading(line: str) -> bool:
    clean = line.lstrip("#").strip(" *_")
    if not clean or len(clean) > 140 or clean.endswith((";", ".")):
        return False
    if line.startswith("#"):
        return True
    plain = _plain_section(clean)
    if plain is not None:
        return True
    match = _NUMBERED_HEADING_RE.match(clean)
    if match is None:
        return False
    number, title = match.groups()
    if number.count(".") >= 1:
        return False
    letters = [char for char in title if char.isalpha()]
    uppercase = [char for char in letters if char.isupper()]
    return bool(letters) and len(uppercase) / len(letters) >= 0.6


def _effective_section(line: str, current_section: str | None) -> str | None:
    match = _NUMBERED_RULE_RE.match(line)
    if match is None:
        return current_section
    major = match.group(1)
    if current_section and re.match(rf"^{re.escape(major)}(?:\D|$)", current_section):
        return current_section
    return f"{major}.x numbered rules"


def _is_no_dos_rule(lowered: str) -> bool:
    if "negação de serviço" in lowered or "negacao de servico" in lowered:
        return True
    if "denial of service" in lowered:
        return True
    explicit_dos = (
        "(dos)",
        "ex. dos",
        "ex: dos",
        "ataque dos",
        "ataques dos",
        "dos attack",
        "dos attacks",
    )
    return any(marker in lowered for marker in explicit_dos)


def _add_constraint(
    constraints: list[ProgramConstraint],
    *,
    code: str,
    provenance: RuleProvenance,
    value: str | bool | float | None = True,
    effect: RuleEffect = RuleEffect.RESTRICT,
) -> None:
    existing = next(
        (
            item
            for item in constraints
            if item.code == code and item.effect == effect and item.value == value
        ),
        None,
    )
    if existing is None:
        constraints.append(
            ProgramConstraint(
                code=code,
                effect=effect,
                value=value,
                provenance=[provenance],
            )
        )
        return
    if provenance not in existing.provenance:
        existing.provenance.append(provenance)


def _extract_excluded_finding_type(
    lowered: str,
    *,
    in_exclusion_section: bool = False,
) -> str | None:
    exclusion_markers = (
        "não será",
        "nao sera",
        "não serão",
        "nao serao",
        "não aceito",
        "nao aceito",
        "não aceitos",
        "nao aceitos",
        "fora do escopo",
        "não elegível",
        "nao elegivel",
        "não elegíveis",
        "nao elegiveis",
    )
    if not in_exclusion_section and not any(marker in lowered for marker in exclusion_markers):
        return None
    for code, markers in _EXCLUDED_FINDING_PATTERNS:
        if any(marker in lowered for marker in markers):
            return code
    return None


def import_program_text(
    text: str,
    *,
    name: str,
    platform: str,
    source_type: str = "text",
    source_url: str | None = None,
    captured_at: datetime | None = None,
    program_id: str | None = None,
) -> BugBountyProgram:
    text = text.replace("https\\://", "https://").replace("http\\://", "http://")
    scope: list[ProgramScopeEntry] = []
    constraints: list[ProgramConstraint] = []
    issues: list[ProgramIssue] = []
    excluded_finding_types: list[str] = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    denial_mode = False
    scope_mode = False
    finding_exclusion_mode = False
    seen_scope: set[tuple[str, str, str]] = set()
    current_section: str | None = None

    for line in lines:
        lowered = line.lower()
        clean_line = line.lstrip("#").strip(" *_")
        if _looks_like_heading(line):
            current_section = clean_line or current_section

        plain_section = _plain_section(clean_line)
        if plain_section == "scope":
            current_section = clean_line or "Escopo"
            scope_mode = True
            denial_mode = False
            finding_exclusion_mode = False
        elif plain_section == "deny":
            current_section = clean_line or "Exclusões"
            scope_mode = False
            denial_mode = True
            finding_exclusion_mode = False
        elif plain_section == "finding_exclusions":
            current_section = clean_line or "Excluded findings"
            scope_mode = False
            denial_mode = False
            finding_exclusion_mode = True
        elif plain_section == "other":
            current_section = clean_line or current_section
            scope_mode = False
            denial_mode = False
            finding_exclusion_mode = False
        elif line.startswith("#") and "escopo" not in lowered:
            scope_mode = False
            finding_exclusion_mode = False
            if "exclusão" not in lowered and "exclusao" not in lowered:
                denial_mode = False

        section = _effective_section(line, current_section)
        provenance = _provenance(
            line,
            source_type=source_type,
            source_url=source_url,
            section=section,
            captured_at=captured_at,
        )

        candidates = _extract_scope_candidates(line)
        for candidate in candidates:
            rule = _scope_rule(candidate)
            if rule is None:
                continue
            effect = (
                RuleEffect.DENY if denial_mode or _is_denial_context(line) else RuleEffect.ALLOW
            )
            if not scope_mode and effect == RuleEffect.ALLOW:
                continue
            key = (effect.value, rule.kind.value, rule.value.lower())
            if key in seen_scope:
                continue
            seen_scope.add(key)
            scope.append(
                ProgramScopeEntry(
                    effect=effect,
                    selector=rule,
                    provenance=provenance,
                )
            )

        if "user agent" in lowered and "bughunt - security research" in lowered:
            _add_constraint(
                constraints,
                code="recommended_user_agent",
                effect=RuleEffect.INFO,
                value="Bughunt - Security Research",
                provenance=provenance,
            )
        if "programa" in lowered and "offline" in lowered and "proib" in lowered:
            _add_constraint(
                constraints,
                code="program_must_be_online",
                provenance=provenance,
            )
        if "contas que você possui" in lowered or "contas que voce possui" in lowered:
            _add_constraint(
                constraints,
                code="own_accounts_only",
                provenance=provenance,
            )
        if "brute-force" in lowered or "brute force" in lowered:
            _add_constraint(
                constraints,
                code="no_auth_bruteforce",
                provenance=provenance,
            )
        if "engenharia social" in lowered or "social engineering" in lowered:
            _add_constraint(
                constraints,
                code="no_social_engineering",
                provenance=provenance,
            )
        if _is_no_dos_rule(lowered):
            _add_constraint(
                constraints,
                code="no_dos",
                provenance=provenance,
            )

        excluded_type = _extract_excluded_finding_type(
            lowered,
            in_exclusion_section=finding_exclusion_mode,
        )
        if excluded_type and excluded_type not in excluded_finding_types:
            excluded_finding_types.append(excluded_type)

        if "qualquer sistema" in lowered and (
            "universidade smart fit" in lowered or "empresa asap" in lowered
        ):
            issues.append(
                ProgramIssue(
                    code="broad_asset_exclusion",
                    message=(
                        "A broad excluded asset family cannot be converted to a complete host list "
                        "deterministically and requires reviewed deny mappings."
                    ),
                    source_text=line,
                )
            )
        if "totens" in lowered and (
            "sistemas" in lowered or "serviços" in lowered or "servicos" in lowered
        ):
            issues.append(
                ProgramIssue(
                    code="physical_or_totem_asset_exclusion",
                    message=(
                        "Totem-related systems are broadly excluded and require reviewed deny "
                        "mappings before executable scope can be compiled."
                    ),
                    source_text=line,
                )
            )
        if "tráfego significativo" in lowered or "trafego significativo" in lowered:
            issues.append(
                ProgramIssue(
                    code="qualitative_rate_limit",
                    message=(
                        "Program restricts high-traffic automation but does not provide a numeric "
                        "requests-per-second limit. A numeric execution limit must be reviewed."
                    ),
                    source_text=line,
                )
            )

    recommended_user_agent = next(
        (
            str(item.value)
            for item in constraints
            if item.code == "recommended_user_agent" and item.value
        ),
        None,
    )
    visibility = (
        ProgramVisibility.PUBLIC
        if "programa público" in text.lower()
        else ProgramVisibility.UNKNOWN
    )

    if not any(entry.effect == RuleEffect.ALLOW for entry in scope):
        issues.append(
            ProgramIssue(
                code="no_allowed_scope_extracted",
                message="No explicit allowed web scope could be extracted from the source.",
            )
        )

    source = ProgramSourceSnapshot(
        source_type=source_type,
        source_url=source_url,
        content_sha256=_sha256_text(text),
    )
    if captured_at is not None:
        source.captured_at = captured_at

    return BugBountyProgram(
        id=program_id or _slug(f"{platform}-{name}"),
        name=name,
        platform=platform,
        visibility=visibility,
        operational_status=ProgramOperationalStatus.UNKNOWN,
        scope=scope,
        constraints=constraints,
        excluded_finding_types=excluded_finding_types,
        recommended_user_agent=recommended_user_agent,
        source=source,
        issues=issues,
    )


def import_program_file(
    path: Path,
    *,
    name: str,
    platform: str,
    source_url: str | None = None,
) -> BugBountyProgram:
    text = path.read_text(encoding="utf-8")
    return import_program_text(
        text,
        name=name,
        platform=platform,
        source_type=path.suffix.lower().lstrip(".") or "text",
        source_url=source_url,
    )


def resolve_rate_issue(program: BugBountyProgram, requests_per_second: float) -> None:
    if requests_per_second <= 0:
        raise ValueError("requests_per_second must be greater than zero")
    matches = [
        issue
        for issue in program.issues
        if issue.code == "qualitative_rate_limit" and not issue.resolved
    ]
    if not matches:
        raise ValueError("no unresolved qualitative_rate_limit issue found")
    program.reviewed_max_requests_per_second = requests_per_second
    for issue in matches:
        issue.resolution = ProgramIssueResolution(
            resolution_type="operator_constraint",
            operator_value=requests_per_second,
            note=(
                "Operator-selected conservative execution limit; the source program did not "
                "publish this numeric rate."
            ),
        )


def resolve_issue_with_denies(
    program: BugBountyProgram,
    *,
    issue_index: int,
    deny_rules: list[ScopeRule],
    note: str | None = None,
) -> None:
    del deny_rules, note
    if issue_index < 1 or issue_index > len(program.issues):
        raise ValueError("issue index is out of range")
    issue = program.issues[issue_index - 1]
    if issue.resolved:
        raise ValueError("issue is already resolved")
    if issue.code in {"broad_asset_exclusion", "physical_or_totem_asset_exclusion"}:
        raise ValueError(
            "broad semantic exclusions cannot be resolved by host mappings alone; "
            "use a semantic deny guardrail"
        )
    raise ValueError("this issue type cannot be resolved with deny mappings")


def resolve_issue_with_semantic_exclusion(
    program: BugBountyProgram,
    *,
    issue_index: int,
    kind: SemanticExclusionKind,
    value: str,
    note: str | None = None,
) -> None:
    if issue_index < 1 or issue_index > len(program.issues):
        raise ValueError("issue index is out of range")
    issue = program.issues[issue_index - 1]
    if issue.resolved:
        raise ValueError("issue is already resolved")
    expected = {
        "broad_asset_exclusion": {
            SemanticExclusionKind.PRODUCT_FAMILY,
            SemanticExclusionKind.ORGANIZATION_FAMILY,
            SemanticExclusionKind.ASSET_FAMILY,
        },
        "physical_or_totem_asset_exclusion": {SemanticExclusionKind.ASSET_FAMILY},
    }.get(issue.code)
    if expected is None:
        raise ValueError("this issue type cannot be resolved with a semantic deny guardrail")
    if kind not in expected:
        allowed = ", ".join(sorted(item.value for item in expected))
        raise ValueError(f"semantic exclusion kind must be one of: {allowed}")
    value = value.strip()
    if not value:
        raise ValueError("semantic exclusion value cannot be empty")

    digest = hashlib.sha256(
        f"{program.id}|{issue_index}|{kind.value}|{value}".encode()
    ).hexdigest()[:12]
    rule = SemanticExclusionRule(
        id=f"semex-{digest}",
        kind=kind,
        value=value,
        source_text=issue.source_text,
    )
    if all(existing.id != rule.id for existing in program.semantic_exclusions):
        program.semantic_exclusions.append(rule)
    issue.resolution = ProgramIssueResolution(
        resolution_type="semantic_deny_guardrail",
        note=note,
        operator_value=f"{kind.value}={value}",
    )


def compile_program(
    program: BugBountyProgram,
    *,
    engagement_id: str | None = None,
    max_requests_per_second: float | None = None,
) -> Engagement:
    unresolved = {issue.code for issue in program.unresolved_issues}
    if "qualitative_rate_limit" in unresolved and max_requests_per_second is None:
        other_blocking = unresolved - {"qualitative_rate_limit"}
        if not other_blocking:
            raise ValueError(
                "Program has a qualitative traffic restriction. Review it with review-program "
                "--rps or supply an explicitly reviewed --rps for this compilation."
            )
    blocking = set(unresolved)
    if max_requests_per_second is not None:
        blocking.discard("qualitative_rate_limit")
    if blocking:
        raise ValueError(
            "Program still has unresolved review issues: " + ", ".join(sorted(blocking))
        )
    if not program.allowed_scope():
        raise ValueError("Program has no explicit allowed scope and cannot be compiled safely.")

    rate = max_requests_per_second
    if rate is None:
        rate = program.reviewed_max_requests_per_second
    if rate is None:
        rate = 2.0
    if rate <= 0:
        raise ValueError("max_requests_per_second must be greater than zero")

    constraints_by_code = {item.code: item for item in program.constraints}
    return Engagement(
        id=engagement_id or program.id,
        name=program.name,
        scope=ScopePolicy(
            allowed=program.allowed_scope(),
            denied=program.denied_scope(),
        ),
        methods=MethodPolicy(),
        constraints=Constraints(
            max_requests_per_second=rate,
            semantic_exclusions=list(program.semantic_exclusions),
            no_dos="no_dos" in constraints_by_code,
            no_social_engineering="no_social_engineering" in constraints_by_code,
            no_data_destruction=True,
        ),
    )
