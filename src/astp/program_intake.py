from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

from astp.models import Constraints, Engagement, MethodPolicy, ScopeKind, ScopePolicy, ScopeRule
from astp.program_models import (
    BugBountyProgram,
    ProgramConstraint,
    ProgramIssue,
    ProgramOperationalStatus,
    ProgramScopeEntry,
    ProgramSourceSnapshot,
    ProgramVisibility,
    RuleEffect,
    RuleProvenance,
)

_URL_RE = re.compile(r"https?://[^\s)\]>*]+", re.IGNORECASE)
_WILDCARD_RE = re.compile(r"\*\.([a-z0-9.-]+\.[a-z]{2,})", re.IGNORECASE)


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
) -> RuleProvenance:
    return RuleProvenance(
        source_type=source_type,
        source_url=source_url,
        section=section,
        source_text=text.strip(),
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


def import_program_text(
    text: str,
    *,
    name: str,
    platform: str,
    source_type: str = "text",
    source_url: str | None = None,
) -> BugBountyProgram:
    text = text.replace("https\\://", "https://").replace("http\\://", "http://")
    scope: list[ProgramScopeEntry] = []
    constraints: list[ProgramConstraint] = []
    issues: list[ProgramIssue] = []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    denial_mode = False
    scope_mode = False
    seen_scope: set[tuple[str, str, str]] = set()
    current_section: str | None = None

    for line in lines:
        lowered = line.lower()
        if line.startswith("#"):
            current_section = line.lstrip("#").strip(" *_") or None
        plain_section = _plain_section(line.lstrip("#").strip(" *_"))
        if plain_section == "scope":
            current_section = line.lstrip("#").strip(" *_") or "Escopo"
            scope_mode = True
            denial_mode = False
        elif plain_section == "deny":
            current_section = line.lstrip("#").strip(" *_") or "Exclusões"
            scope_mode = False
            denial_mode = True
        elif plain_section == "other":
            current_section = line.lstrip("#").strip(" *_") or current_section
            scope_mode = False
            denial_mode = False
        elif lowered.startswith("#") and "escopo" not in lowered:
            scope_mode = False
            if "exclusão" not in lowered and "exclusao" not in lowered:
                denial_mode = False

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
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )

        if "user agent" in lowered and "bughunt - security research" in lowered:
            constraints.append(
                ProgramConstraint(
                    code="recommended_user_agent",
                    effect=RuleEffect.INFO,
                    value="Bughunt - Security Research",
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )
        if "programa" in lowered and "offline" in lowered and "proib" in lowered:
            constraints.append(
                ProgramConstraint(
                    code="program_must_be_online",
                    value=True,
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )
        if "contas que você possui" in lowered or "contas que voce possui" in lowered:
            constraints.append(
                ProgramConstraint(
                    code="own_accounts_only",
                    value=True,
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )
        if "brute-force" in lowered or "brute force" in lowered:
            constraints.append(
                ProgramConstraint(
                    code="no_auth_bruteforce",
                    value=True,
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )
        if "engenharia social" in lowered or "social engineering" in lowered:
            constraints.append(
                ProgramConstraint(
                    code="no_social_engineering",
                    value=True,
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )
        if (
            "negação de serviço" in lowered
            or "denial of service" in lowered
            or re.search(r"\bdos\b", lowered) is not None
        ):
            constraints.append(
                ProgramConstraint(
                    code="no_dos",
                    value=True,
                    provenance=_provenance(
                        line,
                        source_type=source_type,
                        source_url=source_url,
                        section=current_section,
                    ),
                )
            )
        if "qualquer sistema" in lowered and (
            "universidade smart fit" in lowered or "empresa asap" in lowered
        ):
            issues.append(
                ProgramIssue(
                    code="broad_asset_exclusion",
                    message=(
                        "A broad excluded asset family cannot be converted to a complete host list "
                        "deterministically and requires review."
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
                        "Totem-related systems are broadly excluded and require a reviewed asset "
                        "mapping before executable scope can be compiled."
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
    status = ProgramOperationalStatus.UNKNOWN

    if not any(entry.effect == RuleEffect.ALLOW for entry in scope):
        issues.append(
            ProgramIssue(
                code="no_allowed_scope_extracted",
                message="No explicit allowed web scope could be extracted from the source.",
            )
        )

    return BugBountyProgram(
        id=_slug(f"{platform}-{name}"),
        name=name,
        platform=platform,
        visibility=visibility,
        operational_status=status,
        scope=scope,
        constraints=constraints,
        recommended_user_agent=recommended_user_agent,
        source=ProgramSourceSnapshot(
            source_type=source_type,
            source_url=source_url,
            content_sha256=_sha256_text(text),
        ),
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


def compile_program(
    program: BugBountyProgram,
    *,
    engagement_id: str | None = None,
    max_requests_per_second: float | None = None,
) -> Engagement:
    unresolved = {issue.code for issue in program.issues}
    blocking = unresolved - {"qualitative_rate_limit"}
    if blocking:
        raise ValueError(
            "Program still has unresolved review issues: " + ", ".join(sorted(blocking))
        )
    if "qualitative_rate_limit" in unresolved and max_requests_per_second is None:
        raise ValueError(
            "Program has a qualitative traffic restriction. Supply an explicitly reviewed numeric "
            "max_requests_per_second before compiling an executable engagement."
        )
    if not program.allowed_scope():
        raise ValueError("Program has no explicit allowed scope and cannot be compiled safely.")

    constraints_by_code = {item.code: item for item in program.constraints}
    rate = max_requests_per_second if max_requests_per_second is not None else 2.0
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
            no_dos="no_dos" in constraints_by_code,
            no_social_engineering="no_social_engineering" in constraints_by_code,
            no_data_destruction=True,
        ),
    )
