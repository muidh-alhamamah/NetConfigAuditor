"""Text and JSON reports. Findings arrive already redacted; nothing here touches raw config text."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field

from ncaudit import __version__
from ncaudit.models import Finding, Severity


@dataclass
class FileResult:
    path: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


def summarize(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
    for finding in findings:
        counts[finding.severity.label] += 1
    return {"total": len(findings), **counts}


def _counts_text(summary: dict[str, int]) -> str:
    parts = [f"{name} {count}" for name, count in summary.items() if name != "total" and count]
    return f"{summary['total']} finding{'s' if summary['total'] != 1 else ''}" + (f" ({', '.join(parts)})" if parts else "")


def render_text(results: Sequence[FileResult]) -> str:
    out: list[str] = []
    for result in results:
        if result.error:
            out += [f"== {result.path}: ERROR: {result.error}", ""]
            continue
        out += [f"== {result.path}: {_counts_text(summarize(result.findings))}", ""]
        for f in result.findings:
            where = f"line {f.line}" if f.line else "not configured"
            out.append(f"[{f.severity.label.upper()}] {f.rule_id}  {f.title}  ({where})")
            if f.evidence:
                out.append(f"  Evidence: {f.evidence}")
            out += [f"  Reason:   {f.message}", f"  Fix:      {f.recommendation}", ""]
    audited = [r for r in results if not r.error]
    all_findings = [f for r in audited for f in r.findings]
    out.append(f"Summary: {len(audited)} file{'s' if len(audited) != 1 else ''} audited, "
               f"{_counts_text(summarize(all_findings))}"
               + (f", {len(results) - len(audited)} error(s)" if len(audited) != len(results) else ""))
    return "\n".join(out)


def render_json(results: Sequence[FileResult]) -> str:
    audited = [r for r in results if not r.error]
    report = {
        "tool": "ncaudit",
        "version": __version__,
        "files": [{"file": r.path, "findings": [f.to_dict() for f in r.findings],
                   "summary": summarize(r.findings)} for r in audited],
        "errors": [{"file": r.path, "error": r.error} for r in results if r.error],
        "summary": summarize([f for r in audited for f in r.findings]),
    }
    return json.dumps(report, indent=2)  # ASCII-only: valid whatever the console encoding


def render_rules(rules: Sequence, as_json: bool) -> str:
    rules = sorted(rules, key=lambda r: r.id)
    if as_json:
        return json.dumps([{"id": r.id, "severity": r.severity.label, "title": r.title,
                            "recommendation": r.recommendation} for r in rules], indent=2)
    return "\n".join(f"{r.id:<9} {r.severity.label:<9} {r.title}" for r in rules)
