from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from flask import Flask, jsonify, render_template, request


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(SCRIPT_DIR, "dashboard")
DEFAULT_REPORT_PATH = os.path.join(SCRIPT_DIR, "security_report.md")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "security_reports")
RUN_STATUS_PATH = os.path.join(SCRIPT_DIR, "run_status.json")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _pid_is_alive(pid: object) -> bool:
    """
    Best-effort liveness check for the background pipeline process.
    Uses os.kill(pid, 0) which does not actually signal the process.
    """
    try:
        p = int(pid)  # type: ignore[arg-type]
        if p <= 0:
            return False
    except Exception:
        return False
    try:
        os.kill(p, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # If we don't have permission to signal, assume it's alive to avoid false negatives.
        return True


def _latest_report_path() -> str:
    """
    Prefer the newest timestamped report in security_reports/, otherwise fall back
    to security_report.md.
    """
    try:
        if os.path.isdir(REPORTS_DIR):
            candidates: list[str] = []
            for name in os.listdir(REPORTS_DIR):
                if name.endswith(".md") and name.startswith("security_report_"):
                    candidates.append(os.path.join(REPORTS_DIR, name))
            if candidates:
                return max(candidates, key=lambda p: os.path.getmtime(p))
    except Exception:
        pass
    return DEFAULT_REPORT_PATH


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _load_run_status() -> dict[str, Any]:
    """
    Load pipeline run status written by deepagent_sast_demo.py.
    Returns a stable default shape if no status file exists yet.
    """
    default: dict[str, Any] = {
        "state": "idle",  # idle|running|done|error
        "stage": None,
        "progress": 0,
        "message": None,
        "updated_at": None,
        "started_at": None,
        "finished_at": None,
        "run_id": None,
        "pid": None,
    }
    try:
        if not os.path.isfile(RUN_STATUS_PATH):
            return default
        with open(RUN_STATUS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {**default, **data}
    except Exception:
        pass
    return default


def _extract_json_fence(markdown: str) -> dict[str, Any] | None:
    """
    Extract the first ```json ... ``` fenced block as a JSON object.
    Returns None if not found or not parseable.
    """
    m = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", markdown, flags=re.IGNORECASE)
    if not m:
        return None
    try:
        obj = json.loads(m.group(1))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _severity_rank(sev: str | None) -> int:
    s = (sev or "").strip().lower()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(s, 4)


def _normalize_severity_label(sev: object) -> str:
    """
    UI-facing normalization for severity labels.
    Ensures canonical title-case: Critical/High/Medium/Low.
    """
    s = str(sev or "").strip().lower()
    if s in {"critical", "crit", "p0"}:
        return "Critical"
    if s in {"high", "hi", "p1"}:
        return "High"
    if s in {"medium", "med", "moderate", "p2"}:
        return "Medium"
    if s in {"low", "lo", "p3"}:
        return "Low"
    if not s:
        return "Unspecified"
    # Best-effort title case for odd inputs ("info", "warning", etc.)
    return s[:1].upper() + s[1:]


def _looks_like_owasp(category: str | None) -> bool:
    if not category:
        return False
    # Example: "A02:2021 - Cryptographic Failures"
    return bool(re.match(r"^A\d{2}:\d{4}\s*-", category.strip()))


def _infer_category(title: str | None, description: str | None) -> str:
    """
    Prefer OWASP Top 10 categories when they clearly apply; otherwise fall back
    to precise native-code labels. This keeps the UI from showing "Uncategorized".
    """
    t = (title or "").lower()
    d = (description or "").lower()
    text = f"{t}\n{d}"

    # OWASP Top 10 (2021) heuristics
    if any(k in text for k in ["crypto", "crypt", "pbkdf2", "salt", "key deriv", "encryption", "cipher"]):
        return "A02:2021 - Cryptographic Failures"
    if any(k in text for k in ["sql injection", "sqli", "command injection", "injection", "xss", "template injection"]):
        return "A03:2021 - Injection"
    if any(k in text for k in ["auth", "authorization", "idor", "access control", "permission"]):
        return "A01:2021 - Broken Access Control"

    # Native-code / general
    if any(k in text for k in ["buffer overflow", "out-of-bounds", "oob", "use-after-free", "uaf", "double free"]):
        return "Memory Safety"
    if any(k in text for k in ["race condition", "toctou", "symlink", "hardlink"]):
        return "Race Condition / TOCTOU"

    return "Security Misconfiguration / Best Practice"


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    category: str
    file: str
    line: int | None
    validation_status: str | None
    validation_confidence: float | None
    validation_rationale: str | None
    code_snippet: str | None
    description: str | None
    impact: str | None
    remediation: str | None
    references: list[str]


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        v = value.strip()
        if v.isdigit():
            return int(v)
    return None


def _normalize_report(report: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize different report schemas into a consistent shape for the UI.
    Supports:
    - security-report skill schema: summary/findings/recommendations
    - looser schemas seen in the wild (e.g. summary as string, findings using file_path/line_number/evidence)
    """
    raw_summary = report.get("summary")
    raw_findings = report.get("findings")
    raw_recs = report.get("recommendations")
    raw_filetypes = report.get("filetype_scan")

    summary: dict[str, Any]
    if isinstance(raw_summary, dict):
        summary = dict(raw_summary)
    elif isinstance(raw_summary, str):
        summary = {"note": raw_summary}
    else:
        summary = {}

    findings_in: list[dict[str, Any]] = []
    if isinstance(raw_findings, list):
        findings_in = [f for f in raw_findings if isinstance(f, dict)]

    normalized_findings: list[Finding] = []
    for idx, f in enumerate(findings_in, start=1):
        # Common keys (skill schema)
        fid = str(f.get("id") or f.get("finding_id") or f.get("name") or f"FINDING-{idx:03d}")
        raw_title = (
            f.get("title")
            or f.get("name")
            or f.get("issue")
            or f.get("finding")
            or f.get("summary")
            or f.get("message")
            or f.get("description")
        )
        title = str(raw_title).strip() if raw_title is not None else ""
        severity = _normalize_severity_label(f.get("severity") or "Unspecified")
        description = f.get("description")

        raw_category = f.get("category") or f.get("owasp")
        if isinstance(raw_category, str) and raw_category.strip():
            category = raw_category.strip()
        else:
            category = _infer_category(title, description if isinstance(description, str) else None)

        # If the model gave a non-OWASP category but the text strongly indicates OWASP, upgrade it.
        if not _looks_like_owasp(category):
            inferred = _infer_category(title, description if isinstance(description, str) else None)
            if _looks_like_owasp(inferred):
                category = inferred

        # Location keys (handle nested "location" objects too)
        loc_obj = f.get("location") if isinstance(f.get("location"), dict) else {}
        file_ = (
            f.get("file")
            or f.get("file_path")
            or f.get("path")
            or f.get("filename")
            or loc_obj.get("file")
            or loc_obj.get("path")
            or ""
        )
        line = _as_int(f.get("line") or f.get("line_number") or f.get("lineno"))
        if line is None:
            line = _as_int(loc_obj.get("line"))
        code_snippet = f.get("code_snippet") or f.get("evidence") or f.get("snippet")

        validation_status_raw = f.get("validation_status")
        vs_norm = str(validation_status_raw or "").strip().lower()
        if vs_norm in {"yes", "y", "true", "confirmed"}:
            validation_status = "Yes"
        elif vs_norm in {
            "requires_manual_check",
            "manual_check",
            "requires manual check",
            "needs_manual_check",
            "needs manual review",
            "unknown",
            "unclear",
            # Legacy/unsupported: treat "no" as needing manual review rather than a hard invalidation.
            "no",
            "false",
        }:
            validation_status = "Requires manual check"
        else:
            validation_status = "Requires manual check"

        vc_raw = f.get("validation_confidence")
        validation_confidence: float | None
        if isinstance(vc_raw, (int, float)) and not isinstance(vc_raw, bool):
            validation_confidence = max(0.0, min(1.0, float(vc_raw)))
        else:
            validation_confidence = 0.5

        validation_rationale = f.get("validation_rationale")
        if validation_rationale is not None and not isinstance(validation_rationale, str):
            validation_rationale = str(validation_rationale)

        impact = f.get("impact")
        remediation = f.get("remediation") or f.get("fix")
        refs = f.get("references") or []
        if not isinstance(refs, list):
            refs = []
        refs = [str(r) for r in refs if r]

        normalized_findings.append(
            Finding(
                id=fid,
                title=title,
                severity=severity,
                category=category,
                file=str(file_),
                line=line,
                validation_status=validation_status,
                validation_confidence=validation_confidence,
                validation_rationale=validation_rationale,
                code_snippet=str(code_snippet) if code_snippet is not None else None,
                description=str(description) if description is not None else None,
                impact=str(impact) if impact is not None else None,
                remediation=str(remediation) if remediation is not None else None,
                references=refs,
            )
        )

    normalized_findings.sort(key=lambda x: (_severity_rank(x.severity), x.id))

    # Compute counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    for f in normalized_findings:
        key = (f.severity or "").strip().lower()
        if key in counts:
            counts[key] += 1
        else:
            counts["other"] += 1

    # Normalize counts based on the actual findings list.
    # (Models sometimes emit stale/incorrect summary counters, so we recompute.)
    summary.setdefault("assessment_type", report.get("assessment_type", "Static Analysis"))
    summary["total_findings"] = len(normalized_findings)
    summary["critical"] = counts["critical"]
    summary["high"] = counts["high"]
    summary["medium"] = counts["medium"]
    summary["low"] = counts["low"]

    recommendations: list[str] = []
    if isinstance(raw_recs, list):
        recommendations = [str(r) for r in raw_recs if r]

    filetype_scan: dict[str, Any] | None = None
    if isinstance(raw_filetypes, dict):
        filetype_scan = dict(raw_filetypes)
        inc = filetype_scan.get("included_counts") or {}
        ign = filetype_scan.get("ignored_counts") or {}
        if isinstance(inc, dict):
            filetype_scan["included_files_total"] = sum(
                int(v) for v in inc.values() if isinstance(v, (int, float)) and not isinstance(v, bool)
            )
        else:
            filetype_scan["included_files_total"] = 0
        if isinstance(ign, dict):
            filetype_scan["ignored_files_total"] = sum(
                int(v) for v in ign.values() if isinstance(v, (int, float)) and not isinstance(v, bool)
            )
        else:
            filetype_scan["ignored_files_total"] = 0

    return {
        "summary": summary,
        "findings": [f.__dict__ for f in normalized_findings],
        "recommendations": recommendations,
        "filetype_scan": filetype_scan,
        "raw": report,
    }


def _load_report(report_path: str) -> dict[str, Any]:
    md = _read_text(report_path)
    raw = _extract_json_fence(md) or {}
    return _normalize_report(raw)


def _safe_report_path(path: str) -> str | None:
    """
    Only allow loading reports from REPORTS_DIR or DEFAULT_REPORT_PATH.
    This prevents arbitrary file reads via the API.
    """
    if not isinstance(path, str) or not path.strip():
        return None
    p = os.path.abspath(path.strip())
    reports_root = os.path.abspath(REPORTS_DIR)
    default_abs = os.path.abspath(DEFAULT_REPORT_PATH)
    if p == default_abs:
        return p
    if p.startswith(reports_root + os.sep) and p.endswith(".md"):
        return p
    return None


def _tokenize(text: str) -> set[str]:
    parts = re.split(r"[^a-zA-Z0-9_\-/\.]+", (text or "").lower())
    return {p for p in parts if p and len(p) >= 2}


def _format_finding_brief(f: dict[str, Any]) -> str:
    loc = f"{f.get('file') or '—'}" + (f":{f.get('line')}" if f.get("line") is not None else "")
    return (
        f"- id: {f.get('id')}\n"
        f"  title: {f.get('title')}\n"
        f"  severity: {f.get('severity')}\n"
        f"  category: {f.get('category')}\n"
        f"  location: {loc}\n"
        f"  validation: {f.get('validation_status')} (confidence={f.get('validation_confidence')})"
    )


def _format_finding_detail(f: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"ID: {f.get('id')}")
    lines.append(f"Title: {f.get('title')}")
    lines.append(f"Severity: {f.get('severity')}")
    lines.append(f"Category: {f.get('category')}")
    loc = f"{f.get('file') or '—'}" + (f":{f.get('line')}" if f.get("line") is not None else "")
    lines.append(f"Location: {loc}")
    lines.append(f"Validation: {f.get('validation_status')} (confidence={f.get('validation_confidence')})")
    if f.get("validation_rationale"):
        lines.append(f"Rationale: {f.get('validation_rationale')}")
    if f.get("description"):
        lines.append("")
        lines.append("Description:")
        lines.append(str(f.get("description")))
    if f.get("impact"):
        lines.append("")
        lines.append("Impact:")
        lines.append(str(f.get("impact")))
    if f.get("code_snippet"):
        lines.append("")
        lines.append("Evidence:")
        lines.append(str(f.get("code_snippet")))
    if f.get("remediation"):
        lines.append("")
        lines.append("Remediation:")
        lines.append(str(f.get("remediation")))
    refs = f.get("references") or []
    if isinstance(refs, list) and refs:
        lines.append("")
        lines.append("References:")
        for r in refs:
            lines.append(f"- {r}")
    return "\n".join(lines).strip()


def _best_effort_fix_guidance(f: dict[str, Any]) -> str:
    """
    Produce a practical remediation guide even when the report's remediation field is shallow.
    This is heuristic and uses the finding's category/title/snippet.
    """
    title = (f.get("title") or "").lower()
    category = (f.get("category") or "").lower()
    snippet = (f.get("code_snippet") or "").lower()

    tips: list[str] = []
    tips.append("Suggested fix approach:")

    # C / memory safety heuristics
    if any(k in category for k in ["memory safety", "buffer", "overflow"]) or any(
        k in title for k in ["buffer", "overflow", "sprintf", "strcpy", "strcat"]
    ):
        if "sprintf" in snippet or "sprintf" in title:
            tips.append("- Replace `sprintf` with `snprintf` and pass the destination buffer size.")
            tips.append("- Check the return value of `snprintf` for truncation.")
            tips.append("- Prefer safer helpers (e.g., GLib `g_snprintf`) if the project standardizes on them.")
        elif "strcpy" in snippet or "strcat" in snippet:
            tips.append("- Replace unbounded string copies/concats with bounded variants and validate lengths.")
        else:
            tips.append("- Identify the destination buffer and ensure all writes are length-bounded.")
        tips.append("- Add tests for long inputs / edge cases to prevent regressions.")

    # Input validation heuristics
    if "input validation" in category or "validation" in title:
        tips.append("- Validate inputs before use (null checks, bounds, expected types).")
        tips.append("- Define behavior for missing/invalid fields (return error vs default value).")

    remediation = f.get("remediation")
    if remediation:
        tips.append("")
        tips.append("Report remediation:")
        tips.append(str(remediation).strip())

    return "\n".join(tips).strip()


def _format_actionable_answer(f: dict[str, Any]) -> str:
    """
    A more 'helpful by default' response for vague prompts like:
    'tell me more details' or 'how to fix it'.
    """
    parts: list[str] = []
    parts.append(_format_finding_detail(f))
    parts.append("")
    parts.append(_best_effort_fix_guidance(f))
    parts.append("")
    parts.append("Next questions you can ask:")
    parts.append(f"- `evidence for {f.get('id')}`")
    parts.append(f"- `impact for {f.get('id')}`")
    parts.append(f"- `remediation for {f.get('id')}`")
    parts.append(f"- `validation for {f.get('id')}`")
    return "\n".join(parts).strip()


def _select_best_finding(message: str, findings: list[dict[str, Any]]) -> dict[str, Any] | None:
    msg = (message or "").strip()
    if not msg:
        return None
    msg_l = msg.lower()

    # Direct ID mention.
    for f in findings:
        fid = str(f.get("id") or "").strip()
        if fid and fid.lower() in msg_l:
            return f

    # Keyword scoring.
    q = _tokenize(msg)
    if not q:
        return None
    best: tuple[int, dict[str, Any]] | None = None
    for f in findings:
        hay = " ".join(
            str(x or "")
            for x in [
                f.get("id"),
                f.get("title"),
                f.get("severity"),
                f.get("category"),
                f.get("file"),
                f.get("description"),
                f.get("impact"),
                f.get("remediation"),
            ]
        )
        t = _tokenize(hay)
        score = len(q & t)
        if score <= 0:
            continue
        if best is None or score > best[0]:
            best = (score, f)
    return best[1] if best else None


def _answer_from_report(message: str, report: dict[str, Any]) -> dict[str, Any]:
    msg = (message or "").strip()
    findings: list[dict[str, Any]] = report.get("findings") or []

    if not msg:
        return {
            "answer": "Ask about a finding by ID (example: `unsafe-string-function`) or ask for 'list findings'.",
            "matched_finding_id": None,
        }

    msg_l = msg.lower()
    if any(k in msg_l for k in ["list findings", "show findings", "what findings", "list all", "findings list"]):
        if not findings:
            return {"answer": "No findings in the current report.", "matched_finding_id": None}
        out = ["Findings in this report:"]
        for f in findings:
            out.append(_format_finding_brief(f))
        out.append("")
        out.append("Ask: `explain <id>` or `remediation for <id>`.")
        return {"answer": "\n".join(out).strip(), "matched_finding_id": None}

    f = _select_best_finding(msg, findings)
    if not f:
        sample = ", ".join([str(x.get("id")) for x in findings[:5] if isinstance(x, dict) and x.get("id")])
        hint = f" Try: `list findings`." + (f" Known IDs include: {sample}" if sample else "")
        return {"answer": "I couldn't match that question to a specific finding." + hint, "matched_finding_id": None}

    # Intent: if user is vague ("more details" / "how to fix"), respond with the full actionable view.
    if any(
        k in msg_l
        for k in [
            "more detail",
            "more details",
            "tell me more",
            "explain",
            "how to fix",
            "how do i fix",
            "how to fit",  # common typo
            "what is this",
            "what does it mean",
            "walk me through",
        ]
    ):
        return {"answer": _format_actionable_answer(f), "matched_finding_id": f.get("id")}

    # Narrow response if user asked a specific aspect.
    if any(k in msg_l for k in ["remediation", "fix", "patch", "mitigation"]):
        ans = _best_effort_fix_guidance(f)
        return {"answer": f"{f.get('id')}: remediation\n\n{ans}", "matched_finding_id": f.get("id")}
    if any(k in msg_l for k in ["impact", "risk", "why bad", "consequence"]):
        ans = f.get("impact") or "No impact field provided for this finding."
        return {"answer": f"{f.get('id')}: impact\n\n{ans}", "matched_finding_id": f.get("id")}
    if any(k in msg_l for k in ["evidence", "snippet", "code", "where in code"]):
        ans = f.get("code_snippet") or "No evidence/snippet field provided for this finding."
        return {"answer": f"{f.get('id')}: evidence\n\n{ans}", "matched_finding_id": f.get("id")}
    if any(k in msg_l for k in ["validate", "validation", "confidence", "true", "real vuln"]):
        ans = (
            f"validation_status={f.get('validation_status')}, "
            f"confidence={f.get('validation_confidence')}"
            + (f"\n\nRationale: {f.get('validation_rationale')}" if f.get("validation_rationale") else "")
        )
        return {"answer": f"{f.get('id')}: validation\n\n{ans}", "matched_finding_id": f.get("id")}

    return {"answer": _format_finding_detail(f), "matched_finding_id": f.get("id")}


app = Flask(
    __name__,
    template_folder=os.path.join(ASSETS_DIR, "templates"),
    static_folder=os.path.join(ASSETS_DIR, "static"),
)


@app.get("/")
def index():
    report_path = os.getenv("SECURITY_REPORT_PATH") or _latest_report_path()
    data = _load_report(report_path)
    repo_path = (os.getenv("REPO_PATH") or os.path.join(SCRIPT_DIR, "repo")).strip()
    skills_dir = (os.getenv("SKILLS_DIR") or os.path.join(SCRIPT_DIR, "skills")).strip()
    skills_list: list[str] = []
    try:
        if os.path.isdir(skills_dir):
            for name in sorted(os.listdir(skills_dir)):
                if os.path.isfile(os.path.join(skills_dir, name, "SKILL.md")):
                    skills_list.append(name)
    except Exception:
        skills_list = []

    qwen_model = os.getenv("BEDROCK_QWEN_MODEL_ID", "qwen.qwen3-32b-v1:0").strip() or "qwen.qwen3-32b-v1:0"
    alt_default = (
        os.getenv("BEDROCK_ALT_MODEL_ID")
        or os.getenv("BEDROCK_CLAUDE_MODEL_ID", "anthropic.claude-3-5-sonnet-20240620-v1:0")
        or qwen_model
    )
    alt_model = os.getenv("BEDROCK_ALT_ANALYZER_MODEL_ID", alt_default).strip() or alt_default

    meta = {
        "report_path": report_path,
        "report_filename": os.path.basename(report_path),
        "repo_path": repo_path,
        "skills_dir": skills_dir,
        "skills": skills_list,
        "models": {"qwen": qwen_model, "alt": alt_model},
    }
    return render_template("dashboard.html", data=data, meta=meta)


@app.get("/api/report")
def api_report():
    report_path = os.getenv("SECURITY_REPORT_PATH") or _latest_report_path()
    return jsonify(_load_report(report_path))


@app.get("/api/reports")
def api_reports():
    """
    List available timestamped reports for comparison.
    """
    out: list[dict[str, Any]] = []
    try:
        if os.path.isdir(REPORTS_DIR):
            for name in os.listdir(REPORTS_DIR):
                if not (name.endswith(".md") and name.startswith("security_report_")):
                    continue
                p = os.path.join(REPORTS_DIR, name)
                try:
                    mtime = os.path.getmtime(p)
                except Exception:
                    mtime = 0
                out.append(
                    {
                        "name": name,
                        "path": p,
                        "mtime": mtime,
                        "label": name.replace("security_report_", "").replace(".md", ""),
                    }
                )
    except Exception:
        out = []
    out.sort(key=lambda x: x.get("mtime") or 0, reverse=True)
    return jsonify({"reports": out})


@app.get("/api/report_by_path")
def api_report_by_path():
    """
    Load a specific report from REPORTS_DIR for comparison.
    Query: ?path=/abs/path/to/security_report_*.md
    """
    raw = request.args.get("path") or ""
    safe = _safe_report_path(raw)
    if not safe or not os.path.isfile(safe):
        return jsonify({"error": "invalid_path"}), 400
    return jsonify(_load_report(safe))


@app.post("/api/chat")
def api_chat():
    report_path = os.getenv("SECURITY_REPORT_PATH") or _latest_report_path()
    report = _load_report(report_path)
    payload = request.get_json(silent=True) or {}
    message = payload.get("message") if isinstance(payload, dict) else None
    resp = _answer_from_report(str(message or ""), report)
    return jsonify(resp)


@app.get("/api/status")
def api_status():
    st = _load_run_status()
    if st.get("state") == "running" and not _pid_is_alive(st.get("pid")):
        # Process died (or PID reused) but status never got reset → surface this as error so user can rerun.
        now = _utc_now_iso()
        st = {
            **st,
            "state": "error",
            "stage": st.get("stage") or "Unknown",
            "message": "Pipeline process is no longer running (stale status). Please click 'Run scan' again.",
            "finished_at": st.get("finished_at") or now,
            "updated_at": now,
        }
        try:
            with open(RUN_STATUS_PATH, "w", encoding="utf-8") as f:
                json.dump(st, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return jsonify(st)


@app.post("/api/run")
def api_run():
    """
    Trigger the SAST pipeline run in the background.
    Guards against concurrent runs by checking run_status.json state.
    """
    st = _load_run_status()
    if st.get("state") == "running":
        return jsonify({"ok": False, "error": "already_running", "status": st}), 409

    # Run deepagent_sast_demo.py in a subprocess.
    # Use the same python interpreter as the dashboard to avoid venv mismatch.
    script_path = os.path.join(SCRIPT_DIR, "deepagent_sast_demo.py")
    if not os.path.isfile(script_path):
        return jsonify({"ok": False, "error": "missing_script", "path": script_path}), 500

    env = dict(os.environ)
    # Ensure imports work when invoked from repo root.
    existing_pp = env.get("PYTHONPATH", "")
    add_pp = os.path.join(SCRIPT_DIR)
    env["PYTHONPATH"] = add_pp if not existing_pp else add_pp + os.pathsep + existing_pp

    try:
        p = subprocess.Popen(
            [sys.executable, script_path],
            cwd=SCRIPT_DIR,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        return jsonify({"ok": False, "error": "spawn_failed", "message": str(e)}), 500

    # Seed status so UI immediately flips to running; deepagent will keep updating it.
    try:
        with open(RUN_STATUS_PATH, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "state": "running",
                    "stage": "Starting",
                    "progress": 1,
                    "message": "Triggered from dashboard.",
                    "pid": p.pid,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )
    except Exception:
        pass

    return jsonify({"ok": True, "pid": p.pid})


@app.post("/api/stop")
def api_stop():
    """
    Stop a currently running scan (best-effort).
    Kills the stored PID from run_status.json and marks the run as cancelled so the UI unblocks.
    """
    st = _load_run_status()
    pid = st.get("pid")
    if not pid or st.get("state") != "running":
        return jsonify({"ok": True, "stopped": False, "message": "No running scan."})

    # Best-effort terminate.
    try:
        p = int(pid)
        try:
            os.kill(p, 15)  # SIGTERM
        except Exception:
            pass
        try:
            os.kill(p, 9)  # SIGKILL
        except Exception:
            pass
    except Exception:
        pass

    now = _utc_now_iso()
    out = {
        **st,
        "state": "idle",
        "stage": "Cancelled",
        "progress": 0,
        "message": "Scan cancelled by operator.",
        "pid": None,
        "finished_at": st.get("finished_at") or now,
        "updated_at": now,
    }
    try:
        with open(RUN_STATUS_PATH, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return jsonify({"ok": True, "stopped": True})


if __name__ == "__main__":
    # Default to 5056 to avoid collisions with other exercises.
    base_port = int(os.getenv("PORT", "5056"))
    debug = os.getenv("DEBUG", "").strip() in {"1", "true", "TRUE", "yes", "YES"}
    # Avoid watchdog/fsevents issues in some environments by default.
    port = base_port
    for _ in range(20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                break
            except OSError:
                port += 1

    print(f"Dashboard running at http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug, use_reloader=False)

