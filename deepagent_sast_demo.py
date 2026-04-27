"""
DeepAgent SAST Demo - Exercise 23 (Basic Version)

This is the basic DeepAgent demo without skills.
For the skills-enhanced version, see: deepagent_skills_demo.py
"""

from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_aws import ChatBedrockConverse
from dotenv import load_dotenv
import os
import git
import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from tools.filetype_scan import scan as filetype_scan
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.runnables import RunnableLambda
import uuid

try:
    from langgraph.types import Overwrite as _LangGraphOverwrite
except ImportError:  # pragma: no cover
    _LangGraphOverwrite = None

load_dotenv()

# Consistency/recall knobs (env-overridable)
MIN_FINDINGS = int(os.getenv("MIN_FINDINGS", "10").strip() or "10")
TARGET_FINDINGS = int(os.getenv("TARGET_FINDINGS", str(max(20, MIN_FINDINGS))).strip() or str(max(20, MIN_FINDINGS)))

# Recall-first behavior: keep low-confidence findings (do not drop in evaluator/normalizer).
RECALL_FIRST = str(os.getenv("RECALL_FIRST", "1")).strip().lower() not in {"0", "false", "no", "off"}

# Git repo setup
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
repo_url = os.getenv("REPO_URL", "https://github.com/haiwen/seafile.git").strip()
repo_path = os.getenv("REPO_PATH", os.path.join(SCRIPT_DIR, "repo")).strip()
RUN_STATUS_PATH = os.path.join(SCRIPT_DIR, "run_status.json")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_run_status(payload: dict) -> None:
    """
    Write a small JSON status file for the dashboard to poll.
    Best-effort and atomic (write-then-rename).
    """
    try:
        base = {}
        if os.path.isfile(RUN_STATUS_PATH):
            try:
                with open(RUN_STATUS_PATH, "r", encoding="utf-8") as f:
                    existing = json.load(f)
                if isinstance(existing, dict):
                    base = existing
            except Exception:
                base = {}
        data = {**base, **payload, "updated_at": _utc_now_iso()}
        tmp = RUN_STATUS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, RUN_STATUS_PATH)
    except Exception:
        pass

if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, ".git")):
    print("Directory already contains a git repository.")
else:
    try:
        repo = git.Repo.clone_from(repo_url, repo_path)
        print(f"Repository cloned into: {repo_path}")
    except Exception as e:
        print(f"An error occurred while cloning the repository: {e}")

# ------------------------------------------------------------------------------
# LLM setup (Qwen on Amazon Bedrock; uses your existing AWS credentials)
# ------------------------------------------------------------------------------
bedrock_qwen_model_id = os.getenv("BEDROCK_QWEN_MODEL_ID", "qwen.qwen3-32b-v1:0")
# Optional second analyzer model (used in Stage 3 dual-flow).
# Defaults to a *different* model than Qwen so Stage 3 is a real cross-model check.
_alt_default = (
    os.getenv("BEDROCK_ALT_MODEL_ID")
    or os.getenv("BEDROCK_CLAUDE_MODEL_ID")
    or "amazon.nova-lite-v1:0"
)
bedrock_alt_analyzer_model_id = os.getenv("BEDROCK_ALT_ANALYZER_MODEL_ID", _alt_default)
if (bedrock_alt_analyzer_model_id or "").strip() == (bedrock_qwen_model_id or "").strip():
    print(
        "[Config] BEDROCK_ALT_ANALYZER_MODEL_ID is the same as BEDROCK_QWEN_MODEL_ID; "
        "Stage 3 will not be a cross-model check. Set BEDROCK_ALT_ANALYZER_MODEL_ID to a different Bedrock model id."
    )

llm = ChatBedrockConverse(
    model_id=bedrock_qwen_model_id,
    temperature=0.6,
)

# Optional: multi-stage chain of LLMs (separate "roles")
llm_repo_reader = ChatBedrockConverse(model_id=bedrock_qwen_model_id, temperature=0.2)
llm_skill_runner = ChatBedrockConverse(model_id=bedrock_qwen_model_id, temperature=0.2)
# Analyzer should be conservative + evidence-driven (lower temp reduces hallucinations).
llm_analyzer = ChatBedrockConverse(model_id=bedrock_qwen_model_id, temperature=0.2)
llm_analyzer_alt = ChatBedrockConverse(model_id=bedrock_alt_analyzer_model_id, temperature=0.2)
# Evaluator/judge should be as deterministic as possible.
llm_evaluator = ChatBedrockConverse(model_id=bedrock_qwen_model_id, temperature=0.0)

# Backend for local filesystem access - points to the repo directory
# virtual_mode=True restricts access to root_dir only (recommended for security)
filesystem_backend = FilesystemBackend(root_dir=repo_path, virtual_mode=True)

print(f"Repo path: {repo_path}")

REPO_MAP_CACHE_PATH = os.path.join(SCRIPT_DIR, "repo_map_cache.json")


def _costar_prompt(
    *,
    role: str,
    context: str,
    objective: str,
    style: str,
    tone: str,
    audience: str,
    response: str,
    constraints: str = "",
) -> str:
    """
    CO-STAR prompt format (Context, Objective, Style, Tone, Audience, Response).
    We keep this as plain text so it works consistently across Bedrock chat + DeepAgent.
    """
    parts = [
        "CO-STAR",
        "",
        "## Role",
        role.strip(),
        "",
        "## Context",
        context.strip(),
        "",
        "## Objective",
        objective.strip(),
        "",
        "## Style",
        style.strip(),
        "",
        "## Tone",
        tone.strip(),
        "",
        "## Audience",
        audience.strip(),
        "",
        "## Response",
        response.strip(),
    ]
    if constraints.strip():
        parts += ["", "## Constraints", constraints.strip()]
    return "\n".join(parts).strip() + "\n"


def _git_head_hex(repo: str) -> str | None:
    try:
        if not (os.path.isdir(repo) and os.path.isdir(os.path.join(repo, ".git"))):
            return None
        return git.Repo(repo).head.commit.hexsha
    except Exception:
        return None


def _try_load_repo_map_cache(repo: str) -> str | None:
    """If repo exists and cache matches current HEAD, return cached repo map JSON text."""
    head = _git_head_hex(repo)
    if not head or not os.path.isfile(REPO_MAP_CACHE_PATH):
        return None
    try:
        with open(REPO_MAP_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("git_head") != head:
        return None
    text = data.get("repo_map_text")
    return text if isinstance(text, str) and text.strip() else None


def _save_repo_map_cache(repo: str, repo_map_text: str) -> None:
    head = _git_head_hex(repo)
    if not head or not repo_map_text.strip():
        return
    try:
        with open(REPO_MAP_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump({"git_head": head, "repo_map_text": repo_map_text}, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# ------------------------------------------------------------------------------
# Skills setup
# ------------------------------------------------------------------------------
skills_dir = os.path.join(SCRIPT_DIR, "skills")
print(f"Skills directory: {skills_dir}")
if os.path.isdir(skills_dir):
    print("Skills loaded:")
    for skill_name in sorted(os.listdir(skills_dir)):
        skill_path = os.path.join(skills_dir, skill_name, "SKILL.md")
        if os.path.exists(skill_path):
            print(f"  - {skill_name}")
else:
    print("Skills directory not found; continuing without skills.")

# System prompt (formal CO-STAR; no ReAct boilerplate needed)
system_prompt = _costar_prompt(
    role="Security analyst agent specialized in C and Python vulnerability review.",
    context="The source code is available in the current directory.",
    objective=(
        "Identify and explain security vulnerabilities and logic flaws, prioritizing issues that are "
        "supported by concrete code evidence."
    ),
    style="Static-analysis report style: evidence-first, concise, specific, security-accurate.",
    tone="Professional, direct, non-alarmist.",
    audience="Application security engineers and developers fixing vulnerabilities.",
    response=(
        "Output MUST be a single valid JSON object (no markdown fences, no extra text) in the Security "
        "Report schema from the reporting skill:\n"
        '{"summary":{...},"findings":[...],"recommendations":[...]}\n\n'
        "Requirements:\n"
        "- Sort findings by severity (Critical, High, Medium, Low).\n"
        "- Be specific: include file paths, line numbers, and short code snippets when possible.\n"
        "- Avoid false positives: only report issues you can justify from code evidence."
    ),
)

# Lazy-built: compiling DeepAgent at import time is slow; only used for legacy single-agent mode.
_legacy_agent = None


def _get_legacy_agent():
    global _legacy_agent
    if _legacy_agent is None:
        print("[Agent] Initializing DeepAgent (legacy single-agent mode)...")
        _legacy_agent = create_deep_agent(
            model=llm,
            tools=[],
            backend=filesystem_backend,
            system_prompt=system_prompt,
            skills=[skills_dir] if os.path.isdir(skills_dir) else [],
        )
    return _legacy_agent


def _read_skills_text(skills_dir_path: str) -> str:
    if not os.path.isdir(skills_dir_path):
        return ""
    parts: list[str] = []
    for name in sorted(os.listdir(skills_dir_path)):
        p = os.path.join(skills_dir_path, name, "SKILL.md")
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    parts.append(f"\n\n## Skill: {name}\n\n" + f.read())
            except Exception:
                continue
    return "\n".join(parts).strip()


# Fast path: exactly these two SKILL.md files (no other skills, no security-report).
SKILL_MD_PATHS: tuple[str, str] = (
    os.path.join(SCRIPT_DIR, "skills", "owasp-top10", "SKILL.md"),
    os.path.join(SCRIPT_DIR, "skills", "c-python-security", "SKILL.md"),
)

_SKIP_WALK_DIRS = frozenset(
    {".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist", ".idea", "target"}
)


def _read_skill_md_files(paths: tuple[str, ...]) -> str:
    parts: list[str] = []
    for p in paths:
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    parts.append(f"\n\n## File: {p}\n\n" + f.read())
            except Exception:
                continue
    return "\n".join(parts).strip()


def _repo_source_index(repo: str, max_files: int = 120) -> str:
    """Relative paths of likely security-relevant sources (no DeepAgent walk)."""
    exts = {
        ".c",
        ".h",
        ".py",
        ".cpp",
        ".cc",
        ".hpp",
        # Web sources (XSS/SSRF/auth issues often live here)
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".vue",
        ".html",
    }
    # Bias toward likely CVE hotspots so they make it into the limited context window.
    keyword_boost = (
        "websocket",
        "ws",
        "sdoc",
        "seadoc",
        "excalidraw",
        "sanitize",
        "escape",
        "dompurify",
        "innerhtml",
        "href",
        "src",
        "render",
        "markdown",
        "editor",
    )
    boosted: list[str] = []
    paths: list[str] = []
    for root, dirnames, files in os.walk(repo):
        dirnames.sort()
        files.sort()
        dirnames[:] = [d for d in dirnames if d not in _SKIP_WALK_DIRS]
        for fn in files:
            if len(boosted) + len(paths) >= max_files:
                return "\n".join(boosted + paths)
            ext = os.path.splitext(fn)[1].lower()
            if ext in exts:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, repo)
                rel = rel.replace(os.sep, "/")
                rel_l = rel.lower()
                if any(k in rel_l for k in keyword_boost):
                    boosted.append(rel)
                else:
                    paths.append(rel)
    return "\n".join(boosted + paths)


def run_two_skill_fast_scan(task: str) -> str:
    """
    Single Bedrock call on llm_skill_runner: apply only the two SKILL.md files and
    return JSON whose sole substantive output is ``findings`` (wrapped for downstream).
    """
    print("[Fast scan] Skill LLM — owasp-top10 + c-python-security SKILL.md only...")
    skills_text = _read_skill_md_files(SKILL_MD_PATHS)
    if not skills_text.strip():
        return json.dumps(
            {
                "summary": {"assessment_type": "error", "note": "Missing SKILL.md under skills/owasp-top10 or skills/c-python-security"},
                "findings": [],
                "recommendations": [],
            },
            ensure_ascii=False,
            indent=2,
        )

    max_index_files = int(os.getenv("MAX_INDEX_FILES", "240").strip() or "240")
    file_index = _repo_source_index(repo_path, max_files=max_index_files)

    system = _costar_prompt(
        role="Skill runner that applies two provided SKILL.md documents.",
        context="You are given two SKILL.md documents and an optional list of repo file paths for context.",
        objective="Produce findings that are strictly derived from those two skills (no extra categories).",
        style="Checklist-driven; each finding names the skill and the specific checklist/reference used.",
        tone="Neutral and precise.",
        audience="Security engineer triaging a quick skills-only scan.",
        response=(
            'Output one JSON object only (no markdown, no code fences) with required shape:\n'
            '{"findings":[...]}\n\n'
            "Each finding MUST include:\n"
            '- "skill": either "owasp-top10" or "c-python-security"\n'
            '- "skill_reference": short string pointing to the applied skill section/checklist item\n'
            '- "id", "title", "severity", "category", "description"\n'
            '- Optional: "file", "line", "code_snippet", "impact", "remediation", "references"\n'
        ),
        constraints=(
            'Do NOT add issues outside those two skills. Do NOT output "summary" or "recommendations" at top level; '
            'only "findings".'
        ),
    )

    user = f"""Optional operator focus:
{task.strip() or "(none)"}

Repo root (for context only): {repo_path}

Optional sample paths (relative to repo root; may be empty):
{file_index or "(none)"}

--- SKILL documents (only authority for what to report) ---
{skills_text}
"""

    raw = _invoke_json_only(llm_skill_runner, system, user)
    return _wrap_skill_findings_json(raw)


def _invoke_json_only(model: ChatBedrockConverse, system: str, user: str) -> str:
    """
    Invoke a chat model and return raw text. Callers should parse JSON.
    """
    msgs = [SystemMessage(content=system), HumanMessage(content=user)]
    out = model.invoke(msgs)
    return getattr(out, "content", str(out))


def _iter_stream_messages(messages_field: object) -> list:
    """
    DeepAgent/LangGraph stream chunks may set ``messages`` to a list/tuple or to an
    ``Overwrite(value=[...])`` wrapper when replacing the channel (not iterable).
    """
    if messages_field is None:
        return []
    if _LangGraphOverwrite is not None and isinstance(messages_field, _LangGraphOverwrite):
        inner = getattr(messages_field, "value", None)
        if isinstance(inner, (list, tuple)):
            return list(inner)
        return []
    if isinstance(messages_field, (list, tuple)):
        return list(messages_field)
    return []


def _stream_final_content(agent_obj, user_content: str) -> str:
    """
    Helper to run an agent with streaming and return the final assistant content.
    """
    final_text = ""
    for event in agent_obj.stream({"messages": [{"role": "user", "content": user_content}]}):
        for value in event.values():
            if isinstance(value, dict) and "messages" in value:
                for msg in _iter_stream_messages(value.get("messages")):
                    if hasattr(msg, "content") and msg.content:
                        final_text = msg.content
    return final_text


def _norm_severity(s: object) -> str:
    v = str(s or "").strip().lower()
    if v in {"critical", "crit", "p0", "sev0", "s0"}:
        return "Critical"
    if v in {"high", "sev1", "p1", "s1"}:
        return "High"
    if v in {"medium", "med", "moderate", "sev2", "p2", "s2"}:
        return "Medium"
    if v in {"low", "sev3", "p3", "s3", "informational", "info"}:
        return "Low"
    return ""


def _classify_severity(f: dict) -> str:
    """
    Deterministic severity assignment (recall-first).
    Ensures every finding has one of: Critical/High/Medium/Low.
    """
    # If the model already provided a valid severity, keep it.
    existing = _norm_severity(f.get("severity"))
    if existing:
        return existing

    title = str(f.get("title") or "").lower()
    cat = str(f.get("category") or f.get("owasp") or "").lower()
    desc = str(f.get("description") or "").lower()
    impact = str(f.get("impact") or "").lower()
    snippet = str(f.get("code_snippet") or f.get("evidence") or "").lower()
    text = " ".join([title, cat, desc, impact, snippet])

    def has_any(*words: str) -> bool:
        return any(w in text for w in words if w)

    # Critical: RCE / auth bypass / command injection / deserialization / memory corruption primitives.
    if has_any(
        "remote code execution",
        "rce",
        "auth bypass",
        "authentication bypass",
        "command injection",
        "os command injection",
        "shell injection",
        "unsafe deserialization",
        "deserialize",
        "pickle.loads",
        "yaml.load(",
        "arbitrary code",
        "buffer overflow",
        "stack overflow",
        "heap overflow",
        "use-after-free",
        "uaf",
        "double free",
        "format string",
        "sql injection",
        "sqli",
        "ssrf",
    ):
        return "Critical"

    # High: strong exploitation risk or sensitive data compromise patterns.
    if has_any(
        "path traversal",
        "directory traversal",
        "lfi",
        "rfi",
        "xxe",
        "xss",
        "cross-site scripting",
        "csrf",
        "open redirect",
        "hardcoded secret",
        "hard-coded secret",
        "api key",
        "private key",
        "jwt secret",
        "credential",
        "password",
        "token",
        "session fixation",
        "insecure session",
        "broken access control",
        "privilege escalation",
    ):
        return "High"

    # Medium: weaker primitives / misconfig / missing validation with plausible impact.
    if has_any(
        "missing validation",
        "input validation",
        "insufficient validation",
        "unsafe temp file",
        "tmpfile",
        "weak crypto",
        "insecure random",
        "predictable",
        "information disclosure",
        "leak",
        "log injection",
        "header injection",
        "dos",
        "denial of service",
        "resource exhaustion",
        "integer overflow",
        "null dereference",
        "race condition",
    ):
        return "Medium"

    # Low: best-practice issues, hygiene, or uncertain impact.
    return "Low"


def _normalize_report_json_inplace(report: dict) -> None:
    """
    Enforce a minimum report schema so downstream markdown + dashboard rendering
    never has missing titles/locations.
    """
    findings = report.get("findings")
    if not isinstance(findings, list):
        return

    for idx, f in enumerate(findings, start=1):
        if not isinstance(f, dict):
            continue

        # Title: required. Prefer existing title, otherwise derive from description.
        title = f.get("title")
        if not isinstance(title, str) or not title.strip():
            desc = f.get("description")
            if isinstance(desc, str) and desc.strip():
                f["title"] = desc.strip()
            else:
                f["title"] = f"Finding {idx:03d}"

        # Location: accept nested location.{file,path,lines/line}
        if not f.get("file"):
            loc = f.get("location") if isinstance(f.get("location"), dict) else {}
            file_ = f.get("file_path") or f.get("path") or loc.get("file") or loc.get("path")
            if isinstance(file_, str) and file_.strip():
                f["file"] = file_.strip()

        if f.get("line") is None:
            loc = f.get("location") if isinstance(f.get("location"), dict) else {}
            if isinstance(loc.get("line"), int):
                f["line"] = loc["line"]
            elif isinstance(loc.get("lines"), list) and loc["lines"]:
                # Prefer first line for table display.
                first = loc["lines"][0]
                if isinstance(first, int):
                    f["line"] = first

        # Evidence: normalize "evidence" -> "code_snippet" for consistent UI.
        if not f.get("code_snippet") and isinstance(f.get("evidence"), str):
            f["code_snippet"] = f["evidence"]

        # Severity: never allow "Unspecified" (force deterministic classification).
        f["severity"] = _classify_severity(f)

        # Validation: evaluator may attach verdict + confidence. Ensure stable defaults so
        # downstream renderers can always show a column even for legacy/fast-mode outputs.
        vs = f.get("validation_status")
        vs_norm = str(vs or "").strip().lower()
        if vs_norm in {"yes", "y", "true", "confirmed"}:
            f["validation_status"] = "Yes"
        elif vs_norm in {
            "requires_manual_check",
            "manual_check",
            "requires manual check",
            "needs_manual_check",
            "needs manual review",
            "unknown",
            "unclear",
        }:
            f["validation_status"] = "Requires manual check"
        else:
            # This pipeline intentionally avoids a "No" state; unclear/invalid items should be treated as
            # manual review rather than a false negative. (Recall-first: we keep findings, even if low confidence.)
            f["validation_status"] = "Requires manual check"
        vc = f.get("validation_confidence")
        if not isinstance(vc, (int, float)) or isinstance(vc, bool):
            f["validation_confidence"] = 0.5
        else:
            # Clamp to [0, 1] for easy UI formatting + later calibration.
            f["validation_confidence"] = max(0.0, min(1.0, float(vc)))

        # Confidence calibration: encourage near-1.0 when the evaluator says "Yes".
        # Keep manual-check confidence below the "Yes" band to preserve meaning.
        if f.get("validation_status") == "Yes":
            f["validation_confidence"] = max(float(f["validation_confidence"]), 0.95)
        else:
            f["validation_confidence"] = min(float(f["validation_confidence"]), 0.94)


def run_multi_stage_chain() -> str:
    """
    Multi-stage chained pipeline:
      1) Repo-reader DeepAgent creates a repo map (JSON).
      2) Skill-runner LLM turns repo map + skills into an analysis plan (JSON).
      3) Analyzer LLM produces the security report (JSON).
      4) Evaluator LLM validates/fixes the report and outputs final JSON.
    Returns a JSON string (final report).
    """
    # Stage 1: repo map (tool-using agent, no skills)
    repo_reader_prompt = _costar_prompt(
        role="Repo mapper agent for security review (tool-using).",
        context="You have read access to the repository via filesystem tools in the current directory.",
        objective="Produce a security-oriented repo map to guide later analysis.",
        style="Structured JSON repo map; include real paths and focused rationales.",
        tone="Direct and factual.",
        audience="A downstream security analyzer agent and human reviewer.",
        response=(
            "Return a single JSON object (no markdown) with keys:\n"
            '- "repo_overview": string\n'
            '- "trust_boundaries": list\n'
            '- "security_sensitive_areas": list of {path, why}\n'
            '- "files_to_review": list of {path, rationale}\n'
            '- "search_terms": list of strings\n'
        ),
        constraints="Be specific and cite real file paths from the repo.",
    )

    cached = _try_load_repo_map_cache(repo_path)
    if cached is not None:
        print("[Multi-stage] Repo map loaded from cache (skipping repo reader LLM).")
        repo_map_text = cached
    else:
        repo_reader_agent = create_deep_agent(
            model=llm_repo_reader,
            tools=[],
            backend=filesystem_backend,
            system_prompt=repo_reader_prompt,
            skills=[],
        )

        repo_map_text = ""
        for event in repo_reader_agent.stream(
            {"messages": [{"role": "user", "content": "Explore the repo and produce the JSON repo map."}]}
        ):
            for value in event.values():
                if isinstance(value, dict) and "messages" in value:
                    for msg in _iter_stream_messages(value.get("messages")):
                        if hasattr(msg, "content") and msg.content:
                            repo_map_text = msg.content
        if repo_map_text.strip():
            _save_repo_map_cache(repo_path, repo_map_text)

    # Stage 2: apply skills into a plan
    skills_text = _read_skills_text(skills_dir)
    plan_system = _costar_prompt(
        role="Security analysis planner.",
        context="You will be given a repo map JSON and the contents of the security skills.",
        objective="Generate an actionable, prioritized analysis plan for static review.",
        style="Structured JSON plan; concrete checks and search terms.",
        tone="Professional and unambiguous.",
        audience="A tool-using analyzer agent that will execute the plan.",
        response=(
            "Output JSON only with keys:\n"
            '- "scope": list of paths\n'
            '- "checks": list of {category, what_to_look_for, example_search_terms}\n'
            '- "prioritization": ordered list of focus areas\n'
        ),
    )
    plan_user = f"""Inputs (execute in CO-STAR plan format above).

Repo map JSON:
{repo_map_text}

Skills:
{skills_text}
"""
    plan_text = _invoke_json_only(llm_skill_runner, plan_system, plan_user)

    # Stage 3: generate the security report JSON (dual-flow: Qwen + alt analyzer in parallel)
    report_system = _costar_prompt(
        role="Static security analysis report writer.",
        context="You will be given a repo map JSON and a plan JSON produced from skills.",
        objective="Produce a complete security report JSON in the required schema.",
        style="Evidence-driven report; specific, concrete fields; no filler.",
        tone="Professional and direct.",
        audience="Security engineers and developers remediating findings.",
        response=(
            'Output a single JSON object only (no markdown) in the Security Report schema:\n'
            '{"summary":{...},"findings":[...],"recommendations":[...]}\n\n'
            "Each finding must include: id, title, severity, category, file, line, code_snippet, description, impact, remediation, references."
        ),
    )
    report_user = f"""Inputs (execute in CO-STAR report format above).

Repo map JSON:
{repo_map_text}

Plan JSON:
{plan_text}
"""
    def _run_report(model) -> str:
        return _invoke_json_only(model, report_system, report_user)

    report_texts: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = {
            ex.submit(_run_report, llm_analyzer): "qwen",
            ex.submit(_run_report, llm_analyzer_alt): "alt",
        }
        for fut in as_completed(futs):
            report_texts[futs[fut]] = fut.result()

    report_text_qwen = report_texts.get("qwen", "")
    report_text_alt = report_texts.get("alt", "")

    # Stage 4: validate both (Qwen evaluator), compare, and produce confidence_score
    eval_system = _costar_prompt(
        role="Strict security report validator and corrector.",
        context="You will be given a candidate security report JSON.",
        objective="Return a corrected, schema-compliant report JSON (de-hallucinated where needed).",
        style="Deterministic JSON validation and correction; minimal changes beyond correctness.",
        tone="Strict and precise.",
        audience="Downstream markdown renderer and dashboard consumer.",
        response=(
            "Output corrected JSON only (single object; no markdown; no extra text).\n\n"
            "In addition to schema correction, you MUST add per-finding validation fields:\n"
            '- "validation_status": EXACTLY one of ["Yes","Requires manual check"]\n'
            '- "validation_confidence": number in [0,1]\n'
            '- "validation_rationale": short string explaining the verdict\n\n'
            "Validation rubric (use the repo filesystem tools to verify):\n"
            '- **Yes**: evidence is present in the referenced file and the vulnerability claim is technically sound\n'
            "  for the code shown (real unsafe sink / missing check / dangerous pattern). "
            "Return confidence in [0.95, 1.0] unless there is a very specific unresolved nuance.\n"
            "- **Requires manual check**: use ONLY when, after reading surrounding context, you still cannot\n"
            "  determine whether the claim is technically correct (e.g., missing variable provenance / macro expansion / build flags).\n"
            "  Keep confidence < 0.95.\n"
        ),
        constraints=(
            "- Ensure it is a valid JSON object.\n"
            "- Ensure required keys exist: summary/findings/recommendations.\n"
            "- Ensure each finding has required fields (MUST include a non-empty title) and plausible file+line.\n"
            "- RECALL-FIRST: Do NOT drop findings. If evidence is missing/unclear, keep the finding but set validation_status='Requires manual check', lower validation_confidence, and explain why.\n"
            "- For each remaining finding, open the referenced file and confirm the code snippet exists.\n"
            "- If a snippet is missing but the underlying issue is present elsewhere nearby, correct the line/snippet.\n"
            "- IMPORTANT: Do NOT output any other validation_status values (no lowercase, no 'No').\n"
            "- Bias towards 'Yes' when the dangerous sink/pattern is clearly present in code, even if exploitability depends on inputs; "
            "state preconditions in validation_rationale.\n"
            "- Confidence must reflect how directly the evidence supports the claim; when 'Yes', make it close to 1.0."
        ),
    )
    def _run_eval(report_text: str) -> str:
        eval_user = f"""Report JSON to validate/correct:

Report JSON:
{report_text}
"""
        return _invoke_json_only(llm_evaluator, eval_system, eval_user)

    final_texts: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs = {
            ex.submit(_run_eval, report_text_qwen): "qwen",
            ex.submit(_run_eval, report_text_alt): "alt",
        }
        for fut in as_completed(futs):
            final_texts[futs[fut]] = fut.result()

    final_qwen = final_texts.get("qwen", "")
    final_alt = final_texts.get("alt", "")

    obj_qwen = _extract_json_object(final_qwen) or _extract_json_object(report_text_qwen)
    obj_alt = _extract_json_object(final_alt) or _extract_json_object(report_text_alt)
    similarity = _report_similarity(obj_qwen, obj_alt)

    chosen_obj = obj_qwen if _report_quality_score(obj_qwen) >= _report_quality_score(obj_alt) else obj_alt
    other_obj = obj_alt if chosen_obj is obj_qwen else obj_qwen
    chosen_text = final_qwen if chosen_obj is obj_qwen else final_alt
    chosen_source = "qwen" if chosen_obj is obj_qwen else "alt"

    if isinstance(chosen_obj, dict):
        summary = chosen_obj.get("summary")
        if not isinstance(summary, dict):
            summary = {"note": str(summary)} if summary is not None else {}
        summary["confidence_score"] = _overall_confidence_from_comparison(
            chosen_obj, other_obj, similarity=similarity
        )
        summary["eval_comparison"] = {
            "chosen": chosen_source,
            "similarity": similarity,
            "models": {"qwen": bedrock_qwen_model_id, "alt": bedrock_alt_analyzer_model_id},
        }
        chosen_obj["summary"] = summary
        return json.dumps(chosen_obj, ensure_ascii=False)

    return chosen_text


def build_multi_stage_chain():
    """
    LangChain LCEL-style chain that mirrors scripts/llm_training/audit.py:
      RunnableLambda(...) | repo_reader_step | skill_step | analysis_step | eval_step
    """

    def repo_reader_step(state: dict) -> dict:
        _write_run_status(
            {
                "state": "running",
                "stage": "Repo reader (mapping)",
                "progress": 15,
                "message": "Building repo map…",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        repo_reader_prompt = _costar_prompt(
            role="Repo mapper agent for security review (tool-using).",
            context="You have read access to the repository via filesystem tools in the current directory.",
            objective="Produce a security-oriented repo map to guide later analysis.",
            style="Structured JSON repo map; include real paths and focused rationales.",
            tone="Direct and factual.",
            audience="A downstream security analyzer agent and human reviewer.",
            response=(
                "Return a single JSON object (no markdown) with keys:\n"
                '- "repo_overview": string\n'
                '- "trust_boundaries": list\n'
                '- "security_sensitive_areas": list of {path, why}\n'
                '- "files_to_review": list of {path, rationale}\n'
                '- "search_terms": list of strings\n'
            ),
            constraints="Be specific and cite real file paths from the repo.",
        )

        cached = _try_load_repo_map_cache(repo_path)
        if cached is not None:
            print("[Multi-stage] Repo map loaded from cache (skipping repo reader LLM).")
            _write_run_status(
                {
                    "state": "running",
                    "stage": "Repo reader (cached)",
                    "progress": 25,
                    "message": "Using cached repo map.",
                    "run_id": state.get("run_id"),
                    "started_at": state.get("started_at"),
                }
            )
            print("[Stage 1/4] Repo reader complete (cached).")
            return {**state, "repo_map_json": cached}

        repo_reader_agent = create_deep_agent(
            model=llm_repo_reader,
            tools=[],
            backend=filesystem_backend,
            system_prompt=repo_reader_prompt,
            skills=[],
        )

        repo_map_text = ""
        for event in repo_reader_agent.stream(
            {"messages": [{"role": "user", "content": "Explore the repo and produce the JSON repo map."}]}
        ):
            for value in event.values():
                if isinstance(value, dict) and "messages" in value:
                    for msg in _iter_stream_messages(value.get("messages")):
                        if hasattr(msg, "content") and msg.content:
                            repo_map_text = msg.content
        if repo_map_text.strip():
            _save_repo_map_cache(repo_path, repo_map_text)
        _write_run_status(
            {
                "state": "running",
                "stage": "Repo reader (done)",
                "progress": 25,
                "message": "Repo map complete.",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        print("[Stage 1/4] Repo reader complete.")

        return {**state, "repo_map_json": repo_map_text}

    def skill_step(state: dict) -> dict:
        _write_run_status(
            {
                "state": "running",
                "stage": "Skill runner (planning)",
                "progress": 35,
                "message": "Generating analysis plan…",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        skills_text = _read_skills_text(skills_dir)
        plan_text = _invoke_json_only(
            llm_skill_runner,
            _costar_prompt(
                role="Security analysis planner.",
                context="You will be given a repo map JSON and the contents of the security skills.",
                objective="Generate an actionable, prioritized analysis plan for static review.",
                style="Structured JSON plan; concrete checks and search terms.",
                tone="Professional and unambiguous.",
                audience="A tool-using analyzer agent that will execute the plan.",
                response=(
                    "Output JSON only with keys:\n"
                    '- "scope": list of paths\n'
                    '- "checks": list of {category, what_to_look_for, example_search_terms}\n'
                    '- "prioritization": ordered list of focus areas\n'
                ),
            ),
            f"""Inputs (execute in CO-STAR plan format above).

Repo map JSON:
{state.get('repo_map_json', '')}

Skills:
{skills_text}
""",
        )
        _write_run_status(
            {
                "state": "running",
                "stage": "Skill runner (done)",
                "progress": 45,
                "message": "Plan complete.",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        print("[Stage 2/4] Skill runner complete.")
        return {**state, "analysis_plan_json": plan_text}

    def analysis_step(state: dict) -> dict:
        _write_run_status(
            {
                "state": "running",
                "stage": "Analyzer (evidence gathering)",
                "progress": 60,
                "message": "Collecting evidence and drafting findings…",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        # Tool-using analysis agent (skills loaded). This forces evidence collection.
        analysis_system = _costar_prompt(
            role="Tool-using static security analyst for a C/Python codebase.",
            context=(
                "The source code is available in the current directory. Security skills are loaded in context "
                "(OWASP Top 10 + C/Python AppSec)."
            ),
            objective=(
                "Execute the provided analysis plan across the repo and produce an evidence-backed security report "
                "JSON with multiple distinct findings."
            ),
            style="Evidence-first; each finding includes verbatim snippet and precise location.",
            tone="Professional, direct, careful about false positives.",
            audience="Security engineers and developers remediating vulnerabilities.",
            response=(
                'Output a single JSON object only (no markdown) with shape:\n'
                '{"summary":{...},"findings":[...],"recommendations":[...]}\n\n'
                "For each finding (REQUIRED fields): id, title, severity, category, file, line, code_snippet, description, impact, remediation, references."
            ),
            constraints=(
                "- Use filesystem tools (ls/glob/grep/read_file) to gather evidence.\n"
                "- Report findings only when you have a concrete code snippet from a real file (via tools) that supports the claim.\n"
                "- Breadth: execute every major checks entry from the analysis plan across multiple categories/paths.\n"
                f"- Minimum {TARGET_FINDINGS} distinct findings (non-empty array). If you cannot reach this, explain why in summary.review_note.\n"
                "- Do not return an empty findings array after opening only one or two files; work through files_to_review/scope/search_terms."
            ),
        )

        skills_digest = _read_skills_text(skills_dir)
        if len(skills_digest) > 18000:
            skills_digest = skills_digest[:18000] + "\n\n[... remainder of skills omitted for length; follow loaded skill rules in your system context. ...]"

        analysis_user = f"""Use this repo map and plan to produce the final security report JSON.

Repo map JSON:
{state.get('repo_map_json', '')}

Plan JSON:
{state.get('analysis_plan_json', '')}

Security skills (digest — use together with your full skill instructions):
{skills_digest}

Operator priority (additional focus):
{state.get("input_task", "").strip() or "(none)"}

Execute the plan: use `search_terms` and `checks` from the plan to drive greps and reads across the repo map scope.
Aim for as many distinct, evidence-backed findings as you can justify (often many in a large C/Python codebase); do not stop after one or two issues if more are clearly supported by snippets.
Each finding must still have a verbatim `code_snippet` from `read_file`/`grep` output.
"""
        def _run_one(label: str, model) -> tuple[str, str]:
            analysis_agent = create_deep_agent(
                model=model,
                tools=[],
                backend=filesystem_backend,
                system_prompt=analysis_system,
                skills=[skills_dir] if os.path.isdir(skills_dir) else [],
            )
            return (label, _stream_final_content(analysis_agent, analysis_user))

        reports: dict[str, str] = {}
        errors: dict[str, str] = {}
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = {
                ex.submit(_run_one, "qwen", llm_analyzer): "qwen",
                ex.submit(_run_one, "alt", llm_analyzer_alt): "alt",
            }
            for fut in as_completed(futs):
                label = futs[fut]
                try:
                    _label, txt = fut.result()
                    reports[_label] = txt
                except Exception as e:
                    errors[label] = str(e)
                    reports[label] = ""

        if errors and reports.get("qwen"):
            print(f"[Stage 3/4] Alt analyzer failed; continuing with Qwen only. ({errors.get('alt','')})")
        elif errors and not reports.get("qwen"):
            # Both failed; surface the first error.
            raise RuntimeError(errors.get("qwen") or errors.get("alt") or "Analyzer failed")

        _write_run_status(
            {
                "state": "running",
                "stage": "Analyzer (done)",
                "progress": 75,
                "message": "Draft report complete." + (" (alt failed; used qwen only)" if errors.get("alt") else ""),
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        print("[Stage 3/4] Analyzer complete.")
        return {
            **state,
            "report_json_qwen": reports.get("qwen", ""),
            "report_json_alt": reports.get("alt", ""),
        }

    def eval_step(state: dict) -> dict:
        _write_run_status(
            {
                "state": "running",
                "stage": "Evaluator (verifying)",
                "progress": 85,
                "message": "Verifying findings against repo…",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        # Tool-using judge: cross-check file/line/snippet against repo and fix schema.
        judge_system = _costar_prompt(
            role="Tool-using security report judge/verifier.",
            context="The source code is available in the current directory; you can read files to verify evidence.",
            objective="Validate, correct, and de-hallucinate the draft security report JSON while preserving real issues.",
            style="Verifier/judge: cross-check evidence, normalize paths, fix schema; minimal necessary edits.",
            tone="Strict, precise, deterministic.",
            audience="Downstream markdown report + dashboard renderer.",
            response=(
                "Output a single corrected JSON object only (no markdown; no extra text).\n\n"
                "You MUST add per-finding validation fields:\n"
                '- "validation_status": EXACTLY one of ["Yes","Requires manual check"]\n'
                '- "validation_confidence": number in [0,1]\n'
                '- "validation_rationale": short string explaining the verdict\n\n'
                "Rubric:\n"
                "- **Yes**: snippet is confirmed in code and claim is technically sound for that snippet. Confidence in [0.95, 1.0].\n"
                "- **Requires manual check**: use ONLY when you cannot decide correctness from code you can read. Confidence < 0.95.\n"
                "\n"
                "Important: If you can confirm the snippet exists in the referenced file AND the described risky API/sink is present, "
                "you should set validation_status=Yes (even if exploitability depends on inputs), and note the preconditions in validation_rationale. "
                "Try hard to avoid 'Requires manual check' by reading surrounding context.\n"
            ),
            constraints=(
                "- Validate the provided JSON report.\n"
                "- For EACH finding, verify evidence by reading the referenced file/line and confirming the code_snippet matches (allow minor whitespace/line-ending differences; fix line if needed).\n"
                "- If a path does not open, try glob/grep from the repo root and normalize the path before deleting a finding.\n"
                "- Remove a finding only when the code clearly contradicts the claim after a reasonable read.\n"
                "- Prefer correcting file path/line/snippet over deleting when the vulnerability is present.\n"
                "- Do not output findings: [] if the draft had findings unless you have verified every draft finding as invalid.\n"
                "- Ensure every remaining finding has required fields: id, title, severity, category, file, line, code_snippet, description, impact, remediation, references.\n"
                "- Ensure every remaining finding ALSO has validation_status/validation_confidence/validation_rationale."
            ),
        )

        def _eval_one(label: str, report_text: str) -> tuple[str, str]:
            judge_agent = create_deep_agent(
                model=llm_evaluator,
                tools=[],
                backend=filesystem_backend,
                system_prompt=judge_system,
                skills=[],
            )
            judge_user = f"""Validate, correct, and de-hallucinate this report JSON. If needed, read files to verify.

Report JSON:
{report_text}
"""
            return (label, _stream_final_content(judge_agent, judge_user))

        final_texts: dict[str, str] = {}
        report_qwen = state.get("report_json_qwen", "") or ""
        report_alt = state.get("report_json_alt", "") or ""
        with ThreadPoolExecutor(max_workers=2) as ex:
            futs = {}
            if report_qwen.strip():
                futs[ex.submit(_eval_one, "qwen", report_qwen)] = "qwen"
            if report_alt.strip():
                futs[ex.submit(_eval_one, "alt", report_alt)] = "alt"
            for fut in as_completed(futs):
                label, txt = fut.result()
                final_texts[label] = txt

        final_qwen = final_texts.get("qwen", "")
        final_alt = final_texts.get("alt", "")

        obj_qwen = _extract_json_object(final_qwen) or _extract_json_object(state.get("report_json_qwen", ""))
        obj_alt = _extract_json_object(final_alt) or _extract_json_object(state.get("report_json_alt", ""))
        if obj_qwen and obj_alt:
            similarity = _report_similarity(obj_qwen, obj_alt)
        else:
            similarity = 0.0

        chosen_obj = obj_qwen if _report_quality_score(obj_qwen) >= _report_quality_score(obj_alt) else obj_alt
        other_obj = obj_alt if chosen_obj is obj_qwen else obj_qwen
        chosen_text = final_qwen if chosen_obj is obj_qwen else final_alt
        chosen_source = "qwen" if chosen_obj is obj_qwen else "alt"

        if isinstance(chosen_obj, dict):
            summary = chosen_obj.get("summary")
            if not isinstance(summary, dict):
                summary = {"note": str(summary)} if summary is not None else {}
            summary["confidence_score"] = _overall_confidence_from_comparison(
                chosen_obj, other_obj, similarity=similarity
            )
            summary["eval_comparison"] = {
                "chosen": chosen_source,
                "similarity": similarity,
                "models": {"qwen": bedrock_qwen_model_id, "alt": bedrock_alt_analyzer_model_id},
            }
            chosen_obj["summary"] = summary
            final_text = json.dumps(chosen_obj, ensure_ascii=False)
        else:
            final_text = chosen_text
        _write_run_status(
            {
                "state": "running",
                "stage": "Evaluator (done)",
                "progress": 92,
                "message": "Evaluation complete.",
                "run_id": state.get("run_id"),
                "started_at": state.get("started_at"),
            }
        )
        print("[Stage 4/4] Evaluator complete.")
        return {**state, "final_json": final_text}

    full_chain = (
        RunnableLambda(lambda state: state)
        | RunnableLambda(repo_reader_step)
        | RunnableLambda(skill_step)
        | RunnableLambda(analysis_step)
        | RunnableLambda(eval_step)
    )
    return full_chain


def analyze_code(input_task: str) -> str:
    """
    Analyze code using the DeepAgent with streaming output.
    """
    print("[Agent] Running (streaming)...")
    final_output = ""
    for event in _get_legacy_agent().stream({"messages": [{"role": "user", "content": input_task}]}):
        for key, value in event.items():
            if "Middleware" in key:
                continue
            if isinstance(value, dict) and "messages" in value:
                for msg in _iter_stream_messages(value.get("messages")):
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        for tc in msg.tool_calls:
                            print(f"  -> {tc['name']}")
                    elif hasattr(msg, "content") and msg.content:
                        final_output = msg.content
    return final_output


def _extract_json_object(text: str) -> dict | None:
    """
    Best-effort extraction of a JSON object from model output.
    Returns None if parsing fails.
    """
    if not text:
        return None
    cleaned = text.strip()
    # Common case: pure JSON
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass

    # Fallback: try substring from first "{" to last "}"
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    snippet = cleaned[start : end + 1]
    try:
        obj = json.loads(snippet)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _norm_s(s: object) -> str:
    if s is None:
        return ""
    return str(s).strip().lower()


def _finding_fingerprint(f: dict) -> tuple[str, str, str, str, str]:
    title = _norm_s(f.get("title"))
    file_ = _norm_s(f.get("file") or f.get("file_path") or f.get("path"))
    line = _norm_s(f.get("line") or f.get("line_number") or f.get("lineno"))
    category = _norm_s(f.get("category") or f.get("owasp"))
    severity = _norm_s(f.get("severity"))
    return (title, file_, line, category, severity)


def _report_similarity(a: dict | None, b: dict | None) -> float:
    """
    Jaccard similarity over finding fingerprints. Returns [0,1].
    """
    if not isinstance(a, dict) or not isinstance(b, dict):
        return 0.0
    fa = a.get("findings")
    fb = b.get("findings")
    if not isinstance(fa, list) or not isinstance(fb, list):
        return 0.0
    sa = {_finding_fingerprint(f) for f in fa if isinstance(f, dict)}
    sb = {_finding_fingerprint(f) for f in fb if isinstance(f, dict)}
    if not sa and not sb:
        return 0.0
    union = sa | sb
    if not union:
        return 0.0
    return len(sa & sb) / max(1, len(union))


def _report_quality_score(r: dict | None) -> float:
    """
    Recall-first scoring: prefer reports that keep more findings (even if low confidence),
    while still preferring higher-validated findings when available.
    """
    if not isinstance(r, dict):
        return 0.0
    findings = r.get("findings")
    if not isinstance(findings, list) or not findings:
        return 0.0
    yes_confs: list[float] = []
    manual_count = 0
    for f in findings:
        if not isinstance(f, dict):
            continue
        status = _norm_s(f.get("validation_status"))
        conf = _clamp01(f.get("validation_confidence"), default=0.5)
        if status == "yes":
            yes_confs.append(conf)
        elif status:
            manual_count += 1
    avg_yes = (sum(yes_confs) / len(yes_confs)) if yes_confs else 0.0
    # Prefer more findings overall; don't penalize manual-check findings (user wants max capture).
    total_count = len([f for f in findings if isinstance(f, dict)])
    return (total_count * 0.02) + (len(yes_confs) * 0.06) + avg_yes + (manual_count * 0.005)


def _overall_confidence_from_comparison(chosen: dict | None, other: dict | None, *, similarity: float) -> float:
    """
    Single [0,1] score from evaluator validations + inter-model agreement.
    """
    chosen_score = _report_quality_score(chosen)
    quality = _clamp01(0.5 + chosen_score, default=0.5)
    return _clamp01((0.55 * quality) + (0.45 * _clamp01(similarity, default=0.0)), default=0.5)


def _wrap_skill_findings_json(raw: str) -> str:
    """Normalize skill-LLM output to full report shape for markdown/dashboard."""
    obj = _extract_json_object(raw)
    if not obj:
        return raw
    findings = obj.get("findings")
    if not isinstance(findings, list):
        findings = []
    out = {
        "summary": {
            "application": "Target repository",
            "assessment_type": "Skill-only findings (OWASP Top 10 + C/Python SKILL.md)",
            "skill_sources": [p.replace("\\", "/") for p in SKILL_MD_PATHS],
        },
        "findings": findings,
        "recommendations": [],
    }
    return json.dumps(out, ensure_ascii=False, indent=2)


def _findings_count(raw: str) -> int:
    obj = _extract_json_object(raw or "")
    if not obj:
        return 0
    findings = obj.get("findings")
    if not isinstance(findings, list):
        return 0
    return len([f for f in findings if isinstance(f, dict)])


def _prefer_non_empty_findings(final_json: str, draft_json: str | None) -> str:
    """
    If the evaluator returns JSON with zero findings but the analyzer draft had
    findings, use the draft (judge often over-strips on path/snippet mismatch).
    """
    if _findings_count(final_json) > 0:
        return final_json
    if draft_json and _findings_count(draft_json) > 0:
        return draft_json
    return final_json


def _ensure_qwen_findings_in_final(final_json: str, qwen_draft_json: str | None) -> str:
    """
    Ensure the final report includes *at least* all findings that Qwen produced in Stage 3.

    Rationale: we prefer to keep the evaluator's validated output, but never want to drop
    potentially useful Qwen findings entirely. Any appended findings are marked as
    "Requires manual check" with conservative confidence.
    """
    final_obj = _extract_json_object(final_json) or {}
    qwen_obj = _extract_json_object(qwen_draft_json or "") or {}

    final_findings = final_obj.get("findings")
    qwen_findings = qwen_obj.get("findings")
    if not isinstance(final_findings, list) or not isinstance(qwen_findings, list):
        return final_json

    def _key(f: dict) -> str:
        fid = f.get("id")
        if isinstance(fid, str) and fid.strip():
            return fid.strip()
        title = str(f.get("title") or "").strip().lower()
        file_ = str(f.get("file") or f.get("path") or "").strip().lower()
        line = f.get("line")
        line_s = str(line) if isinstance(line, int) else ""
        return f"t:{title}|f:{file_}|l:{line_s}"

    existing: dict[str, dict] = {}
    out: list[dict] = []
    for f in final_findings:
        if not isinstance(f, dict):
            continue
        k = _key(f)
        if k in existing:
            continue
        existing[k] = f
        out.append(f)

    added = 0
    for f in qwen_findings:
        if not isinstance(f, dict):
            continue
        k = _key(f)
        if k in existing:
            continue
        nf = dict(f)
        nf["validation_status"] = "Requires manual check"
        nf["validation_confidence"] = _clamp01(nf.get("validation_confidence"), default=0.65)
        nf["validation_rationale"] = (
            "Carried over from the Qwen analyzer draft to avoid dropping potential issues; not re-validated by the evaluator."
        )
        out.append(nf)
        existing[k] = nf
        added += 1

    if added <= 0:
        return final_json

    summary = final_obj.get("summary")
    if not isinstance(summary, dict):
        summary = {"note": str(summary)} if summary is not None else {}
    summary["total_findings"] = len(out)
    # If we appended unvalidated findings, conservatively penalize the confidence score.
    try:
        cs = float(summary.get("confidence_score")) if summary.get("confidence_score") is not None else None
    except Exception:
        cs = None
    if cs is not None:
        total = max(1, len(out))
        penalty = 0.50 * (added / total)
        summary["confidence_score"] = _clamp01(cs * (1.0 - penalty), default=0.5)
    final_obj["summary"] = summary
    final_obj["findings"] = out
    return json.dumps(final_obj, ensure_ascii=False)


def _merge_findings_unique(primary_raw: str, secondary_raw: str, *, min_findings: int) -> str:
    """
    Merge findings from two report JSON strings, keeping stable order and deduping.
    This is a recall-boosting fallback: prefer existing vetted findings, then add extras.
    """
    a = _extract_json_object(primary_raw or "") or {}
    b = _extract_json_object(secondary_raw or "") or {}
    a_findings = a.get("findings") if isinstance(a.get("findings"), list) else []
    b_findings = b.get("findings") if isinstance(b.get("findings"), list) else []

    def _key(f: dict) -> tuple:
        fid = str(f.get("id") or "").strip().lower()
        if fid:
            return ("id", fid)
        return (
            "sig",
            str(f.get("title") or "").strip().lower(),
            str(f.get("file") or f.get("file_path") or "").strip().lower(),
            str(f.get("line") or f.get("line_number") or "").strip(),
            str(f.get("severity") or "").strip().lower(),
            str(f.get("category") or f.get("owasp") or "").strip().lower(),
        )

    merged: list[dict] = []
    seen: set[tuple] = set()
    for src in (a_findings, b_findings):
        for f in src:
            if not isinstance(f, dict):
                continue
            k = _key(f)
            if k in seen:
                continue
            seen.add(k)
            merged.append(f)
            if len(merged) >= max(min_findings, len(a_findings)):
                # Only early-exit if we've already satisfied the minimum and kept all original.
                pass

    out = dict(a) if isinstance(a, dict) else {}
    out["findings"] = merged
    # keep summary consistent if present
    if isinstance(out.get("summary"), dict):
        out["summary"]["total_findings"] = len(merged)
    return json.dumps(out, ensure_ascii=False, indent=2)


def _synthesize_report_if_too_few_findings(chain_out: dict, task: str, *, min_findings: int) -> str:
    """
    After the four-stage chain, if there are too few findings, run a recall-boost
    tool-using pass to gather additional evidence-backed findings (not hallucinated).
    """
    merged = _prefer_non_empty_findings(
        chain_out.get("final_json", ""),
        chain_out.get("report_json"),
    )
    if _findings_count(merged) >= min_findings:
        return merged

    print(
        f"[Multi-stage] Only {_findings_count(merged)} finding(s); recall-boost pass to reach {min_findings}+..."
    )
    existing = _extract_json_object(merged) or {}
    existing_findings = existing.get("findings") if isinstance(existing.get("findings"), list) else []
    existing_titles = []
    for f in existing_findings:
        if isinstance(f, dict):
            t = f.get("title")
            if isinstance(t, str) and t.strip():
                existing_titles.append(t.strip())
    existing_titles = existing_titles[:40]

    repo_map = (chain_out.get("repo_map_json") or "")[:12000]
    plan = (chain_out.get("analysis_plan_json") or "")[:12000]

    boost_system = _costar_prompt(
        role="Tool-using static security analyst (recall boost pass).",
        context="You can use filesystem tools to grep and read code under the repo root.",
        objective=f"Add more distinct, evidence-backed findings until there are at least {min_findings}.",
        style="High-recall but evidence-driven: every finding must include a verbatim snippet and exact file path.",
        tone="Direct and technical.",
        audience="Security engineers and developers.",
        response=(
            'Output ONE JSON object only (no markdown) with keys: "summary", "findings", "recommendations".\n'
            f'The output must contain at least {min_findings} distinct findings.'
        ),
        constraints=(
            "- Only add findings that you can support with an exact `file` + `line` + verbatim `code_snippet` from a real file.\n"
            "- Avoid duplicates of the existing findings (titles given in the user message).\n"
            "- Prefer concrete vulnerability patterns in C: unsafe string/memory APIs, integer overflow, bounds checks, format strings,\n"
            "  path traversal, symlink/TOCTOU, authZ checks, injection.\n"
            "- Also check Python/web surfaces if present.\n"
        ),
    )
    boost_user = f"""Operator task:
{task}

Repo map JSON (truncated):
{repo_map}

Plan JSON (truncated):
{plan}

Existing findings (avoid duplicates; titles):
{json.dumps(existing_titles, ensure_ascii=False)}

Instructions:
- Focus on finding *additional* issues not already listed.
- Use grep to find risky APIs and security-sensitive handlers, then read surrounding code to confirm.
"""

    boost_agent = create_deep_agent(
        model=llm_analyzer,
        tools=[],
        backend=filesystem_backend,
        system_prompt=boost_system,
        skills=[skills_dir] if os.path.isdir(skills_dir) else [],
    )
    raw = _stream_final_content(boost_agent, boost_user)
    if _findings_count(raw) > 0:
        return _merge_findings_unique(merged, raw, min_findings=min_findings)
    return merged


def _severity_rank(sev: str) -> int:
    s = (sev or "").strip().lower()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order.get(s, 4)


def _infer_category(title: str | None, description: str | None) -> str:
    """
    Lightweight heuristic so the report never shows "Uncategorized".
    Prefer OWASP Top 10 where it cleanly applies; otherwise use a precise native-code label.
    """
    t = (title or "").lower()
    d = (description or "").lower()
    text = f"{t}\n{d}"

    # OWASP Top 10 (2021) mappings (heuristic).
    if any(k in text for k in ["crypto", "crypt", "pbkdf2", "salt", "key deriv", "encryption", "cipher"]):
        return "A02:2021 - Cryptographic Failures"
    if any(k in text for k in ["sql injection", "sqli", "command injection", "injection", "xss", "template injection"]):
        return "A03:2021 - Injection"
    if any(k in text for k in ["auth", "authorization", "idor", "access control", "permission"]):
        return "A01:2021 - Broken Access Control"

    # Native-code / general categories.
    if any(k in text for k in ["buffer overflow", "out-of-bounds", "oob", "use-after-free", "uaf", "double free"]):
        return "Memory Safety"
    if any(k in text for k in ["race condition", "toctou", "symlink", "hardlink"]):
        return "Race Condition / TOCTOU"

    return "Security Misconfiguration / Best Practice"


def _clamp01(x: object, default: float = 0.5) -> float:
    if not isinstance(x, (int, float)) or isinstance(x, bool):
        return float(default)
    return max(0.0, min(1.0, float(x)))


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _extract_cves_from_text(*parts: object) -> list[str]:
    cves: set[str] = set()
    for p in parts:
        if not isinstance(p, str) or not p.strip():
            continue
        for m in _CVE_RE.findall(p):
            cves.add(m.upper())
    return sorted(cves)


def _read_json_file_best_effort(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _write_json_file_best_effort(path: str, data: dict) -> None:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        return


def _fetch_json_url(url: str, timeout_s: float = 6.0) -> dict | None:
    """
    Minimal fetch helper (stdlib only). Returns None on any failure.
    """
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "nextgen-dashboard/1.0 (+local)",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8", errors="ignore"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _lookup_cve_best_effort(cve_id: str, cache: dict) -> dict | None:
    """
    Look up a CVE using an unauthenticated public API.
    Currently uses CIRCL's CVE API as a lightweight source of truth.
    """
    cve = (cve_id or "").strip().upper()
    if not cve or not _CVE_RE.fullmatch(cve):
        return None

    cached = cache.get(cve)
    if isinstance(cached, dict) and cached.get("_ok") is True:
        return cached
    if cached == {"_ok": False}:
        return None

    # Source: https://cve.circl.lu/api/
    data = _fetch_json_url(f"https://cve.circl.lu/api/cve/{urllib.parse.quote(cve)}", timeout_s=6.0)
    if not isinstance(data, dict) or not data.get("id"):
        cache[cve] = {"_ok": False}
        return None

    summary = data.get("summary") or data.get("description") or ""
    cvss = data.get("cvss")
    cvss3 = data.get("cvss3")
    out = {
        "_ok": True,
        "id": cve,
        "summary": str(summary)[:8000],
        "cvss": cvss if isinstance(cvss, (int, float)) else None,
        "cvss3": cvss3 if isinstance(cvss3, (int, float)) else None,
        "source": "cve.circl.lu",
        "links": {
            "cve_org": f"https://www.cve.org/CVERecord?id={cve}",
            "opencve": f"https://www.opencve.io/cve/{cve}",
            "cvedetails": f"https://www.cvedetails.com/cve/{cve}/",
        },
    }
    cache[cve] = out
    return out


def _enrich_findings_with_cve_evidence_inplace(report: dict, cache_path: str | None = None) -> None:
    """
    If findings mention CVE IDs, confirm they exist in a public CVE dataset and
    attach evidence + optionally boost/lower validation confidence.
    """
    if os.getenv("DISABLE_CVE_LOOKUPS", "").strip().lower() in {"1", "true", "yes", "y"}:
        return

    findings = report.get("findings")
    if not isinstance(findings, list):
        return

    cache: dict = {}
    if isinstance(cache_path, str) and cache_path.strip():
        cache = _read_json_file_best_effort(cache_path)

    changed_cache = False
    for f in findings:
        if not isinstance(f, dict):
            continue

        cves = _extract_cves_from_text(
            f.get("title"),
            f.get("description"),
            f.get("remediation"),
            f.get("validation_rationale"),
            f.get("code_snippet"),
        )
        if not cves:
            continue

        evidence: list[dict] = []
        missing: list[str] = []
        for cve in cves[:5]:
            before = cache.get(cve)
            hit = _lookup_cve_best_effort(cve, cache=cache)
            after = cache.get(cve)
            if before != after:
                changed_cache = True
            if hit:
                evidence.append(hit)
            else:
                missing.append(cve)

        # Attach evidence for the dashboard / report consumers.
        f["cve_ids"] = cves
        if evidence:
            f["cve_evidence"] = evidence

        # Confidence calibration:
        # - If CVE(s) mentioned and at least one confirmed exists, that is strong evidence the finding references a real vuln record.
        # - If CVE(s) mentioned but none resolve, keep it below the "Yes" band (or nudge down) to encourage manual verification.
        status = str(f.get("validation_status") or "").strip()
        if status not in {"Yes", "Requires manual check"}:
            status = "Requires manual check"
        conf = _clamp01(f.get("validation_confidence"), default=0.5)

        if evidence:
            # Keep semantics: "Yes" remains near-1.0, but don't force "Yes" solely from CVE lookup.
            if status == "Yes":
                conf = max(conf, 0.97)
            else:
                conf = min(max(conf, 0.90), 0.94)

            if not f.get("validation_rationale"):
                f["validation_rationale"] = f"References confirmed CVE record(s): {', '.join([e.get('id') for e in evidence if isinstance(e, dict) and e.get('id')])}."
        elif missing:
            # Referenced CVEs couldn't be confirmed → reduce confidence and request manual check.
            status = "Requires manual check"
            conf = min(conf, 0.90)
            if not f.get("validation_rationale"):
                f["validation_rationale"] = f"Mentions CVE ID(s) that could not be confirmed via CVE lookup ({', '.join(missing)}); manual verification recommended."

        # Respect global banding rules used elsewhere.
        if status == "Yes":
            conf = max(conf, 0.95)
        else:
            conf = min(conf, 0.94)

        f["validation_status"] = status
        f["validation_confidence"] = _clamp01(conf, default=0.5)

    if changed_cache and isinstance(cache_path, str) and cache_path.strip():
        _write_json_file_best_effort(cache_path, cache)


def _read_file_text_best_effort(repo_path: str, file_path: str) -> str | None:
    """
    Read a repo file for deterministic validation.
    Supports findings that use repo-absolute paths like "/lib/utils.c".
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return None
    fp = file_path.strip()
    if fp.startswith("/"):
        fp = fp[1:]
    abs_path = os.path.join(repo_path, fp)
    try:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def _auto_validate_findings_inplace(report: dict, repo_path: str) -> None:
    """
    Deterministic (non-LLM) validation pass to improve evaluator performance:
    - Confirms snippet exists in referenced file.
    - Applies targeted heuristics for common footguns to produce Yes / Requires manual check with confidence.
    Falls back to Requires manual check when ambiguous.
    """
    findings = report.get("findings")
    if not isinstance(findings, list):
        return

    dangerous_calls = {
        "sprintf": ("Yes", 0.95, "Unbounded formatting call (`sprintf`) present; prefer bounded variant."),
        "vsprintf": ("Yes", 0.95, "Unbounded formatting call (`vsprintf`) present; prefer bounded variant."),
        "gets": ("Yes", 0.99, "Use of `gets` is inherently unsafe (unbounded input)."),
        "strcpy": ("Yes", 0.95, "Potential unbounded copy (`strcpy`); verify destination size and bounds."),
        "strcat": ("Yes", 0.95, "Potential unbounded concat (`strcat`); verify destination size and bounds."),
        # Even when exploitability depends on provenance, the sink is real and worth confirming as a legit risk.
        # We bias to "Yes" and state the preconditions in the rationale.
        "memcpy(": ("Yes", 0.96, "`memcpy` sink present; vulnerability depends on attacker control of length/source/destination bounds."),
        "memmove(": ("Yes", 0.96, "`memmove` sink present; vulnerability depends on attacker control of length/source/destination bounds."),
        "system(": ("Yes", 0.97, "Command execution sink (`system`) present; verify attacker control of arguments."),
        "popen(": ("Yes", 0.96, "Command execution sink (`popen`) present; verify attacker control of arguments."),
    }

    dangerous_python = {
        "pickle.loads": ("Yes", 0.97, "Unsafe deserialization (`pickle.loads`) is dangerous with untrusted input."),
        "yaml.load": ("Yes", 0.96, "`yaml.load` can be unsafe; confirm SafeLoader/safe_load (or explicit Loader) is used."),
        "eval(": ("Yes", 0.97, "`eval` executes code; unsafe with untrusted input."),
        "exec(": ("Yes", 0.97, "`exec` executes code; unsafe with untrusted input."),
        "subprocess.run": ("Yes", 0.95, "`subprocess.run` present; risk depends on argument construction and `shell=True` usage."),
        "shell=true": ("Yes", 0.96, "Subprocess with `shell=True` is a command injection risk with untrusted input."),
    }

    dangerous_web = {
        "innerhtml": ("Yes", 0.95, "DOM XSS sink (`innerHTML`) present; verify input sanitization."),
        "dangerouslysetinnerhtml": ("Yes", 0.95, "React XSS sink (`dangerouslySetInnerHTML`) present; verify sanitization."),
        "setattribute(\"href\"": ("Yes", 0.95, "Setting `href` from data can be XSS/open-redirect; ensure protocol allowlist and URL sanitization."),
        "setattribute(\"src\"": ("Yes", 0.95, "Setting `src` from data can be XSS/SSRF; ensure protocol allowlist and URL sanitization."),
    }

    for f in findings:
        if not isinstance(f, dict):
            continue

        file_ = f.get("file")
        snippet = f.get("code_snippet")
        title = str(f.get("title") or "")
        desc = str(f.get("description") or "")
        cat = str(f.get("category") or "")
        text = f"{title}\n{desc}\n{cat}".lower()

        file_text = _read_file_text_best_effort(repo_path, str(file_ or ""))
        snippet_ok = False
        if isinstance(snippet, str) and snippet.strip() and isinstance(file_text, str):
            snippet_ok = snippet.strip() in file_text

        status = str(f.get("validation_status") or "").strip()
        if status not in {"Yes", "Requires manual check"}:
            status = "Requires manual check"
        confidence = _clamp01(f.get("validation_confidence"), default=0.5)
        rationale = f.get("validation_rationale")
        if rationale is not None and not isinstance(rationale, str):
            rationale = str(rationale)

        if not snippet_ok:
            status = "Requires manual check"
            confidence = min(confidence, 0.94)
            rationale = rationale or "Unable to deterministically confirm snippet in referenced file; manual verification recommended."
            f["validation_status"] = status
            f["validation_confidence"] = max(0.50, _clamp01(confidence, default=0.5))
            f["validation_rationale"] = rationale
            continue

        snip_l = str(snippet).lower() if isinstance(snippet, str) else ""
        matched = False
        for call, (s, c, why) in dangerous_calls.items():
            if call in snip_l:
                matched = True
                status, confidence = s, max(confidence, c)
                rationale = rationale or why
                break

        if not matched:
            for call, (s, c, why) in dangerous_python.items():
                if call in snip_l:
                    matched = True
                    status, confidence = s, max(confidence, c)
                    rationale = rationale or why
                    break

        if not matched:
            for call, (s, c, why) in dangerous_web.items():
                if call in snip_l:
                    matched = True
                    status, confidence = s, max(confidence, c)
                    rationale = rationale or why
                    break

        if not matched:
            if "input validation" in text or "validate" in text:
                status = "Requires manual check"
                confidence = min(max(confidence, 0.80), 0.94)
                rationale = rationale or "Snippet exists, but security impact/exploitability depends on call sites and inputs."
            else:
                status = "Requires manual check"
                confidence = min(max(confidence, 0.80), 0.94)
                rationale = rationale or "Snippet exists, but automated validator cannot fully assess exploitability; manual review recommended."

        f["validation_status"] = status
        # Final calibration: keep "Yes" in near-1.0 band; keep manual check below that.
        if status == "Yes":
            confidence = max(confidence, 0.95)
        else:
            confidence = min(confidence, 0.94)
        f["validation_confidence"] = _clamp01(confidence, default=0.5)
        f["validation_rationale"] = rationale


def _to_markdown_report(raw_output: str, repo_url: str, repo_path: str, skills_dir: str) -> str:
    """
    Convert the agent's JSON security report into a readable markdown file.
    If JSON isn't available, store raw output with minimal framing.
    """
    report = _extract_json_object(raw_output)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    if not report:
        return (
            "# Security Report\n\n"
            f"- **Generated**: {generated_at}\n"
            f"- **Repo**: {repo_url}\n"
            f"- **Local path**: `{repo_path}`\n\n"
            "## Raw Output\n\n"
            f"{raw_output}\n"
        )

    # Attach a deterministic inventory of repo filetypes (skills-informed).
    try:
        fts = filetype_scan(repo_path=repo_path, skills_dir=skills_dir).__dict__
        report["filetype_scan"] = fts
    except Exception as e:
        report["filetype_scan_error"] = str(e)

    _normalize_report_json_inplace(report)
    # CVE evidence can improve confidence calibration when findings explicitly reference CVE IDs.
    _enrich_findings_with_cve_evidence_inplace(
        report,
        cache_path=os.path.join(repo_path, ".cve_cache.json"),
    )
    _auto_validate_findings_inplace(report, repo_path=repo_path)

    # Ensure recommendations exist even when models omit them (common in fast runs).
    recs = report.get("recommendations")
    if not isinstance(recs, list) or not [r for r in recs if isinstance(r, str) and r.strip()]:
        recs_out: list[str] = []
        findings_any = report.get("findings")
        if isinstance(findings_any, list):
            # Prefer explicit per-finding remediation text.
            for f in findings_any:
                if not isinstance(f, dict):
                    continue
                r = f.get("remediation")
                if isinstance(r, str):
                    r = r.strip()
                    if r and r not in recs_out:
                        recs_out.append(r)
                if len(recs_out) >= 8:
                    break
        # Fall back to a small, high-signal baseline.
        if not recs_out:
            recs_out = [
                "Prioritize issues with confirmed evidence and high exploitability; fix memory-safety and injection sinks first.",
                "Replace unsafe C string/format APIs (`strcpy`, `strcat`, `sprintf`) with bounded variants and add length checks at trust boundaries.",
                "For any rich-content rendering or attribute injection (href/src/innerHTML), enforce strict sanitization and protocol allowlists.",
                "Add unit tests/regression tests for identified vulnerable code paths and enable compiler/toolchain hardening where applicable.",
            ]
        report["recommendations"] = recs_out

    summary = report.get("summary") or {}
    findings = report.get("findings") or []
    recommendations = report.get("recommendations") or []

    # Be defensive: models sometimes return the right keys but wrong types.
    if not isinstance(summary, dict):
        summary = {"note": str(summary)}
    if not isinstance(findings, list):
        findings = []
    if not isinstance(recommendations, list):
        recommendations = []
    findings_sorted = sorted(
        [f for f in findings if isinstance(f, dict)],
        key=lambda f: (_severity_rank(f.get("severity")), str(f.get("id") or "")),
    )

    # Always derive severity counts from findings so the markdown header can't show all zeros
    # when findings exist (models often omit summary breakdown fields).
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings_sorted:
        sev = _norm_severity(f.get("severity")) or _classify_severity(f)
        if sev in sev_counts:
            sev_counts[sev] += 1

    total = summary.get("total_findings")
    if total is None:
        total = len(findings_sorted)

    critical = summary.get("critical")
    high = summary.get("high")
    medium = summary.get("medium")
    low = summary.get("low")

    # If the breakdown is missing (or incorrectly all zeros) but we have findings, use derived counts.
    try:
        c0 = int(critical) if critical is not None else None
        h0 = int(high) if high is not None else None
        m0 = int(medium) if medium is not None else None
        l0 = int(low) if low is not None else None
    except Exception:
        c0 = h0 = m0 = l0 = None
    if findings_sorted and ((c0, h0, m0, l0) == (0, 0, 0, 0) or any(v is None for v in (c0, h0, m0, l0))):
        critical, high, medium, low = (
            sev_counts["Critical"],
            sev_counts["High"],
            sev_counts["Medium"],
            sev_counts["Low"],
        )

    app = summary.get("application") or "Unknown"
    assessment_type = summary.get("assessment_type") or "Static Analysis"

    md: list[str] = []
    md.append("# Security Report")
    md.append("")
    md.append(f"- **Generated**: {generated_at}")
    md.append(f"- **Repo**: {repo_url}")
    md.append(f"- **Local path**: `{repo_path}`")
    md.append(f"- **Application**: {app}")
    md.append(f"- **Assessment type**: {assessment_type}")
    md.append("")
    md.append("## Executive summary")
    md.append("")
    md.append(
        f"- **Findings**: {total} "
        f"(Critical: {critical if critical is not None else sev_counts['Critical']}, "
        f"High: {high if high is not None else sev_counts['High']}, "
        f"Medium: {medium if medium is not None else sev_counts['Medium']}, "
        f"Low: {low if low is not None else sev_counts['Low']})"
    )
    md.append("")

    md.append("## Findings (prioritized)")
    md.append("")
    if not findings_sorted:
        md.append("_No detailed findings were returned in the expected format._")
    else:
        for f in findings_sorted:
            fid = f.get("id") or "FINDING"
            title = f.get("title") or "Untitled finding"
            severity = _norm_severity(f.get("severity")) or _classify_severity(f)
            description = f.get("description")

            category = f.get("category") or f.get("owasp") or _infer_category(title, description)

            # Support alternate schemas (e.g. file_path/line_number/evidence).
            file_ = f.get("file") or f.get("file_path") or f.get("path") or "Unknown"
            line = f.get("line")
            if line is None:
                line = f.get("line_number") or f.get("lineno")
            loc = f"{file_}" + (f":{line}" if line is not None else "")

            md.append(f"### {fid}: {title}")
            md.append("")
            md.append(f"- **Severity**: {severity}")
            md.append(f"- **Category**: {category}")
            sk = f.get("skill")
            sk_ref = f.get("skill_reference")
            if sk or sk_ref:
                md.append(f"- **Skill source**: `{sk or '?'}`" + (f" — {sk_ref}" if sk_ref else ""))
            md.append(f"- **Location**: `{loc}`")
            md.append("")
            if description:
                md.append("**Description**")
                md.append("")
                md.append(str(description).strip())
                md.append("")
            impact = f.get("impact")
            if impact:
                md.append("**Impact**")
                md.append("")
                md.append(str(impact).strip())
                md.append("")
            snippet = f.get("code_snippet") or f.get("evidence") or f.get("snippet")
            if snippet:
                md.append("**Evidence**")
                md.append("")
                md.append("```")
                md.append(str(snippet).rstrip())
                md.append("```")
                md.append("")
            remediation = f.get("remediation")
            if remediation:
                md.append("**Remediation**")
                md.append("")
                md.append(str(remediation).strip())
                md.append("")
            refs = f.get("references")
            if isinstance(refs, list) and refs:
                md.append("**References**")
                md.append("")
                for r in refs:
                    md.append(f"- {r}")
                md.append("")

    md.append("## Recommendations")
    md.append("")
    if isinstance(recommendations, list) and recommendations:
        for r in recommendations:
            md.append(f"- {r}")
    else:
        md.append("_No recommendations provided._")
    md.append("")

    if isinstance(report.get("filetype_scan"), dict):
        fts = report["filetype_scan"]
        md.append("## Filetypes scanned (skills-informed)")
        md.append("")
        md.append(f"- **Skills detected**: {', '.join(fts.get('skills') or []) or '(none)'}")
        md.append("")
        md.append("**Included extensions (counts)**")
        md.append("")
        included_counts = fts.get("included_counts") or {}
        if isinstance(included_counts, dict) and included_counts:
            for ext, count in included_counts.items():
                md.append(f"- `{ext}`: {count}")
        else:
            md.append("_No allowlist inferred (treating as all file types)._")
        md.append("")
        md.append("**Ignored extensions (counts)**")
        md.append("")
        ignored_counts = fts.get("ignored_counts") or {}
        if isinstance(ignored_counts, dict) and ignored_counts:
            for ext, count in ignored_counts.items():
                md.append(f"- `{ext}`: {count}")
        else:
            md.append("_None (based on current inferred allowlist)._")
        md.append("")

    md.append("## Raw JSON")
    md.append("")
    md.append("```json")
    md.append(json.dumps(report, indent=2, ensure_ascii=False))
    md.append("```")
    md.append("")

    return "\n".join(md)


def _terminal_safe_preview(text: str, max_chars: int = 4000) -> str:
    # Terminals don't render markdown fences; strip them for readability.
    cleaned = text.replace("```", "")
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars] + "\n\n[... truncated preview; full report saved to file ...]\n"


if __name__ == "__main__":
    print("DeepAgent SAST Demo")
    print("=" * 50)
    print(f"[Models] Qwen: {bedrock_qwen_model_id}")
    print(f"[Models] Alt analyzer: {bedrock_alt_analyzer_model_id}")

    run_id = os.getenv("RUN_ID", "").strip() or uuid.uuid4().hex[:12]
    started_at = _utc_now_iso()
    _write_run_status(
        {
            "state": "running",
            "stage": "Starting",
            "progress": 3,
            "message": "Pipeline started.",
            "run_id": run_id,
            "started_at": started_at,
            "finished_at": None,
        }
    )

    analysis_task = os.getenv(
        "ANALYSIS_TASK",
        """Analyze this codebase for security vulnerabilities.

Start by exploring the directory structure. Then pick one or two C source files that look security-sensitive (request parsing, RPC, networking, file I/O, string handling) and do a deep review.

Prioritize memory safety issues and attacker-controlled inputs, and be explicit about exploitability preconditions.
Also look for web security issues (XSS, injection, unsafe deserialization), especially in any JavaScript/TypeScript code handling rich content or WebSocket messages.
""",
    ).strip()

    print("\nDeepAgent SAST:")
    _msc = os.getenv("MULTI_STAGE_CHAIN", "1").strip().lower()
    if not _msc:
        _msc = "1"
    try:
        if _msc in {"agent", "legacy"}:
            print("[Mode] Legacy streaming DeepAgent (all skills on agent).")
            _write_run_status(
                {
                    "state": "running",
                    "stage": "Legacy agent (streaming)",
                    "progress": 25,
                    "message": "Running single-agent analysis…",
                    "run_id": run_id,
                    "started_at": started_at,
                }
            )
            result = analyze_code(analysis_task)
        elif _msc in {"fast", "two-skill", "skill-only"}:
            print("[Mode] Fast two-SKILL.md scan (no four-stage chain).")
            _write_run_status(
                {
                    "state": "running",
                    "stage": "Fast skill scan",
                    "progress": 35,
                    "message": "Running fast scan…",
                    "run_id": run_id,
                    "started_at": started_at,
                }
            )
            result = run_two_skill_fast_scan(analysis_task)
        else:
            # Default: four-stage chain (#1 repo DeepAgent → #2 plan LLM → #3 analyzer DeepAgent → #4 judge DeepAgent).
            print(
                "[Mode] Four-stage chain: repo reader → skill plan → analyzer (skills on) → evaluator (skills off)."
            )
            chain = build_multi_stage_chain()
            out = chain.invoke({"input_task": analysis_task, "run_id": run_id, "started_at": started_at})
            raw_final = out.get("final_json", "")
            draft_qwen = out.get("report_json_qwen", "")
            draft_alt = out.get("report_json_alt", "")
            # Prefer evaluator output, but never drop Qwen findings entirely.
            merged = _prefer_non_empty_findings(raw_final, draft_qwen if draft_qwen else draft_alt)
            merged = _ensure_qwen_findings_in_final(merged, draft_qwen)
            if merged != raw_final:
                print(
                    "[Multi-stage] Evaluator returned no findings; using analyzer draft "
                    f"({_findings_count(merged)} finding(s))."
                )
            result = _synthesize_report_if_too_few_findings(
                {**out, "final_json": merged, "report_json": draft_qwen or draft_alt},
                analysis_task,
                min_findings=MIN_FINDINGS,
            )
            if _findings_count(result) > _findings_count(merged):
                print(f"[Multi-stage] Synthesis ensured {_findings_count(result)} finding(s) in report.")

        _write_run_status(
            {
                "state": "running",
                "stage": "Rendering report",
                "progress": 96,
                "message": "Rendering markdown report…",
                "run_id": run_id,
                "started_at": started_at,
            }
        )
        markdown_report = _to_markdown_report(result, repo_url=repo_url, repo_path=repo_path, skills_dir=skills_dir)
    except Exception as e:
        msg = str(e)
        if "end of its life" in msg.lower() or "resourcenotfoundexception" in msg.lower():
            msg = (
                msg
                + f" | Check model ids: Qwen={bedrock_qwen_model_id}, Alt={bedrock_alt_analyzer_model_id}"
            )
        _write_run_status(
            {
                "state": "error",
                "stage": "Error",
                "progress": 100,
                "message": msg,
                "run_id": run_id,
                "started_at": started_at,
                "finished_at": _utc_now_iso(),
            }
        )
        raise

    # Save each run with a timestamp for traceability.
    reports_dir = os.path.join(SCRIPT_DIR, "security_reports")
    os.makedirs(reports_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    stamped_report_path = os.path.join(reports_dir, f"security_report_{stamp}.md")

    # Also write/update "latest" for convenience (dashboard + quick open).
    latest_report_path = os.path.join(SCRIPT_DIR, "security_report.md")

    for path in (stamped_report_path, latest_report_path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(markdown_report)

    _write_run_status(
        {
            "state": "done",
            "stage": "Complete",
            "progress": 100,
            "message": f"Wrote report: {os.path.basename(stamped_report_path)}",
            "run_id": run_id,
            "started_at": started_at,
            "finished_at": _utc_now_iso(),
        }
    )

    print("\n" + "=" * 50)
    print("RESULT:")
    print(_terminal_safe_preview(markdown_report))
    print(f"\nFull report written to: {stamped_report_path}")
    print(f"Latest report written to: {latest_report_path}")
