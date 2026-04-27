# Group Project: AI‑Powered AppSec Analysis Workflow

## Background

This folder implements a repeatable **AI-powered AppSec workflow**: analyze an open-source repo with **DeepAgent**, **skills**, and Bedrock, generate a structured report, and present results as **Markdown** and a **dashboard**. By default `deepagent_sast_demo.py` runs the **four-stage chain** (repo reader → skill plan → analyzer → evaluator); a lightweight **fast skill scan** is optional.

- **Default target repo**: [haiwen/seafile](https://github.com/haiwen/seafile) (C-heavy with some Python)
- **Default clone location**: `repo/`

## Running the SAST demo

`deepagent_sast_demo.py` imports `tools/` as a top-level package, so run it with this repo root on `PYTHONPATH` (or run from this directory).

## Setup: `.env` + `venv`

Create a virtualenv and install deps (adjust if you use `uv`/`poetry`):

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

Create your local env file:

```bash
cp .env.example .env
```

Then edit `.env` as needed (scripts call `dotenv.load_dotenv()` automatically; the repo ignores `.env` and `.venv/`).

Optional: run the dashboard UI:

```bash
source .venv/bin/activate
python dashboard_app.py
```

```bash
PYTHONPATH=. python deepagent_sast_demo.py
```

### Run modes

The runner supports multiple modes via `MULTI_STAGE_CHAIN`:

- **Default (recommended)**: `MULTI_STAGE_CHAIN=1` — four-stage chain (repo map → plan → analyzer → evaluator).
- **Fast**: `MULTI_STAGE_CHAIN=fast` — skill-only scan (quick, but may be less grounded).
- **Legacy**: `MULTI_STAGE_CHAIN=legacy` (or `agent`) — single streaming agent mode.

Example:

```bash
PYTHONPATH=. MULTI_STAGE_CHAIN=1 python deepagent_sast_demo.py
```

## DeepAgent

DeepAgent compiles **lazily** for legacy single-agent mode. The **default** path builds DeepAgents inside the four-stage chain (repo reader, analyzer, evaluator) on each run.

### Qwen model setup

```44:49:deepagent_sast_demo.py
bedrock_qwen_model_id = os.getenv("BEDROCK_QWEN_MODEL_ID", "qwen.qwen3-32b-v1:0")

llm = ChatBedrockConverse(
    model_id=bedrock_qwen_model_id,
    temperature=0.6,
)
```

### DeepAgent setup

```59:61:deepagent_sast_demo.py
filesystem_backend = FilesystemBackend(root_dir=repo_path, virtual_mode=True)
```

```188:199:deepagent_sast_demo.py
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
```

## Skills

Skills live in `skills/`.

- `skills/owasp-top10/` — OWASP Top 10 framing and categories
- `skills/c-python-security/` — C memory-safety + Python security guidance
- `skills/security-report/` — structured reporting schema (summary/findings/recommendations)

## Custom tools

Two small tools sit outside the DeepAgent chain: one inventories file types from the repo, the other previews the generated report in a browser.

### 1. Filetype scan (`tools/filetype_scan.py`)

- **Purpose**: detect skills in `skills/`, infer an extension allowlist, then count extensions under `repo/` as **included vs ignored** (rules-informed inventory).
- **Run (text)**:

```bash
python tools/filetype_scan.py
```

- **Run (JSON)**:

```bash
python tools/filetype_scan.py --format json
```

The SAST demo also embeds the same scan into each report’s JSON/Markdown output.

### 2. Dashboard previewer (`dashboard_app.py`)

- **Purpose**: serve a **read-only** UI over the latest security report.
- **Input**: prefers the newest `security_reports/security_report_*.md`, otherwise `security_report.md`.
- **JSON extract**: reads the Markdown report, pulls the JSON object from the **## Raw JSON** section’s fenced `json` code block, and uses it for the UI and for `GET /api/report`.
- **Report assistant chat**: a floating chat widget to query findings (examples: `list findings`, `explain unsafe-string-function`, `remediation for <id>`). Backed by `POST /api/chat`.
- **Workflow status**: `GET /api/status` exposes live pipeline progress (backed by `run_status.json` written by the pipeline).
- **Trigger a run from the UI**: the workflow panel includes a **Run scan** button that calls `POST /api/run` to start `deepagent_sast_demo.py` in the background.
  - Includes a **concurrency guard**: if a run is already in progress, the API returns HTTP 409.
- **View JSON**: the top-right “View JSON” button opens the latest normalized report JSON in a modal (fetched from `GET /api/report`).
- **Run**:

```bash
python dashboard_app.py
```

## Multi‑LLM chained pipeline

The workflow runs a **four-stage LLM chain** (repo map → skills-based plan → evidence-backed analysis → evaluation).

```708:714:deepagent_sast_demo.py
    full_chain = (
        RunnableLambda(lambda state: state)
        | RunnableLambda(repo_reader_step)
        | RunnableLambda(skill_step)
        | RunnableLambda(analysis_step)
        | RunnableLambda(eval_step)
    )
```


| LLM stage | Description | Prompt eng framework |
|-----------|-------------|----------------------|
| **#1 Repo reader** | Uses a tool‑using DeepAgent to explore `repo/` and output a repo map JSON. | **CO‑STAR**: tool-using repo mapper; response schema is a repo map JSON object |
| **#2 Skill runner** | Consumes repo map + `skills/` content and outputs an analysis plan JSON. | **CO‑STAR**: planner over repo map + skills; response schema is an analysis plan JSON object |
| **#3 Analyzer (dual-flow)** | Two parallel tool‑using analyzer runs (Qwen + Alt) that gather evidence from `repo/` and output draft security report JSON (improves consistency via inter-model agreement). | **CO‑STAR**: tool-using evidence collector + report writer; response schema is Security Report JSON |
| **#4 Evaluator + compare** | Qwen evaluator validates both drafts against the repo, then compares outputs to pick the better validated report and compute `summary.confidence_score` derived from inter-model agreement + per-finding validation confidence. | **CO‑STAR**: tool-using verifier/judge; response schema is corrected Security Report JSON |

```mermaid
flowchart LR
  U[User / Runner Script\n`deepagent_sast_demo.py`] --> A[DeepAgent\n(LangChain/LangGraph agent)]
  A -->|system prompt + skills| M[Bedrock Chat Model\n`ChatBedrockConverse`]
  M --> A

  A -->|tool calls| T[Filesystem tools\nls / glob / grep / read_file]
  T --> A

  A -->|final output| J[Structured JSON report\nsummary/findings/recommendations]

  J --> P[Post-processor\nnormalize keys + infer category/location]
  P --> R[`security_report.md`\n(markdown + embedded Raw JSON)]

  R --> D[Dashboard\n`dashboard_app.py`]
  D --> UI[Browser UI\ncards + table + details]
  D --> API[`/api/report`\n(normalized JSON)]
```

## Testing / evaluation

- **Report & dashboard check**:
  - Ensure `security_report.md` contains a non-empty findings list and a `## Raw JSON` fenced `json` block (the dashboard uses this as source-of-truth).
  - Open the dashboard and confirm:
    - Severity counts match the report
    - Rows expand and show details (evidence / impact / remediation)
    - Recommendations are non-empty (auto-derived from remediation when the model omits them)
- **Finding validation check**:
  - Each finding should include: `validation_status` (`Yes` / `Requires manual check`), `validation_confidence` \([0,1]\), `validation_rationale`.
  - After a `MULTI_STAGE_CHAIN=1` run, confirm at least some findings show `validation_status=Yes` with **non-default** confidence.
  - If everything shows `Requires manual check` with confidence `0.5`, you are likely viewing safe defaults from an older/incomplete report (missing `validation_*` keys), or the snippets could not be deterministically matched.
- **Workflow progress check (during a run)**:
  - While `deepagent_sast_demo.py` is running, the dashboard should show the **LLM workflow** status banner above the summary cards.
  - Verify `GET /api/status` returns JSON (backed by `run_status.json` written by the pipeline).
- **Consistency/recall check**:
  - Verify runs produce at least `MIN_FINDINGS` findings (env var; defaults to 8) and don’t oscillate wildly between runs.

## Output

- `security_reports/security_report_YYYYMMDD_HHMMSSZ.md` (one per scan)
- `security_report.md` (latest)
- `repo_map_cache.json` (optional; repo map cache for multi-stage runs)
- Dashboard UI from `dashboard_app.py` (and `/api/report`)
- Each report embeds a **Filetypes scanned** section derived from `tools/filetype_scan.py` and the full data is also included in the report’s **Raw JSON** under `filetype_scan`.

## Consistency

- Findings are ordered by severity in the rendered report (Markdown generation sorts by severity).
- **Streaming robustness**: DeepAgent stream events can deliver `messages` as a LangGraph `Overwrite(value=[...])` wrapper; the demo unwraps this in `_iter_stream_messages` to avoid runtime errors and dropped content.
- Dashboard uses the embedded `## Raw JSON` as source-of-truth.
- **Stable filetype reporting**: dashboard computes `included_files_total` and `ignored_files_total` from the report’s `filetype_scan.{included_counts,ignored_counts}` for consistent summary numbers.
- **Run-to-run stability**: the pipeline uses deterministic file indexing (sorted traversal) and can synthesize/merge results to reach `MIN_FINDINGS` so runs don’t under-fill.

## Notes

- **Bedrock throttling / quota**: if the model call fails (e.g., “too many tokens per day”), rerun later or switch the Bedrock model via `BEDROCK_QWEN_MODEL_ID`.
- **Repo already exists**: if `repo/` already contains a git repo, the scripts will reuse it.
