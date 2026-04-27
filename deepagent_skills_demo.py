"""
DeepAgent Skills Demo - Exercise 23

This exercise demonstrates how to use DeepAgent Skills to create
reusable, composable security analysis capabilities.

Skills are SKILL.md files that contain domain expertise and instructions.
They are loaded from directories and injected into the agent's context.

See the skills/ directory for the skill definitions:
  - skills/owasp-top10/SKILL.md
  - skills/c-python-security/SKILL.md
  - skills/security-report/SKILL.md
"""

from deepagents import create_deep_agent
from deepagents.backends import FilesystemBackend
from langchain_aws import ChatBedrockConverse
from langgraph.checkpoint.memory import MemorySaver
from dotenv import load_dotenv
import os
import git

load_dotenv()

# ------------------------------------------------------------------------------
# Git Repo Setup
# ------------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
repo_url = "https://github.com/haiwen/seafile"
repo_path = os.path.join(SCRIPT_DIR, "repo")

if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, ".git")):
    print("Directory already contains a git repository.")
else:
    try:
        repo = git.Repo.clone_from(repo_url, repo_path)
        print(f"Repository cloned into: {repo_path}")
    except Exception as e:
        print(f"An error occurred while cloning the repository: {e}")

print(f"Repo path: {repo_path}")

# ------------------------------------------------------------------------------
# Skills Setup
# ------------------------------------------------------------------------------
# Skills are directories containing SKILL.md files with frontmatter metadata
# and instructions. DeepAgent loads these and injects them into the agent's
# context when relevant.
skills_dir = os.path.join(SCRIPT_DIR, "skills")

print(f"Skills directory: {skills_dir}")
print("Skills loaded:")
for skill_name in os.listdir(skills_dir):
    skill_path = os.path.join(skills_dir, skill_name, "SKILL.md")
    if os.path.exists(skill_path):
        print(f"  - {skill_name}")

# ------------------------------------------------------------------------------
# LLM Setup
# ------------------------------------------------------------------------------
# Qwen on Amazon Bedrock (uses your existing AWS credentials).
#
# Pick the Bedrock Qwen model via env var if you want:
#   export BEDROCK_QWEN_MODEL_ID="qwen.qwen3-32b-v1:0"
#
# Some known Qwen Bedrock model IDs (subject to region availability):
# - qwen.qwen3-32b-v1:0
# - qwen.qwen3-235b-a22b-2507-v1:0
# - qwen.qwen3-coder-30b-a3b-v1:0
# - qwen.qwen3-coder-480b-a35b-v1:0
bedrock_qwen_model_id = os.getenv("BEDROCK_QWEN_MODEL_ID", "qwen.qwen3-32b-v1:0")

llm = ChatBedrockConverse(
    model_id=bedrock_qwen_model_id,
    temperature=0.3,  # Lower temperature for more consistent analysis
)

# Backend for filesystem access - agent can read files in the repo
filesystem_backend = FilesystemBackend(root_dir=repo_path, virtual_mode=True)

# Checkpointer for conversation memory
checkpointer = MemorySaver()

# ------------------------------------------------------------------------------
# Create Agent with Skills
# ------------------------------------------------------------------------------
# Base system prompt - skills will augment this with domain expertise
base_prompt = """You are a security analyst performing a code review.
Use your available skills to conduct a thorough security assessment.
The source code is available in the current directory.

Apply the guidance from your skills systematically and generate
a structured report of your findings.
"""

# Create agent with skills loaded from the skills directory
# Skills are passed as a list of directory paths containing SKILL.md files
agent = create_deep_agent(
    model=llm,
    tools=[],
    backend=filesystem_backend,
    system_prompt=base_prompt,
    skills=[skills_dir],  # Load all skills from this directory
    checkpointer=checkpointer,
)


# ------------------------------------------------------------------------------
# Analysis Function
# ------------------------------------------------------------------------------
def analyze_with_skills(task: str) -> str:
    """
    Run security analysis using the skill-enhanced agent.
    """
    print("\n[Agent] Running with skills loaded from skills/ directory")
    print("[Agent] Streaming output...")

    final_output = ""
    for event in agent.stream(
        {"messages": [{"role": "user", "content": task}]},
        config={"configurable": {"thread_id": "security-assessment"}},
    ):
        for key, value in event.items():
            if "Middleware" in key:
                continue
            if isinstance(value, dict) and "messages" in value:
                for msg in value["messages"]:
                    if hasattr(msg, "tool_calls") and msg.tool_calls:
                        for tc in msg.tool_calls:
                            print(f"  -> {tc['name']}")
                    elif hasattr(msg, "content") and msg.content:
                        final_output = msg.content
    return final_output


def _terminal_safe_preview(text: str, max_chars: int = 4000) -> str:
    cleaned = text.replace("```", "")
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[:max_chars] + "\n\n[... truncated preview; full report saved to file ...]\n"


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("DeepAgent Skills Demo - Security Assessment")
    print("=" * 60)

    analysis_task = """
Perform a comprehensive security assessment of this C/Python codebase.

1. First, explore the directory structure to understand the codebase
2. Identify the main entrypoints, network handlers, and trust boundaries
3. Apply OWASP Top 10 analysis to find vulnerabilities
4. Check for C memory-safety bugs and Python-specific security issues
5. Generate a structured security report with your findings

Focus on high-impact vulnerabilities that could lead to data breaches.
"""

    print("\nStarting analysis...")
    print("-" * 60)
    result = analyze_with_skills(analysis_task)
    report_path = os.path.join(SCRIPT_DIR, "security_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(result)
    print("\n" + "=" * 60)
    print("SECURITY REPORT:")
    print("=" * 60)
    print(_terminal_safe_preview(result))
    print(f"\nFull report written to: {report_path}")
