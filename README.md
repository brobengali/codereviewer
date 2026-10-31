# CodeGuide

> Turn complex, unfamiliar repositories into clear architectural maps and onboarding guides in minutes.

Joining a new codebase is tough. You stare at hundreds of files, out-of-date documentation, missing diagrams, and wonder where execution actually begins.

**CodeGuide** fixes this. It scans your code, strips out sensitive credentials, maps imports and dependencies with Tree-Sitter AST parsers, and produces an interactive visual dashboard alongside a concrete onboarding guide (`ONBOARDING.md`). Best of all: every single claim points directly to verifiable file paths and line numbers—zero hallucinations, zero fluff.

---

## Why CodeGuide?

Most AI coding tools invent files that do not exist, gloss over architectural details, or leak API keys in transit. CodeGuide is built differently:

- **Exact Citations**: Every explanation cites `path:start_line-end_line`. If the code does not back up a claim, CodeGuide explicitly labels it `unclear` rather than guessing.
- **Automatic Secret Redaction**: AWS tokens, GitHub credentials, database passwords, and high-entropy secrets are masked (`[REDACTED:aws_key]`) before any prompt is prepared. `.env*`, `.pem`, and private keys are never opened.
- **Interactive Offline Dashboard**: Generates a self-contained single-file HTML app (`index.html`) with file trees, architecture graphs, and module summaries. It runs in your browser with strict Content Security Policy and zero external CDN requests.
- **Audience Adaptation**: Need a high-level conceptual walkthrough for a junior engineer or a concurrency and failure-mode review for a senior teammate? The `explain` command tailors its depth automatically.
- **Strict Quality Linters**: Enforces anti-slop rules on both your documentation (`codeguide lint-docs`) and your codebase (`codeguide lint-code`) to catch dead functions, stubs, and comments that merely restate code.

---

## Quickstart (60 Seconds)

### 1. Installation

Requires Python 3.11+.

```bash
# Clone the repository
git clone https://github.com/brobengali/codereviewer.git
cd codereviewer

# Create and activate a virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# Install package dependencies
pip install -e ".[dev]"
```

### 2. Set API Credential (Optional)

If you plan to run AI answers with Google Gemini, set your API key:

```powershell
# Windows PowerShell
$env:GEMINI_API_KEY = "your-api-key"
```

```bash
# Linux / macOS
export GEMINI_API_KEY="your-api-key"
```

*(You can also run CodeGuide completely offline without any API key using `--offline` or local models like Ollama).*

---

## Core Workflows

### 1. Analyze Your Codebase

Analyze the local repository and generate onboarding artifacts:

```bash
codeguide analyze .
```

This scans files, builds the dependency graph, identifies architecture patterns, and writes two artifacts to `codeguide_output/`:
- `ONBOARDING.md`: Traced feature flows, starter tasks, setup instructions, and architecture diagrams.
- `index.html`: Interactive visual dashboard. Open it directly in your browser:
  ```powershell
  Start-Process codeguide_output/index.html   # Windows
  open codeguide_output/index.html            # macOS
  xdg-open codeguide_output/index.html        # Linux
  ```

Want to inspect what data would leave your machine without calling any external model?
```bash
codeguide analyze . --dry-run
```

### 2. Ask Questions About the Repository

Query any subsystem, flow, or concept backed by retrieved code snippets:

```bash
codeguide ask "How is secret redaction implemented?"
codeguide ask "Where does CLI argument parsing happen?"
```

Sample output:
```text
Question: Where does CLI argument parsing happen?

Answer:
Command-line arguments and flags are declared with Typer command functions and routed in the main entrypoint module.

Citations:
  - src/codeguide/cli.py:40-45
  - src/codeguide/cli.py:83-112

Suggested Follow-ups:
  - How are configuration options overridden from CLI flags?
  - Where are subcommands registered?
```

### 3. Explain Specific Files or Symbols

Tailor explanations for different experience levels:

```bash
# Junior engineer: focuses on concepts, dependencies, and core functions
codeguide explain src/codeguide/redactor/engine.py --audience junior

# Mid-level engineer: balanced implementation review (default)
codeguide explain src/codeguide/retrieval/engine.py

# Senior engineer: focuses on edge cases, memory lifecycle, and architectural boundaries
codeguide explain src/codeguide/analyzer/parser.py --audience senior
```

### 4. Audit Documentation and Codebase Quality

Catch unverified claims, dead functions, and redundant comments:

```bash
# Audit markdown documentation files for missing citations and buzzwords
codeguide lint-docs README.md
codeguide lint-docs codeguide_output/ONBOARDING.md

# Audit Python source code for dead functions, stubs, and restating comments
codeguide lint-code src/
```

### 5. Inspect Active Configuration

```bash
# View active settings with all keys masked (********)
codeguide config show

# Validate your configuration against the schema
codeguide config validate codeguide.toml.example
```

---

## Running 100% Locally (Offline Mode)

CodeGuide works completely air-gapped without sending data to third parties:

1. Start an OpenAI-compatible local server (such as Ollama):
   ```bash
   ollama run llama3
   ```
2. Create a `codeguide.toml` in your root folder:
   ```toml
   [llm]
   provider = "local"
   model_name = "llama3"
   api_base_url = "http://localhost:11434"
   offline = true
   ```
3. Run any command with the `--offline` flag:
   ```bash
   codeguide analyze . --offline
   codeguide ask "How does the caching system work?" --offline
   ```

---

## Configuration Reference

CodeGuide loads settings following a strict hierarchy:
`CLI Flags > Environment Variables > codeguide.toml > defaults.toml`.

| Section | Key | Default | Description |
| :--- | :--- | :--- | :--- |
| `[llm]` | `provider` | `"gemini"` | LLM backend: `"gemini"` or `"local"` |
| `[llm]` | `model_name` | `"gemini-3.8-flash"` | Target model name |
| `[llm]` | `temperature` | `0.1` | Generation sampling temperature |
| `[llm]` | `offline` | `false` | Force strict offline execution |
| `[llm]` | `cache_enabled` | `true` | Deterministic SHA-256 disk caching |
| `[paths]` | `output_dir` | `"codeguide_output"` | Output directory for documentation artifacts |
| `[security]` | `redact_secrets` | `true` | Strip API keys, tokens, and passwords |
| `[security]` | `allow_symlinks` | `false` | Prevent symlink directory escape attacks |
| `[retrieval]`| `top_k` | `5` | Retrieved code chunks for question answering |
| `[slop]` | `max_slop_score` | `0.0` | Maximum allowable slop threshold |

---

## Security & Verification

CodeGuide treats target codebases as untrusted input. It protects host environments against path traversals, zip bombs, SSRF requests, secret leaks, and prompt injection attacks.

Run the test and verification suite:

```bash
# Run unit and integration tests (134 tests)
pytest

# Run static type checking
mypy src/

# Run security vulnerability audit
bandit -r src/ -q

# Verify zero hardcoded model names or magic strings
python scripts/check_no_hardcoding.py

# Lint and check formatting
ruff check src tests
ruff format --check src tests
```

---

## License

Distributed under the Apache 2.0 License. See `LICENSE` for details.
