# CodeGuide

A secure, citation-backed CLI tool that analyzes a code repository and explains its architecture, conventions, and workflows to newcomer developers.

---

## Core Tenets

1. **Zero Hardcoded Parameters**: Configuration precedence order is `CLI Flags > Environment Variables > codeguide.toml > defaults.toml`. All prompts, templates, and detection rules live in external data files.
2. **Secure by Design**: Repositories are treated as untrusted input. No code execution, secrets are redacted before leaving the host machine, the LLM has zero tools or code execution capabilities, and all outputs are escaped.
3. **Citations Everywhere**: Every claim links to explicit file paths and line numbers (`path:start_line-end_line`), or states `"unclear"` when supporting evidence is insufficient.
4. **Zero AI Slop**: Banned filler phrases and vague words are enforced via `style_rules.toml`. All generated statements must be falsifiable against the repository.

---

## Installation

### Prerequisites
- Python 3.11 or newer
- Git (optional, required only for cloning remote repositories)

### Setup
```bash
# Clone or navigate to the repository
cd codeguide

# Create and activate virtual environment
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

---

## Configuration Reference

CodeGuide loads configuration using strict four-tier precedence:
1. **CLI Flags**: `--model`, `--offline`, `--dry-run`, `--output-dir`
2. **Environment Variables**: Prefixed with `CODEGUIDE__` (e.g., `CODEGUIDE__LLM__TEMPERATURE=0.1`)
3. **User Project Config**: `codeguide.toml` in repository root or current working directory
4. **Default System Schema**: `src/codeguide/data/defaults.toml`

### Configuration Settings

| Section | Setting | Type | Description |
| :--- | :--- | :--- | :--- |
| `[llm]` | `provider` | string | LLM backend: `"gemini"` or `"local"` |
| | `model_name` | string | Configured model identifier (e.g., `gemini-1.5-flash`) |
| | `api_base_url` | string | Target API endpoint URL |
| | `api_key_env_var` | string | Environment variable name holding API key (default `GEMINI_API_KEY`) |
| | `keyring_service_name` | string | OS keychain service identifier |
| | `request_timeout_seconds` | float | HTTP timeout in seconds |
| | `max_retries` | integer | Maximum network retry attempts |
| | `backoff_factor` | float | Exponential backoff factor |
| | `temperature` | float | Generation temperature (0.0 - 2.0) |
| | `max_tokens` | integer | Maximum generation output tokens |
| | `requests_per_minute` | integer | Client rate limit quota |
| | `tokens_per_minute` | integer | Client token throughput quota |
| | `offline` | boolean | Disallow external network calls |
| | `cache_enabled` | boolean | Enable SHA-256 local disk caching |
| | `cache_dir` | string | Path to cache directory (`0700` directory mode) |
| `[analysis]` | `max_file_size_bytes` | integer | Maximum allowed file size in bytes (default `1048576`) |
| | `max_repo_size_bytes` | integer | Maximum cumulative repo size (default `104857600`) |
| | `max_files_count` | integer | Maximum file limit to process (default `5000`) |
| | `ignore_patterns` | list[str] | Files and directories excluded from scanning |
| `[security]` | `redact_secrets` | boolean | Enable secret detection and redaction |
| | `entropy_threshold` | float | Shannon entropy cutoff (default `4.3`) |
| | `min_entropy_length` | integer | Minimum string length for entropy check (default `20`) |
| | `max_snippet_chars` | integer | Maximum characters per citation snippet |
| | `allow_symlinks` | boolean | Allow repository symlinks (default `false`) |
| | `block_private_ips` | boolean | Block SSRF requests to private and metadata IPs |
| | `max_compression_ratio`| float | Maximum zip decompression ratio (default `100.0`) |
| `[retrieval]` | `mode` | string | Retrieval index type: `"keyword"` (BM25) or `"embedding"` |
| | `top_k` | integer | Number of context chunks retrieved for answers |
| | `min_score_threshold` | float | Minimum similarity score cutoff |

---

## Usage and Commands

### 1. `codeguide analyze`
Scans a local repository or remote Git URL, redacts secrets, performs structural analysis, and generates documentation artifacts:
```bash
# Analyze local repository
codeguide analyze ./my-project

# Analyze remote repository
codeguide analyze https://github.com/org/repo.git

# Dry-run inspection (prints redacted outgoing payload without making LLM calls)
codeguide analyze ./my-project --dry-run
```
**Artifacts Generated**:
- `codeguide_output/ONBOARDING.md`: Architectural overview, tech stack, traced feature flows, setup steps, starter tasks, and conventions backed by `path:line` citations.
- `codeguide_output/index.html`: Interactive, zero-external-request single-file documentation viewer with strict Content Security Policy (`default-src 'none'`).

### 2. `codeguide ask`
Answers technical questions regarding the repository with citation grounding:
```bash
codeguide ask "How are database migrations executed?" ./my-project
```
If evidence is insufficient to answer reliably, CodeGuide returns:
```text
Question: How are database migrations executed?
Evidence weak or missing for question; result is unclear.
```

### 3. `codeguide explain`
Explains a specific file, class, or function, adapted to the target audience level:
```bash
# Junior developer audience (detailed fundamentals and syntax breakdown)
codeguide explain src/auth/token.py ./my-project --audience junior

# Senior developer audience (architectural tradeoffs and failure modes)
codeguide explain TokenManager ./my-project --audience senior
```

### 4. `codeguide config`
Inspect and validate active configuration:
```bash
# Display active configuration with all secrets and API keys masked
codeguide config show

# Validate active configuration against Pydantic schema
codeguide config validate
```

### 5. `codeguide lint-docs`
Audit generated or hand-written documentation files for AI slop, banned phrases, missing citations, out-of-range lines, generic sentences, repetition, and excessive sentence length:
```bash
# Lint documentation file against repository ground truth
codeguide lint-docs codeguide_output/ONBOARDING.md --repo ./my-project
```

### 6. `codeguide lint-code` (CI Check)
Audit codebase Python files for restating comments, uncalled dead functions (via AST and Vulture), empty or stub bodies, bare `except:` clauses, and redundant docstrings:
```bash
# Run codebase slop audit in CI or locally
codeguide lint-code src/
```

---

## Offline Mode

CodeGuide supports running without external internet access. When `--offline` is set or `offline = true` is configured:
1. Calls to external LLM providers (e.g. Gemini) are rejected at startup.
2. The retrieval engine and analyzer use the configured local provider pointing to an OpenAI-compatible endpoint (such as Ollama or llama.cpp).

### Example Local Ollama Setup
Add the following to `codeguide.toml`:
```toml
[llm]
provider = "local"
model_name = "llama3:8b"
api_base_url = "http://localhost:11434/v1"
offline = true
```

Run CodeGuide:
```bash
codeguide ask "What does the main loop do?" ./my-project --offline
```

---

## Sample Command Outputs

### `codeguide config show`
```text
[meta]
version = "1.0.0"
config_filename = "codeguide.toml"

[llm]
provider = "gemini"
model_name = "gemini-1.5-flash"
api_base_url = "https://generativelanguage.googleapis.com"
api_key = "********"
api_key_env_var = "GEMINI_API_KEY"
offline = false
cache_enabled = true
...
```

### `codeguide ask`
```text
Question: Where are HTTP routes registered?
Answer:
HTTP routes are mounted on the FastAPI application instance in the main app module.

Citations:
- src/app.py:15-18

Suggested Follow-ups:
- What authentication middlewares are attached to these routes?
- Which database session dependency is injected into route handlers?
```

### `codeguide explain`
```text
Target: TokenValidator (Audience: senior)

Summary:
TokenValidator performs stateless HMAC-SHA256 signature verification over incoming bearer tokens.

Explanation:
The class implements constant-time signature comparison to prevent timing attacks.
Key lifecycle management is delegated to external key rotation hooks.

Citations:
- src/security/tokens.py:42-58

Suggested Follow-ups:
- Where are secret keys rotated?
- How are expired tokens handled?
```

---

## Security and Verification

Run the full verification and hardening suite:
```bash
# Run all tests (unit, integration, and security)
pytest -v

# Run consolidated security suite (traversal, SSRF, zip bombs, secrets, XSS)
pytest tests/test_security_suite.py -v

# Run AST Zero Hardcoding & Magic Numbers Linter
python scripts/check_no_hardcoding.py

# Run static type analysis
mypy src

# Run code style and format checks
ruff check src tests scripts
ruff format --check src tests scripts

# Run security static analysis
bandit -r src/

# Run dependency vulnerability audit
pip-audit
```
