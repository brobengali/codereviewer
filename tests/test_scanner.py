"""Tests for repository scanner driven entirely by external data rule files."""

import json
from pathlib import Path

from codeguide.config.loader import load_config
from codeguide.scanner.rules import RuleEngine
from codeguide.scanner.scanner import RepositoryScanner


def test_scanner_python_fastapi_repo(tmp_path: Path) -> None:
    cfg = load_config()
    repo_dir = tmp_path / "py_repo"
    repo_dir.mkdir()

    # Documentation and container definitions
    (repo_dir / "README.md").write_text("# Python Service\nProject overview.", encoding="utf-8")
    (repo_dir / "Dockerfile").write_text("FROM python:3.12-slim\nCMD ['python']", encoding="utf-8")

    # .gitignore and ignored file
    (repo_dir / ".gitignore").write_text("*.tmp\nignored_dir/\n", encoding="utf-8")
    ignored_dir = repo_dir / "ignored_dir"
    ignored_dir.mkdir()
    (ignored_dir / "secret.py").write_text("SECRET=1", encoding="utf-8")
    (repo_dir / "temp.tmp").write_text("temporary", encoding="utf-8")

    # Lockfile and binary file (should be skipped)
    (repo_dir / "poetry.lock").write_text("[[package]]\nname='fastapi'", encoding="utf-8")
    (repo_dir / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

    # Manifest
    (repo_dir / "pyproject.toml").write_text(
        """
[tool.poetry]
name = "demo-api"

[tool.poetry.dependencies]
fastapi = "^0.110.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0.0"
""",
        encoding="utf-8",
    )

    # Source code with entrypoint, route, model, env var
    src_dir = repo_dir / "app"
    src_dir.mkdir()
    (src_dir / "main.py").write_text(
        """import os
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class UserSchema(BaseModel):
    id: int
    name: str

@app.get("/users")
def get_users():
    return []

@app.post("/users")
def create_user():
    token = os.environ.get("AUTH_TOKEN")
    return {"token": token}

if __name__ == '__main__':
    print("Running")
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(repo_dir, cfg)
    result = scanner.scan()

    # 1. Output structure & serialization
    serialized = result.model_dump_json()
    parsed = json.loads(serialized)
    assert parsed["repo_name"] == "py_repo"

    # 2. Ignored files check
    scanned_paths = [doc.path for doc in result.documents]
    assert "README.md" in scanned_paths
    assert "Dockerfile" in scanned_paths
    assert "poetry.lock" not in scanned_paths
    assert not any("ignored_dir" in p for p in scanned_paths)

    # 3. Language detection
    lang_names = [lang.name for lang in result.languages]
    assert "Python" in lang_names

    # 4. Package manager, framework, test tool
    pm_names = [pm.name for pm in result.package_managers]
    assert "poetry" in pm_names

    fw_names = [fw.name for fw in result.frameworks]
    assert "FastAPI" in fw_names

    tt_names = [tt.name for tt in result.test_tools]
    assert "pytest" in tt_names

    # 5. Symbols detection
    ep_names = [ep.name for ep in result.entry_points]
    assert "main" in ep_names
    assert result.entry_points[0].citation.file_path == "app/main.py"

    route_names = [r.name for r in result.routes]
    assert "GET /users" in route_names
    assert "POST /users" in route_names

    model_names = [m.name for m in result.db_models]
    assert "UserSchema" in model_names

    env_names = [ev.name for ev in result.env_vars]
    assert "AUTH_TOKEN" in env_names

    # 6. File tree importance scores
    app_node = next(c for c in result.file_tree.children if c.path == "app")
    main_node = next(c for c in app_node.children if c.path == "app/main.py")
    assert main_node.importance_score > 5.0
    assert main_node.line_count > 15


def test_scanner_javascript_express_repo(tmp_path: Path) -> None:
    cfg = load_config()
    repo_dir = tmp_path / "js_repo"
    repo_dir.mkdir()

    (repo_dir / "CONTRIBUTING.md").write_text("# Contributing Guide", encoding="utf-8")
    (repo_dir / "package.json").write_text(
        """{
  "name": "express-demo",
  "dependencies": {
    "express": "^4.19.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}""",
        encoding="utf-8",
    )
    (repo_dir / "package-lock.json").write_text("{}", encoding="utf-8")
    (repo_dir / "jest.config.js").write_text("module.exports = {};", encoding="utf-8")

    (repo_dir / "server.js").write_text(
        """const express = require('express');
const app = express();

@Entity("accounts")
class AccountModel {}

app.get("/api/health", (req, res) => res.send("ok"));

const port = process.env.PORT;
""",
        encoding="utf-8",
    )

    scanner = RepositoryScanner(repo_dir, cfg)
    result = scanner.scan()

    # Language detection
    lang_names = [lang.name for lang in result.languages]
    assert "JavaScript" in lang_names

    # Ecosystem
    assert any(pm.name == "npm" for pm in result.package_managers)
    assert any(fw.name == "Express" for fw in result.frameworks)
    assert any(tt.name == "jest" for tt in result.test_tools)

    # Routes & models & env vars
    assert any(r.name == "GET /api/health" for r in result.routes)
    assert any(m.name == "AccountModel" for m in result.db_models)
    assert any(ev.name == "PORT" for ev in result.env_vars)


def test_extensibility_add_new_language_without_code_changes(tmp_path: Path) -> None:
    """Prove that adding support for a new language requires ONLY a rule file, zero code edits."""
    cfg = load_config()
    repo_dir = tmp_path / "elixir_project"
    repo_dir.mkdir()

    (repo_dir / "mix.exs").write_text("defmodule Demo.MixProject do\nend", encoding="utf-8")
    (repo_dir / "router.ex").write_text(
        """defmodule DemoWeb.Router do
  use Phoenix.Router

  scope "/api" do
    get "/metrics", MetricsController
  end
end
""",
        encoding="utf-8",
    )

    # Phase 1: Baseline scan with standard rules
    base_scanner = RepositoryScanner(repo_dir, cfg)
    base_result = base_scanner.scan()

    # Elixir is not part of default rules; language should not be detected
    assert not any(lang.name == "Elixir" for lang in base_result.languages)
    assert not any(fw.name == "Phoenix" for fw in base_result.frameworks)
    assert len(base_result.routes) == 0

    # Phase 2: Create external rule file for Elixir (zero code modification)
    elixir_rule_file = tmp_path / "elixir_rules.toml"
    elixir_rule_file.write_text(
        """
[[languages]]
id = "elixir"
name = "Elixir"
extensions = [".ex", ".exs"]

[[frameworks]]
name = "Phoenix"
category = "web_framework"
language = "elixir"
code_patterns = ["use Phoenix.Router"]

[[routes]]
id = "phoenix-route"
language = "elixir"
regex = '''(get|post|put|delete)\\s+["']([^"']+)["']'''
method_group = 1
path_group = 2
""",
        encoding="utf-8",
    )

    # Phase 3: Load rule engine with the external rule file
    ext_engine = RuleEngine.load(cfg, extra_rules=[elixir_rule_file])
    ext_scanner = RepositoryScanner(repo_dir, cfg, rule_engine=ext_engine)
    ext_result = ext_scanner.scan()

    # Verify that Elixir, Phoenix, and routes are now completely detected!
    assert any(lang.name == "Elixir" for lang in ext_result.languages)
    assert any(fw.name == "Phoenix" for fw in ext_result.frameworks)
    assert any(r.name == "GET /metrics" for r in ext_result.routes)
    assert ext_result.routes[0].citation.file_path == "router.ex"
    assert ext_result.routes[0].citation.start_line == 5
