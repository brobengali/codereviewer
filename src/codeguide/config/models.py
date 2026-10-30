"""Configuration data schemas."""

from pydantic import BaseModel, ConfigDict


class MetaConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    config_filename: str


class SafetySettingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: str
    threshold: str


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    model_name: str
    api_base_url: str
    api_key: str
    api_key_env_var: str
    keyring_service_name: str
    keyring_username: str
    request_timeout_seconds: float
    max_retries: int
    backoff_factor: float
    temperature: float
    max_tokens: int
    max_output_tokens: int
    requests_per_minute: int
    tokens_per_minute: int
    thinking_budget: int
    offline: bool
    cache_enabled: bool
    cache_dir: str
    safety_settings: list[SafetySettingConfig]


class RepoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_schemes: list[str]
    allowed_hosts: list[str]
    allow_all_hosts: bool
    clone_timeout_seconds: float
    clone_depth: int
    scan_timeout_seconds: float
    temp_dir_prefix: str
    dir_mode: int
    git_binary: str


class ImportanceWeightsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_score: float
    entrypoint_bonus: float
    route_bonus: float
    db_model_bonus: float
    documentation_bonus: float
    ci_build_bonus: float
    root_bonus: float
    lines_scale: float
    max_lines_bonus: float


class GrammarConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package: str
    function: str
    extensions: list[str]


class RiskSignalsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    huge_file_lines_threshold: int
    todo_cluster_threshold: int
    todo_cluster_window_lines: int
    todo_patterns: list[str]
    test_file_patterns: list[str]
    source_file_extensions: list[str]


class ChunkingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_chunk_lines: int
    chunk_overlap_lines: int
    min_chunk_lines: int


class DependenciesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    core_module_min_in_degree: int
    detect_circular: bool
    internal_import_prefixes: list[str]


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_file_size_bytes: int
    max_repo_size_bytes: int
    max_files_count: int
    file_read_timeout_seconds: float
    supported_extensions: list[str]
    ignore_patterns: list[str]
    lockfile_patterns: list[str]
    binary_extensions: list[str]
    build_directories: list[str]
    documentation_patterns: list[str]
    ci_patterns: list[str]
    build_file_patterns: list[str]
    importance_weights: ImportanceWeightsConfig
    grammars: dict[str, GrammarConfig]
    risk_signals: RiskSignalsConfig
    chunking: ChunkingConfig
    dependencies: DependenciesConfig
    max_ast_depth: int
    max_lines_per_file: int


class PathsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    templates_dir: str
    prompts_dir: str
    output_dir: str
    languages_file: str
    entrypoints_file: str
    architecture_rules_file: str
    style_rules_file: str
    messages_file: str
    rules_dir: str
    secret_rules_file: str
    queries_file: str
    onboarding_template: str
    interactive_template: str
    ask_template: str
    explain_template: str


class RetrievalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str
    top_k: int
    min_score_threshold: float
    bm25_k1: float
    bm25_b: float


class SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    redact_secrets: bool
    entropy_threshold: float
    min_entropy_length: int
    max_entropy_length: int
    entropy_placeholder: str
    max_snippet_chars: int
    allow_symlinks: bool
    escape_output: bool
    block_private_ips: bool
    max_compression_ratio: float
    blocked_ip_networks: list[str]
    denied_file_patterns: list[str]
    mask_value: str
    redacted_marker: str
    sensitive_key_names: list[str]
    secret_patterns: list[str]


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    level: str
    format: str


class StyleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_sentence_length: int
    disallow_emojis_in_headings: bool
    require_citations_for_claims: bool
    min_citation_coverage_ratio: float
    unclear_marker: str
    banned_phrases: list[str]
    banned_openers: list[str]
    vague_words: list[str]


class CitationsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    citation_format: str
    single_line_format: str
    unclear_fallback: str
    strict_verification: bool


class UIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    output_format: str
    verbose: bool
    interactive_html_filename: str
    onboarding_md_filename: str
    default_audience_level: str
    supported_audience_levels: list[str]


class SlopConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_slop_score: float
    repetition_similarity_threshold: float
    min_specificity_score: float
    max_sentence_length: int
    fail_on_slop: bool


class AppConfig(BaseModel):
    """Root configuration tree."""

    model_config = ConfigDict(extra="forbid")
    meta: MetaConfig
    llm: LLMConfig
    repo: RepoConfig
    analysis: AnalysisConfig
    paths: PathsConfig
    security: SecurityConfig
    logging: LoggingConfig
    style: StyleConfig
    citations: CitationsConfig
    ui: UIConfig
    retrieval: RetrievalConfig
    slop: SlopConfig
