"""Data schemas for documentation generation context and artifacts."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FeatureFlowStep(BaseModel):
    """Step in an end-to-end traced feature execution path."""

    model_config = ConfigDict(extra="forbid")
    order: int
    description: str
    citation: str


class FeatureFlow(BaseModel):
    """Traced flow through entrypoint, routes, logic, and data layers."""

    model_config = ConfigDict(extra="forbid")
    name: str
    description: str
    steps: list[FeatureFlowStep] = Field(default_factory=list)


class GlossaryTerm(BaseModel):
    """Domain concept, entity, or model extracted from codebase declarations."""

    model_config = ConfigDict(extra="forbid")
    term: str
    definition: str
    citation: str


class StarterTask(BaseModel):
    """First-week onboarding activity anchored to codebase evidence."""

    model_config = ConfigDict(extra="forbid")
    day: int
    title: str
    description: str
    citation: str


class SetupStep(BaseModel):
    """Verified environment setup or execution command from repo manifests."""

    model_config = ConfigDict(extra="forbid")
    step_number: int
    instruction: str
    citation: str


class FolderGuideItem(BaseModel):
    """Top-level directory purpose backed by file and symbol citations."""

    model_config = ConfigDict(extra="forbid")
    path: str
    purpose: str
    citation: str


class GotchaItem(BaseModel):
    """Subtle architectural risk, cluster, or maintenance hazard."""

    model_config = ConfigDict(extra="forbid")
    title: str
    risk_type: str
    explanation: str
    citation: str


class TechStackItem(BaseModel):
    """Detected language, framework, or tool with evidence citation."""

    model_config = ConfigDict(extra="forbid")
    name: str
    category: str
    citation: str


class OnboardingContext(BaseModel):
    """Comprehensive structured data feeding onboarding documentation templates."""

    model_config = ConfigDict(extra="forbid")
    repo_name: str
    purpose: str
    purpose_citation: str
    tech_stack: list[TechStackItem] = Field(default_factory=list)
    architecture_name: str
    architecture_description: str
    architecture_citation: str
    mermaid_diagram: str
    folder_guide: list[FolderGuideItem] = Field(default_factory=list)
    feature_flows: list[FeatureFlow] = Field(default_factory=list)
    setup_steps: list[SetupStep] = Field(default_factory=list)
    glossary: list[GlossaryTerm] = Field(default_factory=list)
    inferred_conventions: list[str] = Field(default_factory=list)
    starter_tasks: list[StarterTask] = Field(default_factory=list)
    gotchas: list[GotchaItem] = Field(default_factory=list)
    interactive_tree: dict[str, Any] = Field(default_factory=dict)
    interactive_modules: list[dict[str, Any]] = Field(default_factory=list)
    interactive_graph: dict[str, Any] = Field(default_factory=dict)
