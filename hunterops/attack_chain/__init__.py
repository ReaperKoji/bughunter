"""Sequential attack pipeline with PoC validation and scope enforcement."""

__all__ = ["ChainOrchestrator", "Target", "load_attack_pipeline"]


def __getattr__(name: str):  # type: ignore[override]
    if name == "ChainOrchestrator":
        from hunterops.attack_chain.orchestrator import ChainOrchestrator

        return ChainOrchestrator
    if name == "Target":
        from hunterops.attack_chain.types import Target

        return Target
    if name == "load_attack_pipeline":
        from hunterops.attack_chain.config import load_attack_pipeline

        return load_attack_pipeline
    raise AttributeError(name)
