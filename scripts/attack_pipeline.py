#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio

from hunterops.attack_chain import ChainOrchestrator, load_attack_pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description="HunterOps attack pipeline orchestrator")
    parser.add_argument("--config", default="attack_pipeline.yaml")
    args = parser.parse_args()

    cfg = load_attack_pipeline(args.config)
    orchestrator = ChainOrchestrator(cfg)
    asyncio.run(orchestrator.run())


if __name__ == "__main__":
    main()
