from __future__ import annotations

import os
from typing import Iterable

from apps.recon.services.tool_runner import render_cmd, run_command


class AxOrchestrator:
    """
    Wrapper minimo para integrar com CLI Ax/Axiom em ambiente autorizado.
    """

    def __init__(self) -> None:
        self.enabled = str(os.getenv("ENABLE_AX_ORCHESTRATION", "0")).strip() == "1"

    def dispatch_nuclei(self, *, target_hosts: Iterable[str], templates: str, timeout: int = 1200) -> dict:
        hosts = [h.strip() for h in target_hosts if str(h).strip()]
        if not self.enabled:
            return {"status": "disabled", "count": len(hosts)}
        if not hosts:
            return {"status": "empty", "count": 0}

        # Exemplo de chamada: ajuste para seu ambiente ax.
        cmd = ["ax", "scan", "nuclei", "--targets", ",".join(hosts), "--templates", templates]
        rc, out, err = run_command(cmd, timeout=timeout)
        return {
            "status": "ok" if rc == 0 else "failed",
            "return_code": rc,
            "stdout": out,
            "stderr": err,
            "command": render_cmd(cmd),
            "count": len(hosts),
        }
