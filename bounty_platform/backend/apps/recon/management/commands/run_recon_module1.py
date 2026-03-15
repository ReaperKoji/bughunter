from __future__ import annotations

import tempfile
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.recon.models import Program, ScopeAsset, Subdomain
from apps.recon.services.parsers import extract_live_ips, parse_dnsx_jsonl, parse_subfinder_output
from apps.recon.services.scope_filter import host_in_scope
from apps.recon.services.tool_runner import render_cmd, run_command


class Command(BaseCommand):
    help = "Modulo 1 Recon: executa subfinder, valida com dnsx e persiste hosts vivos no banco."

    def add_arguments(self, parser):
        parser.add_argument("--program", required=True, help="Program slug")
        parser.add_argument("--domains", default="", help="Lista CSV de dominios raiz (opcional)")
        parser.add_argument("--authorized-token", required=True, help="Use I_HAVE_PERMISSION para confirmar autorizacao")
        parser.add_argument("--subfinder-path", default="subfinder")
        parser.add_argument("--dnsx-path", default="dnsx")
        parser.add_argument("--timeout", type=int, default=600)
        parser.add_argument("--dry-run", action="store_true")

    @transaction.atomic
    def handle(self, *args, **opts):
        if str(opts["authorized_token"]).strip() != "I_HAVE_PERMISSION":
            raise CommandError("Execucao bloqueada: informe --authorized-token I_HAVE_PERMISSION")

        try:
            program = Program.objects.get(slug=opts["program"], is_active=True)
        except Program.DoesNotExist as exc:
            raise CommandError(f"Programa nao encontrado/ativo: {opts['program']}") from exc

        roots: list[str] = []
        domains_csv = str(opts.get("domains", "")).strip()
        if domains_csv:
            roots = [x.strip().lower() for x in domains_csv.split(",") if x.strip()]
        else:
            for asset in ScopeAsset.objects.filter(program=program, in_scope=True):
                value = str(asset.value).strip().lower()
                if asset.asset_type == ScopeAsset.TYPE_DOMAIN:
                    roots.append(value)
                elif asset.asset_type == ScopeAsset.TYPE_WILDCARD:
                    roots.append(value[2:] if value.startswith("*.") else value)

        roots = sorted(list(set(roots)))
        if not roots:
            raise CommandError("Nenhum dominio raiz encontrado. Cadastre ScopeAsset ou use --domains")

        in_scope_assets = list(ScopeAsset.objects.filter(program=program, in_scope=True))
        timeout = int(opts["timeout"])

        # 1) Subfinder
        discovered: set[str] = set()
        for root in roots:
            cmd = [opts["subfinder_path"], "-d", root, "-silent", "-all", "-recursive"]
            rc, out, err = run_command(cmd, timeout=timeout)
            self.stdout.write(f"[subfinder] root={root} rc={rc} cmd={render_cmd(cmd)}")
            if rc != 0 and err.strip():
                self.stdout.write(self.style.WARNING(err.strip()[:400]))
            discovered |= parse_subfinder_output(out)

        discovered = {h for h in discovered if host_in_scope(h, in_scope_assets)}
        if not discovered:
            self.stdout.write(self.style.WARNING("Nenhum host descoberto em escopo."))
            return

        # 2) dnsx
        with tempfile.TemporaryDirectory(prefix="recon_m1_") as tmpd:
            input_file = Path(tmpd) / "hosts.txt"
            input_file.write_text("\n".join(sorted(discovered)) + "\n", encoding="utf-8")

            dnsx_cmd = [
                opts["dnsx_path"],
                "-l",
                str(input_file),
                "-silent",
                "-a",
                "-aaaa",
                "-resp",
                "-json",
            ]
            rc, dnsx_out, dnsx_err = run_command(dnsx_cmd, timeout=timeout)
            self.stdout.write(f"[dnsx] rc={rc} cmd={render_cmd(dnsx_cmd)}")
            if rc != 0 and dnsx_err.strip():
                self.stdout.write(self.style.WARNING(dnsx_err.strip()[:400]))

        dnsx_rows = parse_dnsx_jsonl(dnsx_out)
        live_count = 0
        upsert_count = 0

        for host in sorted(discovered):
            row = dnsx_rows.get(host, {})
            ips = extract_live_ips(row)
            is_live = len(ips) > 0
            if is_live:
                live_count += 1

            if opts["dry_run"]:
                continue

            Subdomain.objects.update_or_create(
                program=program,
                hostname=host,
                defaults={
                    "is_live": is_live,
                    "resolved_ips": ips,
                    "source": "subfinder+dnsx",
                    "raw": row,
                },
            )
            if is_live:
                upsert_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Recon M1 finalizado | discovered={len(discovered)} live={live_count} persisted_live={upsert_count}"
            )
        )
