"""Ponto de entrada: python -m sentinel"""

from __future__ import annotations

import argparse

from rich.console import Console
from rich.table import Table

from sentinel.process_monitor import collect_processes
from sentinel.signature import SignatureStatus

SIGNATURE_STYLE = {
    SignatureStatus.SIGNED: "green",
    SignatureStatus.UNSIGNED: "yellow",
    SignatureStatus.INVALID: "bold magenta",
    SignatureStatus.UNKNOWN: "dim",
}


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel", description="Mini-EDR educacional")
    parser.add_argument(
        "--full-hash", action="store_true", help="mostra o SHA-256 completo"
    )
    parser.add_argument(
        "--suspicious-only", action="store_true", help="mostra só processos suspeitos"
    )
    args = parser.parse_args()

    console = Console()
    with console.status("Analisando processos..."):
        processes = collect_processes()

    if args.suspicious_only:
        processes = [p for p in processes if p.suspicious]

    table = Table(title="Processos em execução", show_lines=False)
    table.add_column("PID", justify="right")
    table.add_column("Nome")
    table.add_column("Usuário")
    table.add_column("Assinatura")
    table.add_column("SHA-256", no_wrap=True)
    table.add_column("Path", overflow="fold")

    for p in processes:
        sha = p.sha256 or "-"
        if not args.full_hash and p.sha256:
            sha = p.sha256[:16] + "…"
        sig_style = SIGNATURE_STYLE[p.signature]
        table.add_row(
            str(p.pid),
            p.name,
            p.username or "-",
            f"[{sig_style}]{p.signature.value}[/]",
            sha,
            p.exe or "-",
            style="bold red" if p.suspicious else None,
        )

    console.print(table)

    n_susp = sum(p.suspicious for p in processes)
    n_unsigned = sum(p.signature is SignatureStatus.UNSIGNED for p in processes)
    console.print(
        f"\n{len(processes)} processos · "
        f"[bold red]{n_susp} em local suspeito[/] · "
        f"[yellow]{n_unsigned} não assinados[/]"
    )


if __name__ == "__main__":
    main()
