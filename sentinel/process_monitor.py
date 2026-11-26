"""Coleta e análise dos processos em execução."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache

import psutil

from sentinel.signature import SignatureStatus, check_signature

CHUNK_SIZE = 1024 * 1024  # 1 MiB


@dataclass
class ProcessInfo:
    pid: int
    name: str
    username: str | None
    exe: str | None
    sha256: str | None
    signature: SignatureStatus
    suspicious: bool


def _normalize(path: str) -> str:
    # realpath expande nomes curtos 8.3 (ex.: C:\Users\IGOR~1) e normcase
    # deixa tudo minúsculo, já que caminhos no Windows não diferenciam caixa.
    return os.path.normcase(os.path.realpath(path))


def suspicious_dirs() -> list[str]:
    """Pastas de onde programas legítimos raramente rodam.

    Malware costuma se instalar em locais graváveis pelo usuário sem
    precisar de admin (MITRE ATT&CK T1036.005 / T1204.002).
    """
    candidates = [
        os.environ.get("TEMP"),
        os.environ.get("APPDATA"),
        os.path.join(os.path.expanduser("~"), "Downloads"),
    ]
    return [_normalize(p) for p in candidates if p]


def is_suspicious_path(exe: str, dirs: list[str]) -> bool:
    exe_norm = _normalize(exe)
    for d in dirs:
        try:
            if os.path.commonpath([exe_norm, d]) == d:
                return True
        except ValueError:
            # Drives diferentes (C:\ vs D:\) — não há caminho em comum
            continue
    return False


@lru_cache(maxsize=None)
def sha256_file(path: str) -> str | None:
    """Hash SHA-256 do arquivo. Cacheado: vários processos (ex.: svchost)
    compartilham o mesmo executável."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


@lru_cache(maxsize=None)
def _cached_signature(path: str) -> SignatureStatus:
    return check_signature(path)


def collect_processes() -> list[ProcessInfo]:
    dirs = suspicious_dirs()
    results: list[ProcessInfo] = []

    # Pedir os atributos de uma vez é mais rápido, e campos sem permissão
    # (AccessDenied) vêm como None em vez de lançar exceção.
    for proc in psutil.process_iter(["pid", "name", "username", "exe"]):
        info = proc.info
        exe = info["exe"] or None

        if exe:
            sha256 = sha256_file(exe)
            signature = _cached_signature(exe)
            suspicious = is_suspicious_path(exe, dirs)
        else:
            sha256 = None
            signature = SignatureStatus.UNKNOWN
            suspicious = False

        results.append(
            ProcessInfo(
                pid=info["pid"],
                name=info["name"] or "?",
                username=info["username"],
                exe=exe,
                sha256=sha256,
                signature=signature,
                suspicious=suspicious,
            )
        )

    # Suspeitos primeiro, depois por nome
    results.sort(key=lambda p: (not p.suspicious, p.name.lower(), p.pid))
    return results
