# Sentinel

Mini-EDR (Endpoint Detection & Response) pessoal para Windows, com foco educacional em cibersegurança.

## Objetivo

Monitorar em tempo real:

- Downloads que chegam na máquina (hash + reputação via VirusTotal + checagem de assinatura).
- Processos em execução (árvore, assinatura, origem, conexões de rede).
- Armazenamento e integridade de pastas sensíveis.
- Persistência (chaves `Run`, Scheduled Tasks, serviços).

Cada detecção é mapeada para técnicas do **MITRE ATT&CK**.

## Status

Em desenvolvimento — fase inicial de setup.

## Stack

- Python 3.12+
- PySide6 (interface + tray)
- psutil, watchdog, pefile, requests

## Aviso

Projeto educacional. **Não substitui um antivírus.**
