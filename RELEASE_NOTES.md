# SudoBoundary v1.0.0

Primeira versão do **SudoBoundary**, um gate offline de políticas declarativas de privilégios para ambientes Linux.

## Destaques

- Análise de permissões com trilha explicável de correspondência e precedência;
- Detecção de concessões amplas de root, `NOPASSWD`, `SETENV`, interpretadores e perdas de logging;
- Comparação entre baseline e candidato com identificação de privilégios introduzidos e controles enfraquecidos;
- Matriz de consultas e assertivas de acesso em CI;
- JSON estável, SARIF 2.1.0 e evidências SHA-256;
- Zero dependências externas em runtime, sem chamadas de rede ou execução de `sudo`.

## Compatibilidade

Python 3.11 ou superior; CI planejada para Ubuntu/Windows com Python 3.11 e 3.13.

## Limitações

Analisa um **modelo explícito JSON**, não arquivos `sudoers` reais; não certifica nenhuma configuração do sistema operacional. Consulte `docs/SEMANTICS.md`, `SECURITY.md` e `docs/THREAT_MODEL.md`.

## Verificação do artefato

O ZIP oficial e o manifesto SHA-256 são produzidos por `python scripts/package.py` e anexados ao release apenas após CI verde.
