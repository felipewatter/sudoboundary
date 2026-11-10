# Arquitetura

```text
           baseline.json        candidate.json          queries.json
                |                     |                      |
                +---------------------+----------------------+
                                      |
                             LER INPUTS LOCAIS
                     (limite, JSON estrito, anti-symlink)
                                      |
                            VALIDAR MODELO V1
                  (tipos, identificadores, comandos, tags)
                                      |
                +---------------------+-------------------+
                |                                         |
       AUDITOR DE RISCOS                        AVALIADOR DE QUERIES
       (SB001 a SB011)                          (last-match-wins no modelo)
                |                                         |
                +----------------------+------------------+
                                       |
                             MOTOR DE REGRESSÃO
                      (new, resolved, access_expanded,
                        access_removed, controls_weakened)
                                       |
                       JSON / SARIF / gate CI (0/1/2)
```

## Módulos

- `src/sudoboundary/core.py`: leitura, validação, avaliação, risco, comparação e SARIF.
- `src/sudoboundary/cli.py`: interface, status de saída e salvamento exclusivo.
- `tests/`: 80 testes unitários, adversariais e fluxo completo.
- `examples/`: política aprovada, mudança insegura e matriz explícita.
- `scripts/package.py`: pacote ZIP determinístico e manifesto SHA-256.
- `.github/workflows/ci.yml`: matriz de testes e gate de release após sucesso.

## Fronteiras de confiança

Os arquivos JSON são tratados como **não confiáveis**; o sistema de arquivos local e a pessoa que constrói a matriz devem ser confiáveis. O resultado de análise não substitui evidência sobre o host real. A execução não requer rede, banco, credenciais ou root.

## Códigos de saída

- `0`: sucesso (ou `--fail-on none`, modo informativo);
- `1`: falha de segurança pelo limiar ou assertiva não atendida;
- `2`: entrada inválida, erro de leitura/escrita ou operação não suportada.

Os códigos são para integração contínua e não certificam segurança do sistema real.
