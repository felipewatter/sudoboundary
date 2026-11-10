# Plano de validação e aceite

## Testes locais

```bash
python -m pip install --no-deps .
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
sudoboundary audit --policy examples/baseline.json --fail-on high --format text
sudoboundary assert --policy examples/baseline.json --queries examples/queries.json --format text
```

## Caso negativo intencional

```bash
sudoboundary compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --queries examples/queries.json --fail-on high --format text
```

O retorno esperado é `1` (**mudança bloqueada**), não falha técnica. O retorno `2` indica documento inválido ou falha operacional.

## Release / GitHub Actions

- `push` na `main`: workflow dispara matriz Ubuntu/Windows x Python 3.11/3.13.
- Cada célula instala o pacote, executa unittest, compila sintaxe e verifica cenários positivo e negativo.
- O job de release está condicionado ao sucesso de toda a matriz; só opera em push na `main`, com permissão de escrita restrita ao job. Na primeira execução aprovada, cria a tag `v1.0.0` e publica o release. Se a versão já existir, não sobrescreve artefatos.
- O workflow gera ZIP e SHA-256 e cria release via `gh release create --target "$GITHUB_SHA"`.
- **Até a execução real no GitHub, nenhuma célula de CI, release ou link remoto é considerada validada.**

## Critérios de aceite

- 80 testes locais (ou mais, conforme versão) aprovados; nenhum arquivo privado ou credencial no pacote;
- Manual e comandos correspondem ao código;
- `audit` do baseline aceita; candidato inseguro bloqueia;
- Fingerprint SHA-256 reproducível; versão e tag coerentes;
- Matriz remota passa antes de disponibilizar release.
