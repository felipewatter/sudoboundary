# Changelog

## [1.0.0] - 2026-11-10

- Primeira versão pública proposta: avaliação offline e determinística de uma política declarativa simplificada.
- Avaliação por usuário, grupo, host, `runas`, caminho e vetor de argumentos; regra correspondente final prevalece.
- Auditoria com 11 códigos SB001–SB011 e graus de severidade.
- Gate de regressões: novo acesso, remoção de acesso e enfraquecimento dos controles.
- Contratos de acesso com assertivas, JSON, SARIF 2.1.0 e fingerprints SHA-256.
- Validadores estritos de estrutura, limites de recursos e recusa de links simbólicos.
- CI matricial para Linux/Windows e Python 3.11/3.13; workflow de release condicionado aos testes.

> Registro de versão de código. A publicação do release no GitHub é etapa separada e não é garantida por este arquivo.
