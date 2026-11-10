# Contribuições

1. Abra uma issue descrevendo o caso e o comportamento esperado.
2. Proponha uma modificação pequena sem ampliar o modelo de maneira silenciosa. Alterações semânticas exigem testes e atualização de `docs/SEMANTICS.md`.
3. Execute `python -m unittest discover -s tests -v` e `python -m compileall -q src tests scripts`.
4. Inclua testes para entradas maliciosas, falsos positivos e regressões de autorização; não adicione execução de comandos externos no motor.
5. Não inclua segredos, `sudoers` reais, identificadores privados ou dados de produção.
6. Documente riscos, limitações e comportamento de compatibilidade do formato JSON.

Código de conduta: discussão técnica respeitosa, sem exposição de dados ou credenciais.
