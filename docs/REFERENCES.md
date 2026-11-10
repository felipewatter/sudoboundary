# Referências e trabalhos relacionados

Material de pesquisa para posicionamento e revisão semântica. Nenhum projeto listado é copiado ou incorporado.

- Documentação oficial `sudoers(5)` — https://www.man7.org/linux/man-pages/man5/sudoers.5.html
- Código e documentação oficial do sudo — https://github.com/sudo-project/sudo
- Cisco CX Security `sudo-parser` (análise de texto sudoers real, não o nosso modelo de regressão) — https://github.com/CiscoCXSecurity/sudo-parser
- `sudo-rs` (implementação de sudo em Rust, escopo diferente) — https://github.com/trifectatechfoundation/sudo-rs
- GitHub Actions: segurança e pinning de ações — https://docs.github.com/en/actions/reference/security/secure-use
- SARIF 2.1.0 — https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

## Posição do SudoBoundary

O SudoBoundary **não** compete como parser oficial de `sudoers`. Ele testa contratos explícitos e mudanças em políticas normalizadas submetidas a revisão humana. A ferramenta é diferente de um scanner de binários, emulador de permissões do kernel, gerenciador de usuário ou agente de host. Não atribua o resultado a um sudo real sem verificação separada.
