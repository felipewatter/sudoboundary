# Contrato semântico v1 — modelo declarativo

> **Importante:** esta é uma linguagem própria de declaração e teste. Não é parser, validador, substituto nem reimplementação de `sudoers(5)`. Nenhuma regra deste projeto deve ser transplantada como texto para `/etc/sudoers` sem revisão independente.

## Estrutura

`policy` tem `schema_version: 1`, opcional `defaults`, opcional `groups` e lista obrigatória `rules`.

`defaults` reconhece `authenticate`, `env_reset`, `secure_path`, `log_input`, `log_output`, `noexec`, `setenv`.

`groups` é um mapeamento explícito e estático de nome de grupo para nomes de usuários. Não admite grupos aninhados nem consulta NSS/LDAP/PAM. Ex.: `{"ops":["ana","bruno"]}`.

Cada regra tem `id`, `users`, `hosts`, `runas`, `commands`, `effect`; opcional `tags`, `reason`.

- `users`: nomes literais, `%grupo` para grupo declarado, ou `ALL`.
- `hosts`: nomes literais ou `ALL`; não interpreta FQDN/DNS nem padrões.
- `runas`: nomes literais ou `ALL`.
- `commands`: lista não vazia de objetos com `path` e `argv`.
- `path`: caminho POSIX absoluto normalizado, sem `.`/`..` nem glob, ou `ALL` para todos os caminhos.
- `argv`: lista de tokens de argumentos **exatamente iguais** na mesma ordem, incluindo `[]` (sem argumentos), ou `null` para qualquer vetor de argumentos; não considera expansão shell, semântica de execve, quoting ou regras de correspondência reais do sudoers.
- `effect`: `allow` ou `deny`.
- `tags`: `nopasswd`, `setenv`, `log_input`, `log_output`, `noexec`, sempre booleanos.

## Avaliação

A consulta possui `user`, `host`, `runas`, `path` e `argv`; todos são obrigatórios.

1. Para cada regra em ordem, verifique usuário individual ou pertencimento em grupo, host, usuário de destino e se **ao menos um comando** coincide com caminho e vetor de argumentos.
2. A **última regra correspondente** determina o resultado (modelo `last-match-wins`).
3. Se não há regra correspondente, o resultado é `implicit_deny`.
4. Quando a regra permite, `tags` da regra atual sobrescrevem os padrões; as flags são calculadas para a **regra vencedora** e **não são herdadas entre regras**.
5. O motor informa quais regras foram correspondidas e a identificadora vencedora.

A ideia da precedência inspira-se na documentação do `sudoers(5)`; este motor não simula toda a complexidade dos aliases, diretivas `Defaults`, ordem dos includes, comandos negados, sub-recursos, IDs/UID/GID, host/netgroup, digests, CWD/CHROOT, plugins, wildcard/regex, PAM, Runas_Spec, histórico de tags e restrições de ambiente do sudo.

## Regressões

Comparação de baseline e candidato sobre uma **matriz explícita** `queries.json`.

- `access_expanded`: consulta negada antes e permitida depois.
- `access_removed`: consulta permitida antes e negada depois (informativa; não bloqueia por padrão).
- `controls_weakened`: consulta permitida em ambos, mas `nopasswd` ou `setenv` mudou de false→true ou `log_input`/`log_output`/`noexec` mudou de true→false.
- Regras de auditoria novas são detectadas por fingerprints estáveis de `regra + sujeito`; algumas alterações de risco podem ser sinalizadas apenas pelas consultas, portanto a matriz deve ser extensa e relevante.

**A comparação não prova equivalência universal** entre políticas. Uma matriz vazia é rejeitada.

## Limites e garantias

Entrada máxima de 2 MB por documento, até 2.000 regras e 5.000 queries; texto em UTF-8; sem links simbólicos nos arquivos de entrada; JSON duplicado ou inválido é rejeitado; sem `NaN` e sem *shell glob* nas rotas. Saídas novas são escritas com criação exclusiva. Comportamento determinístico para os mesmos inputs e mesma versão do motor.
