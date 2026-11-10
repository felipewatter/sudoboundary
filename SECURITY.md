# Política de segurança

## Escopo

SudoBoundary v1.0.0 é um **simulador offline** sobre um JSON declarativo de privilégio. **Não** interpreta toda a gramática `sudoers`, **não** lê usuários do sistema operacional, **não** consulta LDAP/PAM/NSS, **não** executa `sudo` e **não** impõe controles no host. Um resultado favorável **não certifica** que o sistema real esteja seguro.

## Comunicação de vulnerabilidades

Não divulgue publicamente exemplos de exploração contra ambientes reais, tokens ou dados pessoais. Use o mecanismo de *private vulnerability reporting* do GitHub, quando habilitado pelo mantenedor, ou procure contato reservado no perfil do repositório. O mantenedor fará triagem e providenciará eventual correção.

## Recomendações ao operador

- Use snapshots sintéticos ou previamente sanitizados; nunca versione `sudoers` reais com nomes ou detalhes sensíveis sem autorização.
- Não use `--fail-on none` para bloquear mudanças: é modo somente informativo.
- Confirme a política real com `visudo -c`, inspeção de includes, `sudo -l` e testes autorizados de comportamento no host.
- Valide a matriz de queries: mudanças fora da matriz **não** são verificadas exaustivamente.
- Evite executá-lo com privilégios elevados. O programa não precisa de root.
- Arquivos de entrada não são buscados da rede. Arquivos de saída usam criação exclusiva e não sobrescrevem arquivos existentes.

## Endurecimento adotado

Entrada com limite de 2 MB; máximo de 2.000 regras e 5.000 consultas; arquivos regulares sem links simbólicos; rejeição de chaves JSON duplicadas e `NaN`; validação estrita de esquema; caminhos normalizados; operações determinísticas; nenhuma dependência externa de execução. Veja `docs/THREAT_MODEL.md`.
