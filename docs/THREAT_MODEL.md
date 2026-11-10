# Modelo de ameaças

## Ativos

- Políticas aprovadas como baseline;
- Contratos de acesso observáveis (matriz de consultas);
- Evidências de decisões e relatórios SARIF;
- Processo CI que valida mudanças antes de aceitação.

## Adversário e ataques simulados

Um colaborador ou mudança indevida pode tentar ampliar regras, incluir usuários indevidos em grupos, permitir execução como root sem senha, eliminar controles de logging ou desativar separação de ambiente. Um arquivo de entrada malformado pode tentar provocar falha, ambiguidades, entradas grandes ou interpretação enganosa.

## Mitigações implementadas

1. Modelo `deny-by-default` quando nenhuma regra casa.
2. Validação estrita de schema e tipos, chaves desconhecidas e duplicadas são recusadas.
3. Limites de arquivo, regras, grupos, nomes e consultas.
4. Recusa de caminhos relativos, segmentos `..`, shell globs e links simbólicos de entrada.
5. Não chama subprocessos, rede, LDAP, plugins, sudo ou shell no motor.
6. Relatórios gerados de modo determinístico com fingerprints e SHA-256 do modelo.
7. Saídas escritas com `O_EXCL`, nunca sobrescrevendo documento anterior.
8. Gate falha com códigos de saída distintos para risco versus erro de operação.

## Riscos residuais

- **Não existe verificação do host:** política JSON pode não refletir sudoers ou grupo real.
- **Cobertura limitada:** privilégio novo fora da matriz pode não ser detectado por comparação.
- **Simplificação:** não suporta a gramática inteira do sudoers, aliases de comandos, includes reais, precedência de Defaults em vários contextos, Runas/Host específicos, netgroups, opções PAM, hashing de executáveis, redirecionamentos shell e negações internas.
- **TOCTOU:** a checagem dos componentes de diretórios não bloqueia todas as mudanças concorrentes no filesystem durante a leitura.
- **Saídas e conteúdo:** nomes de usuários e serviços usados nos snapshots podem ser privados; exija sanitização antes de versionar ou compartilhar relatórios.
- **SARIF:** arquivo de integração CI não é prova de conformidade nem garantia de segurança.
- **Cadeia de suprimentos:** dependências de build são limitadas mas não vendorizadas; actions são fixadas em SHA conhecido, devem ser atualizadas conscientemente.

## Não objetivos

Executar comandos, elevar privilégios, pentest remoto, exploração de configurações, análise completa de `/etc/sudoers`, substituição de `visudo`, auditoria de contas reais ou varredura de servidores.
