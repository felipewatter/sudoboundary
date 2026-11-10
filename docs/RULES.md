# Catálogo de regras v1

> Resultados são **sinais heurísticos** sobre regras declarativas, não confirmações de exploração ou escalonamento real.

| ID | Grau | Detecta |
|---|---|---|
| SB001 | crítico | Regra de execução como root que inclui qualquer caminho (`path=ALL`) |
| SB002 | crítico | Regra de execução como root disponível a todos os usuários (`users=ALL`) |
| SB003 | alto | `nopasswd=true` ao executar como root |
| SB004 | alto | `setenv=true` em regra para root |
| SB005 | alto | Shell/interpretador/utilitário potencialmente expansível (`bash`, `python`, `vim`, `find` etc.) executável como root |
| SB006 | médio | Vetor de argumentos `argv=null` para um binário como root |
| SB007 | médio | `log_input` ou `log_output` desligado em uma regra root |
| SB008 | alto | `env_reset=false` como valor global do modelo |
| SB009 | médio | `secure_path=null` como valor global do modelo |
| SB010 | baixo | Regra privilegiada aplicável a todos os hosts (`hosts=ALL`) |
| SB011 | médio | Combinação de `path=ALL` com vetor de argumentos específico, sem restringir binário |
| SB100 | crítico/alto | Concessão introduzida para alguma consulta da matriz (crítico para `runas=root`) |
| SB101 | alto | Perda de controle protetivo em consulta autorizada nas duas versões |

## Severidade e gate

`--fail-on critical|high|medium|low|none` escolhe o limiar. `none` desativa o bloqueio. `access_removed` é rastreado, mas não bloqueia por padrão; processos que desejem exigir disponibilidade devem usar `assert` para testar contratos positivos.

IDs e fingerprints são estáveis sob a mesma versão e a mesma representação semântica do achado. O motor não calcula probabilidades de exploração nem graus de impacto específicos da organização.
