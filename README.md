<div align="center">

# SudoBoundary

### Gate de regressão de privilégios administrativos Linux — análise offline, explicável e reproduzível

[![CI](https://github.com/felipewatter/sudoboundary/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/sudoboundary/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/relat%C3%B3rios-SARIF%202.1.0-purple.svg)](docs/ARCHITECTURE.md)
[![Offline](https://img.shields.io/badge/runtime-offline-success.svg)](SECURITY.md)

**v1.0.0 · Projeto público de segurança operacional e DevSecOps**  
Autor: [Felipe Silva](https://github.com/felipewatter) · [Documentação em inglês](README.en.md)

</div>

> **Escopo rigoroso:** o SudoBoundary é um **simulador de políticas JSON explicitamente modeladas**. Ele **não** interpreta os arquivos reais `/etc/sudoers`, **não** chama `sudo`, **não** executa comandos privilegiados, **não** altera servidores e **não** comprova que um host Linux esteja seguro. Todos os resultados são referentes ao conjunto de dados fornecido pelo operador, que deve ser revisado e sanitizado.

## Sumário

1. [O problema que resolve](#1-o-problema-que-resolve)
2. [Funcionalidades](#2-funcionalidades)
3. [Por que é diferente?](#3-por-que-é-diferente)
4. [Arquitetura resumida](#4-arquitetura-resumida)
5. [Instalação e primeiros comandos](#5-instalação-e-primeiros-comandos)
6. [Modelo de política](#6-modelo-de-política)
7. [Como funciona a análise](#7-como-funciona-a-análise)
8. [Catálogo de riscos](#8-catálogo-de-riscos)
9. [Automação CI/CD e release](#9-automação-cicd-e-release)
10. [Testes e validação](#10-testes-e-validação)
11. [Segurança, limitações e privacidade](#11-segurança-limitações-e-privacidade)
12. [Estrutura do repositório](#12-estrutura-do-repositório)
13. [Documentação e referências](#13-documentação-e-referências)
14. [Contribuições e licença](#14-contribuições-e-licença)

## 1. O problema que resolve

Em equipes de infraestrutura, suporte e operações, conceder permissões administrativas pode ser necessário para reiniciar serviços, ler logs, atualizar aplicações ou cumprir incidentes. Em produção, **a menor mudança em uma permissão** pode transformar uma consulta de status limitada em acesso administrativo ilimitado. Revisões superficiais frequentemente não respondem: *quem ganhou um privilégio novo, em qual host, sob qual identidade e graças a qual regra?*

O SudoBoundary representa um contrato de autorização em um JSON legível e versionável, testa **consultas concretas de acesso** e compara um cenário aprovado (**baseline**) com uma mudança proposta (**candidate**). O resultado pode bloquear o merge ou release quando surgem permissões não previstas.

### Exemplo de pergunta operacional

> A equipe de operações pode consultar o status do Nginx em `web-01` como `root`, mas deve continuar proibida de reiniciar o serviço sem autorização adicional?

O motor pode testar as duas situações; se a segunda passar de negada para permitida, produz `access_expanded` e o identificador `SB100` quando configurado para bloquear regressões.

## 2. Funcionalidades

| Área | Recurso implementado | Benefício |
|---|---|---|
| Modelo de acesso | Usuário, grupo estático, host, `runas`, comando e vetor de argumentos | Entender exatamente qual consulta está sendo autorizada **no modelo** |
| Precedência | Última regra correspondente vence | Demonstrar sobreposição e mudanças de prioridade no conjunto declarado |
| Decisões explicáveis | IDs das regras correspondentes, regra decisora e tags efetivas | Investigar a razão do resultado |
| Auditoria de riscos | Regras SB001–SB011 | Sinalizar acesso root amplo, `NOPASSWD`, `SETENV`, perda de logging e interpretadores |
| Detecção de regressões | `access_expanded`, `access_removed`, `controls_weakened` | Enxergar mudança de autorização e enfraquecimento de defesas |
| Contratos e assertivas | Matriz explícita de decisões esperadas | Impedir que testes de permissão previamente aprovados deixem de valer |
| Evidências | JSON, SARIF 2.1.0, fingerprints e SHA-256 do modelo | Integrar revisões, pipelines e auditorias técnicas |
| Segurança de entrada | Limite de tamanho, limites de quantidade, JSON estrito, recusa de links simbólicos e glob de caminhos | Reduzir ambiguidades e acidentes de análise |
| Operação | CLI multiplataforma Python 3.11+ | Rodar localmente e em pipeline, sem infraestrutura externa |
| Entrega | ZIP determinístico, SHA-256 e workflow GitHub Actions | Facilitar distribuição verificável do projeto |

**Não há dependências de execução** além da biblioteca padrão do Python. O `pip` utiliza o `setuptools` no *build*, não no uso cotidiano.

## 3. Por que é diferente?

O projeto não repete as soluções de segurança já presentes no [portfólio público](https://github.com/felipewatter): não analisa JWT, dependências, APIs, cadeias de releases, integridade de arquivos, Kubernetes RBAC, firewall, backups ou configurações de serviços systemd. Seu foco é **regressão de concessões administrativas de comando em sistemas Linux**, delimitada por uma linguagem JSON própria.

Ferramentas como o [Cisco CX `sudo-parser`](https://github.com/CiscoCXSecurity/sudo-parser) buscam interpretar arquivos de sudoers para identificar riscos. O SudoBoundary **não executa essa função**: recebe um **modelo independente que o operador precisa compor e verificar**, oferecendo decisões explicáveis, comparação de cenários e gates testáveis. A [documentação oficial do sudo](https://www.man7.org/linux/man-pages/man5/sudoers.5.html) é a referência para o formato real e suas restrições, não uma certificação do modelo deste projeto.

## 4. Arquitetura resumida

```text
baseline.json          candidate-risky.json              queries.json
     |                         |                                |
     +-------------------------+--------------------------------+
                               |
                    LEITURA E VALIDAÇÃO
                 JSON estrito / tipo / tamanho
                               |
                 REGRAS E MATRIZ DECLARATIVAS
                               |
                  +------------+--------------+
                  |                           |
           Análise heurística           Motor de decisão
           SB001–SB011                 last-match-wins
                  |                           |
                  +------------+--------------+
                               |
                       Comparador de riscos
                         e de autorizações
                               |
             JSON / SARIF / SHA-256 / exit 0, 1 ou 2
                               |
                         GitHub Actions
```

Detalhamento: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## 5. Instalação e primeiros comandos

### Pré-requisitos

- Python 3.11 ou superior;
- Git para clonar e atualizar o código;
- Windows, Linux ou macOS para análise local. **Nenhum privilégio de administrador é necessário.**

```bash
git clone https://github.com/felipewatter/sudoboundary.git
cd sudoboundary
python -m pip install --no-deps .
sudoboundary --version
```

**Windows PowerShell** — caso sua política de execução não permita ativar um ambiente virtual, não há necessidade de ativá-lo: o comando `python -m` também funciona executando a partir da raiz e configurando o caminho dos módulos.

```powershell
$env:PYTHONPATH = 'src'
python -m sudoboundary --version
python -m sudoboundary audit --policy examples/baseline.json --fail-on high --format text
```

### Auditoria inicial

```bash
sudoboundary audit --policy examples/baseline.json --fail-on high --format text
```

A política aprovada contém permissões específicas; o retorno esperado é `0` (**nenhum achado com severidade alta ou crítica**). Riscos abaixo do limiar continuam reportáveis.

### Explicação de uma permissão

```bash
sudoboundary explain --policy examples/baseline.json --request examples/request.json
```

Retorna `allowed`, `matched_rule_ids`, `deciding_rule_id`, `effect` e `tags` da regra que determina o resultado.

### Contratos de acesso

```bash
sudoboundary assert --policy examples/baseline.json --queries examples/queries.json --format text
```

Verifica se cada consulta responde ao valor `expected` fornecido no arquivo. Falha com exit `1` quando a resposta diverge. Uma consulta sem `expected` no modo `assert` é rejeitada com exit `2`.

### Comparar mudança proposta

```bash
sudoboundary compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --queries examples/queries.json --fail-on high --format text
```

**Resultado esperado: exit `1`, bloqueado intencionalmente**. A proposta insegura inclui uma regra de execução ampla que permite a membros de operações executarem comandos root de maneira excessiva. O gate detalha os novos achados e a ampliação identificada nas consultas.

### Gerar evidências JSON e SARIF

```bash
sudoboundary compare --baseline examples/baseline.json --candidate examples/candidate-risky.json --queries examples/queries.json --fail-on high --output relatorio.json --sarif relatorio.sarif
```

Os arquivos `relatorio.json` e `relatorio.sarif` devem **não existir antes da execução**; o programa jamais os sobrescreve. A exportação gera dados estruturados úteis para ferramentas de análise de código. Um arquivo SARIF não é prova de risco explorável no ambiente real.

## 6. Modelo de política

Exemplo reduzido (a demonstração completa está em [`examples/baseline.json`](examples/baseline.json)):

```json
{
  "schema_version": 1,
  "groups": {"ops": ["ana", "bruno"]},
  "rules": [
    {
      "id": "ops-view-service",
      "users": ["%ops"],
      "hosts": ["web-01"],
      "runas": ["root"],
      "commands": [
        {"path": "/usr/bin/systemctl", "argv": ["status", "nginx.service"]}
      ],
      "effect": "allow",
      "tags": {
        "nopasswd": false,
        "setenv": false,
        "log_input": true,
        "log_output": true,
        "noexec": true
      }
    }
  ]
}
```

**Convenções importantes:** `ALL` é um marcador especial somente nos seletores; `argv: null` significa qualquer sequência de argumentos; `argv: []` significa nenhum argumento. Um vetor de argumentos literal deve coincidir exatamente. O formato não suporta a gramática de arquivos sudoers, aliases reais, wildcards de caminhos nem expansão de shell. Para conhecer o contrato completo, consulte [docs/SEMANTICS.md](docs/SEMANTICS.md).

## 7. Como funciona a análise

O avaliador percorre as regras em ordem, combina cinco dimensões de acesso e registra cada correspondência. A última correspondência decide `allow` ou `deny`. Na ausência de regra aplicável, a resposta é **negação implícita**.

A comparação confere os fingerprints dos achados, compara decisões sobre a matriz informada e analisa mudanças nas flags de proteção. Como a matriz é necessariamente finita, a ferramenta **não demonstra equivalência universal** entre políticas: o operador deve cobrir cenários positivos, negativos e casos de borda relevantes.

**Códigos de saída:** `0` aprovado; `1` gate bloqueado ou assertiva falhou; `2` erro de formato, leitura, escrita ou operação.

## 8. Catálogo de riscos

| ID | Severidade | Sinal identificado |
|---|---|---|
| SB001 | Crítica | Caminho `ALL` executável como root |
| SB002 | Crítica | Usuário `ALL` autorizado a executar como root |
| SB003 | Alta | Autorização root sem senha (`NOPASSWD`) |
| SB004 | Alta | `SETENV` liberado para root |
| SB005 | Alta | Shell, interpretador ou ferramenta expansível autorizada como root |
| SB006 | Média | Argumentos ilimitados para comando como root |
| SB007 | Média | Logging de entrada ou saída insuficiente |
| SB008 | Alta | `env_reset` desativado |
| SB009 | Média | `secure_path` ausente |
| SB010 | Baixa | Concessão root aplicável a todos os hosts |
| SB011 | Média | Caminho irrestrito com argumentos específicos |
| SB100 | Crítica/alta | Acesso novo identificado na matriz (crítica para root) |
| SB101 | Alta | Controles existentes enfraquecidos |

Mais detalhes, lógica e limitações: [docs/RULES.md](docs/RULES.md).

## 9. Automação CI/CD e release

O workflow `.github/workflows/ci.yml` automatiza:

1. Execução de testes em **Ubuntu e Windows** com **Python 3.11 e 3.13** (quatro combinações);
2. Instalação do pacote sem dependências de execução, validação de sintaxe e testes unitários;
3. Testes de baseline aprovado, contrato de acesso e candidato propositalmente inseguro;
4. Geração de artefatos apenas depois de sucesso total;
5. Criação automática e única do release `v1.0.0`, com ZIP e checksum SHA-256, após uma submissão à `main` que passe em toda a matriz.

Os gatilhos são `push` para `main`, `push` para tags `v*`, pull requests para `main` e execução manual. **O release ocorre somente no `push` para `main`** após a aprovação dos quatro jobs; não em PRs ou tags isoladas. A permissão padrão é **somente leitura**; somente o job de release recebe `contents: write`. As ações utilizadas são fixadas por **SHA completo** para reduzir dependência de tags mutáveis. O pipeline não usa `pull_request_target` nem executa comandos providos pelo conteúdo das políticas.

**Atenção:** testes locais não substituem a conferência de runs reais. O badge só representa a CI após sua efetiva publicação e execução no GitHub. Veja [docs/VALIDATION.md](docs/VALIDATION.md).

## 10. Testes e validação

```bash
python -m unittest discover -s tests -v
python -m compileall -q src tests scripts
python scripts/package.py
```

A suíte inclui 80 testes automatizados para regras de autorização, precedência, grupos, recursos e arquivos maliciosos, riscos, regressões, códigos de saída, relatórios e workflow da CLI.

O empaquetador gera `dist/sudoboundary-v1.0.0-source.zip` e o respectivo manifesto `.sha256`. As datas internas do ZIP são fixas para estabilidade do artefato. Veja o [plano de validação](docs/VALIDATION.md).

## 11. Segurança, limitações e privacidade

- **Modelo parcial:** o arquivo JSON é uma representação que deve ser construída e revisada; não lê nem converte automaticamente arquivos sudoers de produção. Não extrapole resultados para sistemas reais.
- **Sem execução privilegiada:** `sudo`, shells, alteração de políticas e processos do host não são chamados pelo motor.
- **Validação real obrigatória:** compare com configuração efetiva, `visudo -c`, `sudo -l` e testes autorizados; avalie includes, PAM, grupos e resolução de caminhos.
- **Proteção de inputs:** entradas malformadas, JSON com chaves repetidas, `NaN`, caminhos inválidos, links simbólicos e arquivos excessivos são recusados.
- **Proteção de dados:** modelos podem conter identificadores internos; sanitizar antes de publicar; nenhum arquivo de produção ou chave privada está incluído.
- **Riscos residuais:** falso positivo/negativo, cobertura de matriz, variações de sudoers e race conditions do filesystem; não use como único controle de produção.

Leia [SECURITY.md](SECURITY.md) e o [modelo de ameaças](docs/THREAT_MODEL.md) antes de qualquer implantação.

## 12. Estrutura do repositório

```text
sudoboundary/
├── .github/workflows/ci.yml      # Testes e release condicionados
├── .github/dependabot.yml        # Revisão de dependências de CI e build
├── src/sudoboundary/
│   ├── core.py                   # Motor, validadores, comparação e SARIF
│   ├── cli.py                    # CLI e códigos de saída
│   ├── __init__.py
│   └── __main__.py
├── examples/                      # Baseline, candidato, matriz e requisição
├── tests/                         # Testes unitários, negativos e integrados
├── scripts/package.py            # Empacotamento determinístico
├── docs/                          # Arquitetura, riscos, semântica, ameaças
├── README.md / README.en.md
├── SECURITY.md / CONTRIBUTING.md
├── CHANGELOG.md / RELEASE_NOTES.md
├── pyproject.toml / LICENSE
└── .gitignore
```

## 13. Documentação e referências

- [Semântica e limites do modelo](docs/SEMANTICS.md)
- [Arquitetura técnica](docs/ARCHITECTURE.md)
- [Catálogo de regras](docs/RULES.md)
- [Modelo de ameaças](docs/THREAT_MODEL.md)
- [Procedimento de validação](docs/VALIDATION.md)
- [Fontes de referência e trabalhos relacionados](docs/REFERENCES.md)
- [Política de segurança](SECURITY.md)
- [Notas de release](RELEASE_NOTES.md)
- [Documentação em inglês](README.en.md)

## 14. Contribuições e licença

Sugestões de regras, testes adversariais e exemplos didáticos podem ser submetidos via issues e pull requests. Consulte [CONTRIBUTING.md](CONTRIBUTING.md). O projeto usa a licença [MIT](LICENSE).

**Criado por [Felipe Silva](https://github.com/felipewatter) — projeto de portfólio de segurança e operações de TI.**
