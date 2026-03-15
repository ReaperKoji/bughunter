# Plano Tecnico de Automacao para Bug Bounty

## 1. Contexto e objetivos
- Automatizar testes ofensivos com foco em baixa taxa de falso-positivo.
- Operar somente em alvos autorizados, respeitando politeness e regras do programa.
- Manter modularidade por vetor com interface padrao `module.run(target) -> result`.
- Funcionar 24x7 com supervisao minima e controle de custos.

## 2. Decisoes de design e trade-offs
- Queue: RabbitMQ para durabilidade e Redis para baixa latencia. Producao prioriza RabbitMQ.
- Storage: Postgres para metadados, objeto para evidencias e logs grandes.
- LLM triage: fallback local para evitar dependencia de API externa.
- Concurrency: menor paralelismo por host para reduzir ban e ruida.
- Coverage vs precision: cobertura reduzida no inicio para maximizar confianca de PoC.

## 3. Arquitetura e fluxo
Componentes principais
- Orchestrator: aplica ordem de vetores, politeness e regras do programa.
- Scheduler: prioriza alvos e controla janelas de execucao.
- Workers: executam modulos em containers isolados.
- Queue: Redis ou RabbitMQ para jobs e retries.
- Storage: Postgres para metadados e objeto para evidencias.
- Observability: Prometheus, Grafana e logs centralizados.
- Triage LLM: reduz falso-positivo e gera justificativa curta.

Fluxo de dados
- Ingestao -> validacao de escopo -> execucao sequencial -> validacao de PoC -> relatorio -> metricas.

## 4. Modulos e interface padrao
- Interface: `module.run(target) -> ModuleResult`.
- `ModuleResult` inclui `status`, `evidence`, `metadata`, `candidate_poc`.
- Modulos suportados: idor, sqli, ssti, xss, lfi, rce.
- Cada modulo define politeness e timeouts proprios se necessario.
- RCE somente com probes nao destrutivos e sem execucao arbitraria.

## 5. State machine e pipeline
- Ordem configuravel por programa, por exemplo `idor -> sqli -> ssti -> xss -> lfi -> rce`.
- Fallback em `no_poc`, `false_positive`, `inconclusive` e `timeout`.
- Historico por alvo com motivo do fail e metadados.
- Emissao de PoC somente apos validacao positiva.

## 6. PoC validator e triagem LLM
Heuristicas obrigatorias
- Diferenca de status code ou headers relevantes.
- Mudanca consistente de corpo ou tempo de resposta.
- Presenca de stack trace, erro SQL ou refletividade controlada.

LLM assistido
- Entrada: evidencias sanitizadas e delta vs baseline.
- Saida: `poc_valid`, `inconclusive` ou `false_positive`.
- Rationale de 2 a 4 frases obrigatoria.
- Fallback para modelos locais (Ollama ou llama.cpp).

## 7. OWASP Mode e cobertura
Mapeamento base (OWASP Top 10 2021)
- A01 Broken Access Control: IDOR, bypass de autorizacao.
- A03 Injection: SQLi, XSS, SSTI, LFI.
- A04 Insecure Design: falhas de fluxo e validacao.
- A05 Security Misconfiguration: headers e defaults fracos.
- A06 Vulnerable Components: banners e versoes expostas.
- A07 Identification and Authentication: somente se escopo permitir.
- A10 SSRF: apenas se explicitamente permitido.

Score de cobertura
- `cobertura = categorias_atendidas / categorias_relevantes` por programa.
- Categorias irrelevantes ao escopo nao entram no denominador.

## 8. Politeness e stealth
- Rate limit por host e por programa.
- Randomizacao de User-Agent e pool de proxies rotativos.
- Jitter e shaping de trafego para evitar bloqueio.
- Proibicao de fuzzing massivo em endpoints sensiveis.

## 9. Resiliencia
- Backoff exponencial com jitter e limite maximo.
- Circuit breaker por host para reduzir ruido e ban.
- Retentativas controladas e limitadas.
- Fail-closed para alvos fora do escopo.

## 10. Dados, logging e privacidade
- Logs estruturados com `target_id`, `module`, `verdict` e `reason`.
- Retencao configuravel e expurgo de dados sensiveis.
- Evidencias armazenadas em objeto com controle de acesso.
- Mascaramento de tokens e credenciais em logs.

## 11. Deploy e isolamento
- Docker Compose em Ubuntu 22.04.
- Containers com `read_only`, `cap_drop`, `no-new-privileges`.
- User namespaces, limites de CPU, memoria e PIDs.
- Segredos criptografados e injetados via runtime.

## 12. Escalabilidade e distribuicao
- Single VPS para start.
- Evolucao para Axiom, ShadowClone ou workers serverless.
- Logica de orquestracao permanece igual, apenas backend muda.

## 13. Atualizacao automatica e hot reload
- Atualizacao periodica de templates e wordlists.
- Hot reload via volume compartilhado sem reiniciar workers.
- Versionamento de templates por execucao.

## 14. Runbook 24x7
Healthchecks
- Worker: heartbeat, backlog consumido e taxa de erro.
- Orchestrator: latencia, backlog e tempo medio por alvo.
- Triage: taxa de falso-positivo e tempo de decisao.

Autoscaling minimo
- Escalar se backlog > limite por 5 min.
- Reduzir se fila zerada por janela de estabilidade.

Logging e alertas
- Alertas para erro acima do limite, latencia e quedas de worker.
- Alertas de bloqueio por host e aumento de 403.

Playbook de falso-positivos
- Revalidar com payload benigno e baseline.
- Desabilitar modulo com FP alto.
- Ajustar heuristicas e listas de exclusao.

## 15. Checklist etico-legal e autorizacao
- Validar escopo antes de qualquer execucao.
- Abortar se KYC for exigido e nao estiver concluido.
- Proibir DoS, corrupcao de dados e fuzzing massivo em checkout/KYC.
- Nao contornar autenticacao fora do escopo permitido.
- Registrar consentimento e regras do programa por alvo.

## 16. Metricas e telemetria
- MTTR de triagem e validacao.
- Taxa de falso-positivo por modulo.
- Tempo medio por alvo e por vetor.
- Cobertura de superficie por programa.
- Taxa de bloqueio por host e erros por categoria.
- Versao de templates por execucao.

## 17. Nota sobre o documento base
- O arquivo "Automacao em Bug Bounty_ Ferramentas e Estrategias.docx" nao foi localizado no repositorio.
- As decisoes acima seguem os requisitos fornecidos e boas praticas de engenharia.
