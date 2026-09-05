# Fidelizaê! v161


## v161 — WhatsApp: templates oficiais e status real de entrega
- Envios proativos por WhatsApp (automações e campanhas) agora exigem o nome do template oficial aprovado na Meta e o idioma correspondente.
- O backend envia mensagens do tipo `template` pela WhatsApp Cloud API quando o template Meta estiver configurado, evitando a dependência da janela de 24 horas para iniciar/reabrir conversas.
- Parâmetros do corpo são derivados, em ordem, dos placeholders `{nome}`, `{empresa}`, `{cliente}`, `{selos}`, `{meta}` e `{recompensa}` para corresponder a `{{1}}`, `{{2}}` etc. no template aprovado.
- Testes de WhatsApp deixam de exibir sucesso definitivo assim que a Meta aceita a requisição: o painel aguarda o webhook e mostra `delivered/read` ou a falha real do provedor.
- A fila passa a exibir o status do provedor e código/título do erro do WhatsApp.
- Migração v161 adiciona os campos de template Meta e detalhes de erro sem remover dados existentes.

## v160

- Integração oficial do **WhatsApp Embedded Signup** disponibilizada diretamente no painel do administrador da empresa PRO, com botão **Conectar com WhatsApp**.
- O fluxo usa `META_APP_ID`, `META_CONFIG_ID`, `META_APP_SECRET`, `PUBLIC_BASE_URL` e o SDK oficial da Meta; a empresa escolhe/vincula a própria WABA e o próprio número sem expor token ao usuário.
- Novo endpoint autenticado `/api/client-admin/meta-config` fornece somente os dados públicos necessários ao SDK para administradores da empresa.
- Novo endpoint `/api/client-admin/integration/whatsapp/embedded-complete` troca o código no servidor, valida o Phone Number ID, assina a WABA no webhook global e grava o access token criptografado no tenant correto.
- O salvamento de outras configurações da empresa não sobrescreve mais uma conexão WhatsApp Embedded existente com o modo manual. A configuração manual foi mantida apenas como opção avançada para compatibilidade.
- O status do WhatsApp no modal passa a mostrar **Conectado pela Meta** e oferece **Reconectar WhatsApp** para troca futura de conta/número.

## v159

- Implementado o webhook oficial da Meta/WhatsApp em `GET/POST /api/webhooks/meta/whatsapp`.
- A verificação inicial da Meta usa `META_WEBHOOK_VERIFY_TOKEN`; o valor deve existir somente como variável de ambiente no Railway.
- Entregas POST são autenticadas pela assinatura `X-Hub-Signature-256` usando `META_APP_SECRET`; payloads sem assinatura válida são rejeitados.
- Eventos são associados à empresa correta por `phone_number_id` e, como fallback, `waba_id`, preservando o isolamento multiempresa.
- O sistema registra apenas metadados técnicos dos eventos do webhook; conteúdo de mensagens recebidas não é persistido nessa tabela.
- IDs (`wamid`) retornados pela Cloud API passam a ser gravados na fila para correlacionar os status `sent`, `delivered`, `read` e `failed` recebidos da Meta.
- Em caso de erro interno no processamento, o webhook retorna HTTP 500 para permitir nova tentativa de entrega pela Meta.

### Webhook Meta / WhatsApp

No Railway, configure um token secreto forte e exclusivo, por exemplo:

```
META_WEBHOOK_VERIFY_TOKEN=<segredo longo e aleatório>
```

Na Meta, em **Configurar webhooks**:

```
URL de callback: https://app.fidelizae.com.br/api/webhooks/meta/whatsapp
Verificar token: o mesmo valor de META_WEBHOOK_VERIFY_TOKEN
```

`META_APP_SECRET` deve continuar configurado no Railway, pois é usado para validar criptograficamente os eventos POST enviados pela Meta.

## v158

- Ajustado o modal de confirmação do envio de alertas: removida apenas a frase “Nenhum e-mail será enviado.”, mantendo a confirmação “Este alerta aparecerá no painel de X empresa(s). Deseja continuar?”.

## v157

- **Enviar alerta** agora usa os mesmos filtros de público do envio de e-mail: plano (Iniciante, Intermediário ou PRO), status (ativas, arquivadas ou todas) e programa (Selos ou Pontos).
- O modo coletivo foi renomeado para **Todas / por filtro** e mostra em tempo real quantas empresas receberão o alerta e o resumo do público selecionado.
- Incluídos públicos rápidos **Todas as PRO**, **Apenas Selos** e **Empresas Iniciantes**.
- É possível salvar públicos personalizados no banco, reutilizá-los posteriormente e excluí-los quando não forem mais necessários.
- O histórico dos alertas registra os filtros utilizados em cada disparo para facilitar auditoria e conferência.
- Mantidos seleção manual de empresas, prioridades, leitura individual pelos administradores e envio totalmente interno sem consumo de e-mail.

## v156

- Corrigido o modal de **Enviar alerta** para manter rolagem vertical interna em telas menores ou quando a lista de empresas aumenta, sem esconder os campos finais e o botão de envio.
- Reforçado o envio autenticado do Painel Fidelizaê!: requisições administrativas agora usam credenciais same-origin explicitamente e renovam a sessão/CSRF uma vez em caso de `unauthorized` ou `csrf_failed`, evitando falhas transitórias de sessão.
- Mantidos os alertas internos sem uso de e-mail, com envio para todas as empresas ativas ou seleção manual.

## v155
- Comunicação do Painel Fidelizaê! agora possui submenu **Enviar e-mail** e **Enviar Alerta**.
- Novo alerta interno gratuito para todas as empresas ativas ou empresas específicas, sem consumo de envio de e-mail.
- Alertas aparecem no painel dos administradores das empresas, com prioridade, histórico e leitura individual por administrador.
- Alertas institucionais são auditáveis e podem ser marcados como lidos sem afetar outros administradores da mesma empresa.



## v154
- Central de Comunicação no Painel Fidelizaê! para mensagens institucionais da plataforma às empresas cadastradas.
- Envio individual pelo botão **Enviar e-mail** dentro de Detalhes da empresa e envio coletivo pela nova opção **Comunicação** do menu superior.
- Seleção manual de múltiplas empresas ou disparo filtrado por plano, status e tipo de programa.
- Pré-visualização do e-mail, assunto, título, mensagem e CTA opcional com link HTTPS.
- Modelos prontos e modelos personalizados reutilizáveis.
- Histórico auditável de disparos com status por destinatário (pendente, enviado, nova tentativa ou falha).
- Os disparos administrativos usam exclusivamente o e-mail global do Fidelizaê!, mantendo separadas as credenciais de comunicação das empresas clientes.
- Processamento em fila com tentativas automáticas, evitando travar o painel em envios coletivos.

## v153
- Corrigido o marcador documental antigo **“Versão atual: v142”** para a versão corrente **v153**.
- Implementado monitoramento externo de uptime por **GitHub Actions**, executado aproximadamente a cada 5 minutos a partir de infraestrutura externa ao Railway.
- O monitor consulta `https://app.fidelizae.com.br/api/health`, faz novas tentativas em falhas transitórias e valida tanto o HTTP 200 quanto o JSON `ok=true`.
- Em indisponibilidade, o workflow cria ou atualiza uma única issue **“Produção indisponível”** no repositório; na recuperação, comenta e fecha automaticamente a issue.
- O endpoint `/api/health` agora testa também a conexão com o banco (`SELECT 1`) e retorna **HTTP 503** quando a aplicação está acessível mas o banco não está, evitando falso positivo de disponibilidade.
- A resposta saudável do health check informa apenas dados operacionais não sensíveis: status, serviço, versão, tipo de banco e latência do teste ao banco.
- HSTS permanece opt-in. Pode ser ativado posteriormente com `CLUBE_HSTS_ENABLED=1` após confirmar que todos os subdomínios que serão cobertos possuem HTTPS válido.

### Monitoramento externo de uptime
O arquivo `.github/workflows/uptime-monitor.yml` monitora a produção de fora do Railway usando os runners do GitHub. Para ficar ativo, publique esta versão no branch padrão do repositório e mantenha **GitHub Actions** habilitado. O workflow também pode ser disparado manualmente em **Actions > Fidelizaê! Uptime Monitor > Run workflow**.

Quando houver falha persistente após as tentativas, é aberta uma issue com o link da execução. Quando o serviço voltar a responder normalmente, a issue é fechada automaticamente. Para receber também notificações por e-mail das issues/workflows, mantenha as notificações do repositório habilitadas na sua conta GitHub.

### HSTS
HSTS (`Strict-Transport-Security`) instrui o navegador a acessar o domínio exclusivamente por HTTPS durante o período configurado, mesmo que alguém tente abrir uma URL `http://`. Isso reduz ataques de downgrade/SSL stripping. A aplicação já suporta `CLUBE_HSTS_ENABLED=1`, `CLUBE_HSTS_MAX_AGE` e `CLUBE_HSTS_INCLUDE_SUBDOMAINS`.

Como `includeSubDomains` também força HTTPS em todos os subdomínios, habilite HSTS somente depois de confirmar que todos eles possuem HTTPS válido. O recurso não substitui o SSL/TLS do Cloudflare; ele adiciona uma proteção persistente no navegador.

## v152
- Removido o mecanismo temporário de teste do Sentry após validação bem-sucedida em produção.
- Removidos o botão **TESTAR SENTRY**, o endpoint `POST /api/manager/sentry-test`, a exceção proposital e o registro de auditoria associado ao teste.
- O monitoramento real do Sentry permanece ativo via `SENTRY_DSN`, com captura de exceções não tratadas, sem PII padrão e sem tracing/performance.
- O Diagnóstico da plataforma continua exibindo o estado do Sentry como **Ativo**, **Configurado • indisponível** ou **Não configurado**.

## v151
- Teste controlado do Sentry disponível somente para Administrador Geral autenticado no Painel Fidelizaê!.
- Novo endpoint `POST /api/manager/sentry-test` protegido por sessão de manager, CSRF e rate limit; não existe rota pública de erro.
- O teste captura uma exceção proposital dentro de bloco controlado, envia ao Sentry, aguarda o flush por até 2 segundos e retorna o `event_id` sem derrubar a requisição nem alterar dados da plataforma.
- O Diagnóstico da plataforma passa a mostrar o estado do Sentry e oferece o botão **TESTAR SENTRY** somente quando o monitoramento está ativo.
- Cada teste fica registrado na auditoria administrativa.

## v150
- Integração com Sentry para monitoramento externo de erros do backend em produção.
- O monitoramento só é ativado quando `SENTRY_DSN` estiver configurado; sem a variável, a aplicação continua funcionando normalmente.
- O DSN permanece exclusivamente em variável de ambiente e não é gravado no código-fonte.
- Envio padrão de PII desativado (`send_default_pii=False`) e tracing/performance desativado (`traces_sample_rate=0.0`) para focar apenas em Error Monitoring.
- Eventos recebem `environment` via `APP_ENV` (fallback `production`) e release `fidelizae@v150`.
- Exceções não tratadas nas threads HTTP são capturadas pelo Sentry e continuam seguindo o tratamento padrão do servidor.
- Dependência adicionada: `sentry-sdk>=2,<3`. O backend atual usa `ThreadingHTTPServer` da biblioteca padrão; não há dependência Flask.

## v149
- Correção do utilitário `tools/backup_restore.py`: agora `validate` e `restore-sqlite` aceitam diretamente backups compactados `.json.gz` baixados do Cloudflare R2, além do JSON puro.
- A detecção de gzip usa extensão e assinatura do arquivo, mantendo compatibilidade com backups anteriores.
- Testado com o backup real `daily/2026-09-01/fidelizae-backup.json.gz`: checksum válido, restauração isolada concluída, `integrity_check` OK e `foreign_key_check` sem erros.

## v148
- Backup automático privado no Cloudflare R2 usando as variáveis `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_ENDPOINT`, `R2_BUCKET` e `R2_ACCOUNT_ID`.
- Gera backup diário compactado em `daily/YYYY-MM-DD/fidelizae-backup.json.gz`, compatível com a retenção de 30 dias configurada no bucket.
- No primeiro dia de cada mês, também grava `monthly/YYYY-MM/fidelizae-backup.json.gz`, compatível com a retenção de 365 dias configurada no bucket.
- O backup é validado por checksum SHA-256 antes do envio e o bucket permanece privado.
- O Diagnóstico do Painel Fidelizaê! passa a mostrar se o R2 está configurado e a data/hora do último backup automático concluído na instância atual.
- O botão de backup manual existente continua disponível e inalterado.

## v147
- E-mails institucionais da própria plataforma usam a infraestrutura global da Brevo (`BREVO_API_KEY`) sem preencher ou reutilizar as credenciais das empresas clientes.
- Remetente institucional padrão passa a ser **Fidelizaê! <contato@fidelizae.com.br>**; `BREVO_SENDER_EMAIL` continua podendo sobrescrever o endereço no Railway quando necessário.
- `BREVO_REPLY_TO` passa a usar `contato@fidelizae.com.br` como fallback institucional.
- E-mail, WhatsApp e E-commerce configurados em **Editar empresa** continuam isolados por empresa; campanhas e boas-vindas de clientes não usam as credenciais globais do Fidelizaê! como fallback.
- Para produção, mantenha no Railway `BREVO_SENDER_EMAIL=contato@fidelizae.com.br` e `BREVO_SENDER_NAME=Fidelizaê!` para garantir o mesmo remetente mesmo quando já existirem variáveis antigas.

## v144
- Padronização dos botões do menu superior nos painéis Fidelizaê!, Administrador e Atendente.
- Estado padrão: fundo amarelo-claro, texto e contorno laranja, seguindo o botão Sair.
- Hover: fundo laranja e texto branco em todos os botões do menu superior.
- Corrigida a troca de senha do Administrador Geral: a senha definida no Painel Fidelizaê! passa a permanecer válida após logout, restart e novo deploy.
- `CLUBE_ADMIN_PASSWORD` passa a funcionar como credencial de bootstrap/recuperação de perfil e não sobrescreve mais a senha persistida de uma conta administrativa já existente.

## v142
- Painel Fidelizaê!: novo menu **Perfil** ao lado de Cadastrar.
- Perfil reúne Alterar senha, Cadastrar novo administrador, Administradores e Segurança / 2FA.
- Novo modal Administradores lista os Administradores Gerais cadastrados e permite editar ou remover acessos com proteção contra autoexclusão.

## v141
- Removida a área duplicada de “Configuração do programa” criada na v140.
- A área original de checklist “Configuração do programa” foi movida para depois de “Escanear QR”, inclusive no menu cinza.
- Adicionado espaçamento visual entre “Evolução da retenção” e “Dashboard financeiro”.
- Adicionados três gráficos lado a lado na Visão Geral: gênero, faixa etária e dispositivo (Android x iOS), alimentados por dados reais.
- Gênero passa a ser um campo opcional no cadastro/edição do cliente; idade é calculada pela data de nascimento; dispositivo é identificado no acesso ao cartão.
- Política de Privacidade atualizada para refletir gênero opcional e tipo de dispositivo.


## v139

- Perfil do Administrador da empresa ganha **Minha conta**, com dados cadastrados da empresa, responsável, contato, documento, plano, programa, integrações e histórico de Termos/Política.
- **Excluir conta** foi movido para o final de Minha conta, removendo a ação destrutiva do submenu principal de Perfil.
- Histórico de aceites exibe versões, data/hora, responsável, e-mail e IP quando registrados; aceites de cadastros por assinatura passam a ser vinculados à empresa provisionada.
- Menus com submenu passam a abrir diretamente ao passar o mouse em desktop, mantendo clique/toque como alternativa para dispositivos touch.
## v138

- Auditoria de regressão das funcionalidades acumuladas até a v137.
- Perfil > Editar empresa (Administrador PRO) agora inclui E-commerce junto de E-mail e WhatsApp, com plataforma, URL da loja, webhook e rotação segura do endereço.
- URLs de webhook de E-commerce usam o domínio oficial `https://app.fidelizae.com.br` como fallback quando `PUBLIC_BASE_URL` não estiver definida.
- Painel Fidelizaê! teve nomenclatura visual padronizada para “empresa” nos cadastros e edições.
- Texto de ciência da Política de Privacidade no cadastro do consumidor foi separado conceitualmente do consentimento opcional de marketing.
- Validações de regressão executadas em rotas, planos, integrações, documentos legais, criptografia, menus e responsividade.

## v137

- Painel Fidelizaê!: menu cinza corrigido para não ficar cortado sob o cabeçalho durante a rolagem.
- Fonte do menu cinza do Painel Fidelizaê! igualada à navegação do painel do Administrador.
- Empresas PRO agora podem editar E-mail (SMTP/Brevo) e WhatsApp em **Perfil > Editar empresa**.
- Senhas/tokens já configurados não são exibidos e são preservados quando os campos secretos ficam em branco.

## v136

- Programa de Fidelidade: Vale-presente e Cupons agora ficam lado a lado em telas amplas.
- Corrigido o alinhamento dos checkboxes de Webhooks e de Termos/Política no cadastro de empresa.
- Painel Fidelizaê!: novo menu cinza com Alterar senha e Cadastrar novo administrador, com endpoints protegidos no backend.
- As configurações de E-mail e WhatsApp ficaram visíveis no cadastro de nova empresa em qualquer plano; os disparos continuam sujeitos às permissões do plano contratado.

## v135

- CPF e celular dos clientes são armazenados criptografados no nível da aplicação usando Fernet, derivados de `CLUBE_ENCRYPTION_KEY`.
- Buscas por CPF/celular utilizam HMAC-SHA256 separado (`cpf_hash` / `phone_hash`), evitando a necessidade de texto puro no banco.
- A migração v135 converte automaticamente registros legados quando `CLUBE_ENCRYPTION_KEY` está configurada e limpa os campos antigos em texto puro.
- Destinatários de WhatsApp mantidos na fila de mensagens também passam a ser criptografados, com hash de pesquisa separado.
- A Política de Privacidade foi atualizada para refletir as medidas técnicas realmente implementadas.
- **Importante:** `CLUBE_ENCRYPTION_KEY` deve permanecer estável e protegida em produção; não altere a chave sem um processo controlado de rotação/migração.

## v134

- Painel Fidelizaê! com panorama visual consolidado das empresas, distribuição por plano, tipo de programa e cobertura de integrações.
- Botão Cadastrar com hover padronizado e contador de Alertas com espaçamento corrigido.

## v133

- Removido o botão redundante “Voltar ao painel” do modal Programa de Fidelidade. O modal continua sendo fechado pelo botão “Fechar”.

## v132

- Cupons movidos para **Programa de Fidelidade**, logo abaixo de **Vale-presente**.
- **Segurança / 2FA** passa a abrir em modal também no painel do administrador da empresa.
- Área **DIVULGAÇÃO** simplificada, removendo título e subtítulo redundantes.
- Navegação interna recebe **Central de Campanhas** e **Divulgação** após **Visão Geral**.

## v131

- Aceite obrigatório e auditável dos Termos de Uso e Política de Privacidade/LGPD no cadastro público e no cadastro administrativo de empresas.
- Nova página de Termos de Uso e links legais clicáveis.
- Área Divulgação redesenhada com link clicável, botão de cópia e QR Code de cadastro funcional.

## v130

- Inteligência de clientes com classificação automática em Novo, Ativo, Recorrente, VIP, Em risco, Inativo, Quase na recompensa e Recompensa disponível.
- Métricas individuais de frequência de compra, dias desde a última compra, ticket médio, faturamento, resgates e LTV estimado.
- Segmentação avançada integrada à lista de clientes e às campanhas de comunicação.
- Dashboard comercial ampliado com taxa de retorno, frequência média, LTV médio, clientes recuperados, receita atribuída às campanhas e visão financeira.
- Importação de clientes por CSV e XLSX com análise prévia, validação, identificação de duplicados, saldo inicial e confirmação antes da gravação.
- Onboarding guiado para administradores, com checklist baseado no estado real da conta.
- Central de Ajuda interna e documentação da API.
- API Fidelizaê! v1 com chaves individuais por empresa para clientes, compras e resgates.
- Webhooks de saída assinados, com eventos de cliente criado, compra, pontos/selos e recompensa resgatada, histórico de entregas e tentativas.
- Novas integrações ficam isoladas por empresa e as chaves/segredos são exibidos apenas no momento da criação.
- Todos os recursos anteriores da v129 foram preservados.

## v129

- Painel Fidelizaê!: Segurança / 2FA abre em modal interno.
- “Cadastrar nova empresa” e “Cadastrar novo usuário” ficam dentro do submenu “Cadastrar”.
- Tabelas de Empresas cadastradas e Usuários cadastrados são responsivas no mobile, sem rolagem horizontal.
- Atualizações da plataforma mostram as 5 atualizações mais recentes e permitem rolagem para as anteriores.
- Central de notificações mostra 3 notificações por vez e permite rolagem vertical para as demais.
- Painéis Administrador e Atendente: Programa de Fidelidade abre em modal interno.
- Tabela de Clientes cadastrados é responsiva no mobile e mantém todas as informações visíveis.
- “Editar empresa” aparece somente para administradores da empresa.
- Framing permanece protegido: apenas Segurança / 2FA e Programa de Fidelidade podem ser embutidos pelo próprio domínio.

## v124 — auditoria integral, correções de confiabilidade e isolamento

Revisão completa de backend, banco, rotas HTTP, permissões, frontend e fluxos críticos. Foram corrigidos dois defeitos reais que impediam o resgate de recompensa e o bloqueio/desbloqueio pelo gerente, removida a exposição pública da linha completa de campanhas, reforçado o isolamento da Central de Auditoria por `campaign_id`, restringida a edição/exclusão de clientes ao administrador do cliente, tornada a fila de mensagens segura para múltiplas instâncias, e tornada a expiração de pontos idempotente.

Também foram revisados os ciclos de cobrança anual e os valores em upgrade/downgrade, corrigido o e-mail de boas-vindas para refletir a modalidade contratada, eliminados helpers sem uso, reduzida a exposição de campos internos em APIs, removida a versão do Python do header HTTP, endurecido o segredo do QR dinâmico para falhar de forma segura em produção e atualizado o branding residual.

Validações executadas nesta versão: compilação Python completa, sintaxe de JavaScript externo e inline, IDs HTML duplicados, referências de endpoints do frontend, inicialização/migração de banco limpo, login real local, cadastro de cliente, crédito/resgate, bloqueio/desbloqueio, permissões de atendente, isolamento entre dois tenants, ausência de segredos na API pública, fila concorrente com dois workers e expiração idempotente de pontos.

## v123 — hardening de segurança
- Cookies de sessão com `HttpOnly`, `SameSite=Strict` e `Secure` automaticamente em produção.
- HSTS, Content-Security-Policy, X-Frame-Options, nosniff, Referrer-Policy e Permissions-Policy aplicados às respostas.
- Rate limit de autenticação/recuperação persistente no banco: funciona entre restarts e múltiplas instâncias; limites separados por IP e por conta.
- Login com proteção de timing, logs sem e-mail em claro e bloqueio progressivo de tentativas repetidas.
- Recuperação de senha deixa de revelar indiretamente a existência da conta quando o provedor de e-mail está indisponível.
- Senhas novas passam a usar PBKDF2-SHA256 com 600 mil iterações; hashes antigos continuam compatíveis. Política de novas senhas administrativas: mínimo 12 caracteres, maiúscula, minúscula e número.
- Troca/redefinição de senha revoga sessões antigas; a tela Segurança permite encerrar outras sessões manualmente.
- 2FA/TOTP opcional para o Administrador Geral e administradores de empresas, compatível com Google Authenticator, Microsoft Authenticator, 1Password e similares. O segredo TOTP é criptografado com `CLUBE_ENCRYPTION_KEY`.
- Fluxo 2FA usa desafio descartável de 5 minutos, limite de tentativas e código temporário de 6 dígitos.
- E-mails de boas-vindas de equipe não transportam nem armazenam mais a senha inicial na fila de mensagens.
- CSRF comparado em tempo constante e consultas críticas de empresa reforçadas com escopo `company_id`.
- IP de proxy só é aceito como origem quando o ambiente Railway é reconhecido ou `CLUBE_TRUST_PROXY=1`; o valor é validado como IP.
- `data.sqlite3` foi removido do pacote de deploy; produção continua usando PostgreSQL via `DATABASE_URL`.

### Variáveis de segurança recomendadas no Railway
```
APP_ENV=production
CLUBE_ENCRYPTION_KEY=<chave longa, aleatória e exclusiva>
CLUBE_SECURE_COOKIE=1
CLUBE_TRUST_PROXY=1
CLUBE_ALLOW_ADMIN_REPAIR=0
```

> Não troque `CLUBE_ENCRYPTION_KEY` sem um plano de migração: ela protege segredos de integrações e também o segredo do 2FA.

## v122
- Auditoria completa dos recursos por plano e proteção também no backend.
- Iniciante: Relatório/CSV Básico liberado com campos essenciais.
- Intermediário: Relatório/CSV Completo e cupons; sem recursos exclusivos PRO.
- PRO: NPS, Níveis VIP, aceleradores, vale-presente, automações, comunicação, área do cliente e relatórios avançados.
- Endpoints de recursos exclusivos agora retornam `plan_feature_not_available` quando o plano não permite acesso.
- Cartão do cliente só expõe NPS, nível VIP e cupons quando o plano contratado inclui cada recurso.



## v121
- Tabela de comparação da landing page: “Relatórios / CSV” do plano Intermediário agora aparece como **Completo** em vez de ✓.
- Auditoria funcional dos recursos anunciados nos planos realizada para identificar divergências entre a tabela comercial e as restrições efetivas do backend.
## v120 — cancelamento de renovação e encerramento seguro da conta

- Perfil > Plano e cobrança mostra modalidade, valor, próxima cobrança, compromisso e situação da renovação.
- Mensal: cancelar renovação interrompe a assinatura no Mercado Pago e preserva o acesso até o fim do período já pago.
- Anual à vista: cancelar renovação impede a próxima cobrança anual e preserva o acesso até o fim dos 12 meses já pagos.
- Anual parcelado: cancelar renovação mantém as parcelas do compromisso atual e impede um novo ciclo anual; após 12 pagamentos aprovados a assinatura remota é cancelada.
- Excluir conta cancela cobranças remotas antes de remover os acessos. Durante compromisso anual parcelado, a exclusão é bloqueada até o fim do contrato para não cobrar por uma conta já inacessível.
- Ao término de um período não renovado, o acesso é encerrado sem apagar o histórico financeiro/auditoria.

## v119 — contratação mensal e anual por plano

- A página de cadastro não pede mais para escolher novamente o plano clicado na landing page; o plano selecionado aparece como informação fixa.
- Intermediário: Mensal R$ 49,90/mês; Anual parcelado R$ 44,90/mês por 12 meses; Anual à vista R$ 515,00.
- PRO: Mensal R$ 99,90/mês; Anual parcelado R$ 89,90/mês por 12 meses; Anual à vista R$ 1.020,00.
- Planos anuais exibem claramente o compromisso de 12 meses e a política de não cancelamento antecipado/estorno, ressalvados direitos legais aplicáveis.
- O backend grava a modalidade de cobrança, valor contratado e término do compromisso anual.
- Cobrança anual à vista usa recorrência de 12 meses no Mercado Pago; anual parcelado mantém cobrança mensal com preço reduzido e compromisso anual registrado.
- Alteração de plano pelo painel é bloqueada enquanto houver compromisso anual vigente.
- Mantidas as melhorias de segurança/Device ID e diagnóstico do Mercado Pago da v118.

**Versão atual:** v161


## Novidades da v117

- Landing page atualizada com as novas imagens reais fornecidas para o celular do hero e para a seção de experiência; os ajustes mobile da v116 foram preservados.

- Painel mobile reorganizado: botões de ação do administrador passam a uma grade de duas colunas com dimensões consistentes.
- Menu interno cinza (Escanear QR, Clientes cadastrados, Aniversariantes, Visão Geral e Comunicação) oculto apenas em telas pequenas.
- Automações redesenhadas no mobile como cards verticais: título, Canal/Ativa lado a lado, mensagem em largura total e botão Salvar dentro do card.
- Layout desktop das automações também recebeu colunas mais estáveis para evitar que controles e mensagens disputem espaço.

## Novidades da v115

- **Diagnóstico seguro de Assinaturas do Mercado Pago:** ao criar uma assinatura, o servidor registra `MP_CREATE_RESPONSE` e consulta imediatamente o recurso para registrar `MP_CREATE_STATE`.
- Os logs mostram apenas metadados necessários ao diagnóstico: `id`, `status`, motivo, referência externa, presença de `init_point`/pagador/cartão, `payment_method_id`, recorrência e datas. **E-mail do pagador, Access Token, dados do cartão e URL completa do checkout não são registrados.**
- A consulta de status da tela de pagamento pendente também registra `MP_STATUS_POLL`, permitindo comparar a evolução do mesmo `preapproval`.
- A leitura diagnóstica adicional do Mercado Pago é *best effort*: se falhar, o checkout continua funcionando normalmente.

## Novidades da v114

- Exclusão de conta agora libera os e-mails dos usuários encerrados para novo cadastro, preservando referências históricas de auditoria.

- Domínios oficiais de produção consolidados: `https://www.fidelizae.com.br` para o site institucional e `https://app.fidelizae.com.br` para a plataforma.
- Removidos os fallbacks públicos legados que apontavam para `clube-fidelidade-production.up.railway.app`.
- Recuperação de senha, retorno do Mercado Pago, e-mails de boas-vindas, links de acesso e URLs públicas de Wallet passam a usar `https://app.fidelizae.com.br` como fallback de produção.
- Os links **Acesso da equipe** e **Acessar plataforma** do site institucional agora levam explicitamente a `https://app.fidelizae.com.br/login`.
- Integrações que usam `PUBLIC_BASE_URL`/`CLUBE_PUBLIC_URL` (incluindo callback da Meta, webhook de e-commerce e URLs públicas de Wallet) permanecem configuráveis por variável de ambiente.

### Variáveis recomendadas no Railway para produção

```
PUBLIC_BASE_URL=https://app.fidelizae.com.br
CLUBE_PUBLIC_URL=https://app.fidelizae.com.br
CLUBE_LOGIN_URL=https://app.fidelizae.com.br/login
```

O domínio gerado `*.up.railway.app` continua válido apenas como endereço técnico do serviço e não é mais usado como URL pública padrão pelo código.

## Novidades da v112

- Página inicial: removido o botão “Ver como funciona” do hero.
- Texto atualizado para “Mais que um cartão fidelidade.”
- Título de planos quebrado em duas linhas: “Escolha o plano ideal” / “para o seu negócio.”
- A composição do celular criada em HTML/CSS na seção principal foi substituída pela imagem `static/iphone.png` enviada pelo usuário.
- Os dois cards flutuantes do hero foram preservados nas mesmas posições e continuam sobrepostos ao celular.
- Mantida a responsividade do hero em desktop, tablet e mobile.
- Mantidas todas as funcionalidades da v109.

## Novidades da v109

- Modal **Alterar plano** destaca o plano contratado como indisponível no seletor e sugere automaticamente o plano imediatamente superior quando houver upgrade disponível.
- Empresas PRO passam a oferecer uma **Área PRO do usuário** no cartão, com status, data de entrada, programa, código, saldo/progresso, recompensas, nível, histórico e atalhos de privacidade/recompensas.
- Mantidas as melhorias da v108.

## Novidades da v108

- Corrigidos os itens **Editar empresa** e **Excluir conta** no menu Perfil do administrador do cliente: os modais agora abrem, carregam os dados da empresa e executam as ações corretamente.
- A edição da empresa respeita o plano contratado; por exemplo, o plano Iniciante não permite selecionar Pontos.
- No Painel Fidelizaê!, a ação visível passou de **Arquivar** para **Excluir empresa** e, após a exclusão, a empresa sai da lista ativa.
- Os conteúdos de **Detalhes** e **Editar** no Painel Fidelizaê! permanecem em sobreposição modal, sem deslocar a página.

- **Produção protegida contra pagador de teste:** `MERCADOPAGO_TEST_PAYER_EMAIL` só é usado quando `APP_ENV` estiver em ambiente de teste/desenvolvimento. Em `production`, o Mercado Pago recebe sempre o e-mail real informado pelo cliente no cadastro.
- Isso permite manter a variável de teste cadastrada sem risco de ela substituir o pagador de uma assinatura real; ainda assim, recomenda-se removê-la do Railway ao entrar em produção.

- Corrigido o retorno assíncrono do Mercado Pago: assinaturas que retornam inicialmente como `pending` agora permanecem em uma tela de confirmação e são verificadas automaticamente até a autorização.
- Os dados do cadastro permanecem preservados durante a confirmação; o usuário não volta mais para um formulário vazio enquanto o pagamento está pendente.
- Adicionado endpoint seguro de consulta do status que valida `external_reference` e a assinatura pendente antes de provisionar a conta.
- Ao receber `authorized`, o cadastro é provisionado e o usuário é redirecionado automaticamente para o login.

- Adicionado diagnóstico seguro do retorno de assinaturas do Mercado Pago (`MP_RETURN`) para registrar status, referência e datas sem expor credenciais.
- Mantida a correção da rota dedicada `/signup/payment-return` introduzida na v102.
- O retorno aprovado agora valida a assinatura diretamente na API, conclui o cadastro pendente e redireciona para o login.
- Mantida compatibilidade com URLs de retorno geradas pela v101.


- Testes de Assinaturas do Mercado Pago agora podem usar um `payer_email` de teste separado do e-mail cadastral, via `MERCADOPAGO_TEST_PAYER_EMAIL`.
- Em produção, sem essa variável, o e-mail real do cadastro continua sendo enviado normalmente ao Mercado Pago.

- Fluxo de assinatura do Mercado Pago endurecido para upgrades/downgrades sem antecipar troca de recursos.
- Upgrades pagos agora criam uma nova assinatura pendente e só liberam o novo plano após autorização confirmada via webhook.
- Downgrades permanecem no plano atual até o fim do ciclo já pago; a mudança só é aplicada no vencimento correto.
- Tratamento de estados `pending`, `authorized`, `paused` e `cancelled` normalizado no painel.
- Suporte opcional à validação criptográfica `x-signature` dos Webhooks via `MERCADOPAGO_WEBHOOK_SECRET`.
- Limpeza automática de assinatura anterior após upgrade para reduzir risco de cobrança duplicada.

- Planos Iniciante, Intermediário e PRO com limites e recursos por categoria.
- Seletor de plano no cadastro/edição de empresas e alteração de plano no Perfil do administrador do cliente.
- Landing page com cards e tabela comparativa dos três planos.
- Limites de 50 clientes/1 atendente no Iniciante e 5 atendentes no Intermediário.
- Recursos avançados e comunicação visíveis apenas no PRO.


- Botões **Escanear QR** e **Parar câmera** mantêm a altura padrão mesmo quando o painel lateral cresce.
- Central de auditoria traduz detalhes do teste de WhatsApp e oculta `message_id`/códigos técnicos da interface.
- Nomes das automações padronizados em português.
- **Falta 1 selo** (`one_to_reward`) aparece e executa somente em programas por selos.
- Programa de Fidelidade reorganizado: **Níveis VIP**, **Acelerador de pontos** e **Vale-presente** lado a lado; **Configurações avançadas de pontos** ao lado de **NPS / Satisfação**.
- Preferências de marketing de e-mail e WhatsApp vêm pré-selecionadas no cadastro do cartão, permanecendo opcionais e podendo ser desmarcadas pelo cliente.

## Novidades da v96

- **Modo de teste Meta para WhatsApp:** quando a empresa ainda não conectou sua própria conta, o botão **Enviar teste** pode usar exclusivamente o número de teste da Meta configurado no Railway.
- O modo de teste aceita somente clientes com consentimento de WhatsApp **e** cujo telefone esteja na allowlist `META_TEST_WHATSAPP_RECIPIENTS`.
- As credenciais de teste nunca são usadas por campanhas ou automações de produção; servem somente ao endpoint de teste de templates.
- Se não houver integração de produção nem modo de teste configurado, o envio fica indisponível com explicação clara na interface.

### Variáveis opcionais para o Modo de teste Meta

```
META_TEST_WHATSAPP_PHONE_NUMBER_ID=<Phone Number ID do número de teste da Meta>
META_TEST_WHATSAPP_ACCESS_TOKEN=<token de desenvolvimento da Meta>
META_TEST_WHATSAPP_WABA_ID=<WABA ID de teste, opcional>
META_TEST_WHATSAPP_RECIPIENTS=5521999999999,5511999999999
META_GRAPH_VERSION=v24.0
```

`META_TEST_WHATSAPP_RECIPIENTS` deve conter somente números previamente adicionados/validados como destinatários de teste na Meta, com DDI e DDD, separados por vírgula.

- Teste de templates unificado por canal: E-mail, WhatsApp ou ambos.
- A seleção de clientes respeita o consentimento específico de cada canal.
- Em templates E-mail + WhatsApp, o modo “Ambos” lista somente clientes que autorizaram os dois canais.
- O backend revalida consentimento antes de cada envio de teste.
- Envio de teste por e-mail utiliza a integração de e-mail configurada para a empresa; WhatsApp continua usando a Cloud API oficial.

- O **Enviar teste** dos templates WhatsApp agora permite selecionar somente clientes cadastrados que deram consentimento para comunicação pelo WhatsApp; o backend revalida o consentimento antes de cada envio.
- Corrigida a criação/carregamento das automações para bancos PostgreSQL antigos que não possuam a constraint UNIQUE esperada em `automation_rules`.
- Logs e mensagens de erro do teste de WhatsApp aprimorados para facilitar a validação exigida pela Meta.

## Novidades da v92

- Tratamento específico para bloqueio de IP da Brevo (`401/403` com IP não reconhecido).
- Logs do Railway agora exibem `BREVO_IP_BLOCKED` e o IP recusado, sem expor API Key ou dados sensíveis.
- O formulário público deixa de mostrar erro genérico nesse cenário e informa que o serviço de e-mail bloqueou temporariamente a conexão do servidor.
- O diagnóstico orienta aguardar a autorização automática da Brevo ou revisar **Segurança > IPs autorizados**, sem exigir alteração de código.

## Novidades da v91

- Corrigida a rotina de automações no PostgreSQL: inserções idempotentes agora usam `ON CONFLICT DO NOTHING`, evitando que violações de unicidade deixem a transação em estado abortado (`InFailedSqlTransaction`).
- Corrigido o mesmo padrão no registro de destinatários de campanhas.
- Formulário comercial passa a registrar diagnóstico seguro da configuração/envio de e-mail nos logs, sem expor credenciais.
- O `Reply-To` específico do formulário agora tem prioridade sobre o `BREVO_REPLY_TO` global, permitindo responder diretamente ao lead.

## Novidades da v90

- Landing page: todos os antigos links de e-mail agora levam ao formulário comercial após o FAQ.
- Formulário envia nome, empresa, e-mail, WhatsApp/celular, segmento, interesse e mensagem para `gustavo@agenciataboo.com.br`, usando a configuração global de e-mail da plataforma.
- Consentimento obrigatório, validação de e-mail e honeypot anti-spam.

## Novidades da v89

- Corrigida a inicialização no PostgreSQL/Railway quando a migração v87 já estava registrada.
- O registro de `schema_migrations` agora é idempotente com `ON CONFLICT DO NOTHING` no PostgreSQL e `INSERT OR IGNORE` no SQLite, evitando deixar a transação abortada.
- Mantidas integralmente as funcionalidades e ajustes da v88.

## Novidades da v88

- Página inicial refinada conforme a nova redação e organização visual.
- Central de auditoria com operações em português e botão **Exportar CSV**.
- Menu operacional do painel da empresa corrigido para navegação horizontal responsiva no mobile.
- Cartão do cliente com **CLUBE DE FIDELIDADE** em branco e últimas movimentações apresentadas em português.

## Novidades da v83

- Histórico do cliente evoluído para ficha 360º, preservando a linha do tempo e adicionando segmento, progresso, saldo, datas, resgates, cupons e comunicações.
- Identidade visual Fidelizaê! padronizada nos painéis e componentes com #e27a00, #ffb347 e #f2f2f2.
- Pré-visualização do cartão em tempo real nos formulários de cadastro e edição da empresa.
- Central de alertas inteligente com falhas de envio, integrações pendentes, empresas sem movimentação, clientes em risco, clientes quase na recompensa e filas de comunicação.

## Novidades da v82

- Corrigido definitivamente o servidor de arquivos estáticos para servir PNG/JPEG/WebP/GIF/ICO/fontes como binário, permitindo o carregamento correto da logo Fidelizaê!.

## Novidades da v80

- Página inicial atualizada para a identidade visual oficial do Fidelizaê!, usando #e27a00, #ffb347 e #f2f2f2.
- Header e rodapé passaram a utilizar a imagem oficial `logo-fidelizae.png`.

## Novidades da v79

- Painel geral renomeado para **Painel Fidelizaê!**.
- **Cadastrar nova empresa** e **Cadastrar novo usuário** agora ficam no menu superior, ao lado de **Alertas**, e abrem seus formulários em modais.
- Os novos modais fecham pelo botão **Fechar**, pela tecla **Esc** e ao clicar fora da janela.
- A **Central de notificações** é carregada automaticamente ao entrar no painel, sem exigir o clique em **Atualizar**.
- Identificação do acesso geral simplificada para **Administrador Geral**.
- Todos os recursos e dados da v78 foram preservados.

## Novidades da v76

- Marca da plataforma atualizada para **Fidelizaê!** com o slogan **“Fidelidade que marca pontos.”**
- Dashboard de retenção com visitas, clientes que retornaram, clientes recuperados, taxa de retorno, resumo semanal e evolução mensal.
- Segmentação automática: novos, ativos, VIP, em risco, inativos 60/90 dias, quase na recompensa e recompensa disponível.
- Lista de clientes exibe segmento, nível, última atividade e quanto falta para a próxima recompensa.
- Central de campanhas com público segmentado, WhatsApp/E-mail, fila de envio e medição de conversão por retorno após campanha.
- Automações ampliadas com recuperação em 60 dias, além de aniversário, risco de inatividade, quase recompensa e recompensa liberada.
- Cupons com percentual, valor fixo, pontos bônus ou selos bônus, controle de uso e aplicação no atendimento.
- Kit de divulgação com QR Code, link do programa e geração de cartaz PNG personalizado.
- Onboarding e resumo operacional aproveitam os dados reais do programa.
- Recursos existentes de níveis, Wallets, recompensas, multiunidade, e-commerce, auditoria e integrações foram preservados.
- **Sistema de indicação não foi exposto nem implementado na experiência**, conforme decisão de produto.


## Novidades da v75

- Corrigido o endpoint `/api/manager/meta-config`, usado pelo botão **Conectar WhatsApp** no Painel Taboo.
- Criada a rota pública de callback da Meta em `/auth/meta/callback`.
- O painel agora mostra a **URI exata de redirecionamento OAuth** para copiar e cadastrar no Meta for Developers.
- O fluxo de Embedded Signup aceita tanto o retorno direto do SDK quanto o retorno pela URI de callback, preservando a empresa que está sendo configurada.
- A conexão continua isolada por empresa e grava WABA ID, Phone Number ID e token criptografado somente após a autorização oficial.
- Variáveis necessárias no Railway: `META_APP_ID`, `META_APP_SECRET`, `META_CONFIG_ID`, `PUBLIC_BASE_URL` e, opcionalmente, `META_GRAPH_VERSION`.

## Novidades da v74

- Cadastro e edição da empresa agora incluem **plataforma de e-commerce** (WooCommerce, Nuvemshop, Shopify, Tray, VTEX, Loja Integrada ou API personalizada).
- A compra online usa **a mesma regra de fidelidade já cadastrada**: em pontos, a mesma conversão por valor; em selos, 1 compra paga = 1 selo, respeitando a meta/recompensa existente.
- Cada empresa com e-commerce recebe um **webhook exclusivo e secreto** para eventos de pedidos.
- Pedidos pagos creditam automaticamente; cancelamentos/reembolsos estornam a recompensa; eventos repetidos são idempotentes e não duplicam pontos/selos.
- O cliente é localizado no mesmo programa por CPF, e-mail ou celular. Se ainda não possuir cartão, o pedido fica registrado sem crédito e retorna `customer_not_found`.
- A auditoria registra crédito e estorno de e-commerce, e o painel mostra o status da integração.

### Gestão de unidades funcional

- Unidades agora podem ser vinculadas aos atendentes no cadastro e na edição da equipe.
- Cada operação registra a unidade do atendente no momento em que acontece.
- A Gestão avançada mostra atendentes e quantidade de operações por unidade.
- O relatório comercial separa operações por unidade e por atendente.
- A Central de auditoria ganhou filtro e coluna de unidade.
- Corrigida a falha visual da auditoria causada pelo formatador de data não exposto no escopo da página.
- O histórico de unidade fica preservado mesmo se o atendente for transferido para outra filial.


- Nova página inicial comercial, responsiva e focada em apresentação e conversão.
- Hero com demonstração visual do cartão digital e CTAs para empresas e participantes.
- Novas seções: como funciona, recursos, experiência do cliente, segmentos, painel de gestão, FAQ e CTA final.
- Navegação responsiva e identidade visual premium aplicada sem alterar as telas internas da plataforma.
- Gestão avançada movida para modal acessível pelo menu superior do administrador.
- Central de auditoria agora usa listas de usuários e operações cadastradas para seleção dos filtros.

- Consolidação das melhorias de produto: segmentação de campanhas, multiunidade, permissões granulares, auditoria filtrável e relatórios comerciais.
- Dashboard com série de atividade dos últimos 30 dias e gestão avançada no painel do administrador.
- Removida a caixa redundante “Atendimento rápido e simples” dos painéis de administrador e atendente.
- Navegação superior interna agora faz rolagem suave até as seções “Visão geral”, “Atender cliente”, “Clientes”, “Aniversariantes” e “Comunicação”.

- Consolidação do **perfil 360 do cliente**: histórico em modal agora inclui contato, CPF, nascimento, consentimento de marketing, total de movimentações, resgates e última atividade, além da timeline operacional.
- **Catálogo de recompensas avançado**: estoque ilimitado ou controlado, período de disponibilidade e baixa automática de estoque no resgate.
- Resgates por pontos passam a ter registro dedicado para relatórios e auditoria comercial.
- Estrutura de dados preparada para **multiunidade**, permissões granulares e observações internas de clientes, preservando compatibilidade com empresas existentes.
- Painel do administrador ganhou **checklist de configuração** e mantém os indicadores executivos de clientes, retorno, conclusão, inatividade, aniversariantes e comunicação.
- Fluxo de pontos continua baseado no **valor da compra**, com cálculo automático conforme a regra da empresa e confirmação do novo saldo.
- Mantidos automações, níveis VIP, aceleradores, NPS, vale-presente, exportações, auditoria, Wallets e comunicação segmentada já consolidados nas versões anteriores.
- Versão visual e backend sincronizados em **v81**.


- Vale-presente: botão Excluir para administradores, com remoção segura por empresa e auditoria.
- Vale-presente: avisos de consulta e utilização agora aparecem em modal (ex.: “Vale não encontrado!”).

- Vale-presente: geração corrigida no painel do Programa de Fidelidade com token CSRF, validação do valor, estado de carregamento e mensagem de sucesso/erro.
- Clientes cadastrados: coluna e saldo agora seguem automaticamente o tipo de fidelidade da empresa (Pontos ou Selos).

- **Histórico do cliente em modal:** o botão “HISTÓRICO” da lista de clientes agora abre uma janela centralizada, sem deslocar ou substituir a área de atendimento no topo da página.
- O modal exibe nome do cliente, saldo atual, movimentações em timeline, data/hora, atendente responsável, saldo anterior → novo saldo, observações e destaque visual para entradas e saídas.
- Fechamento pelo botão ×, clique no fundo ou tecla `Esc`; em telas pequenas o modal se adapta ao formato mobile e mantém scroll somente no conteúdo do histórico.
- Redesign premium dos painéis de administrador da empresa e atendente mantido: navegação rápida, atendimento em destaque, cards e tabelas mais limpos, indicadores reorganizados, busca e ações rápidas, responsividade para tablet/mobile e hierarquia visual unificada.
- Cartão web: instrução abaixo do QR permanece dinâmica conforme programa por selos ou pontos.

## Novidades da v62
- Google Wallet: lista geral corrigida para exibir **nome da empresa** na primeira linha e **saldo de pontos/selos** na segunda.
- O nome do cliente continua disponível nos detalhes do passe, sem ser usado como título da listagem.


- Google Wallet: redirecionamento para `pay.google.com` sem chamadas síncronas de PATCH/CREATE antes do HTTP 302, reduzindo a espera após o clique.
- Google Wallet: nova `LoyaltyClass` e novo `LoyaltyObject` na revisão **v62**, impedindo reaproveitamento do layout antigo.
- Programas por pontos: removido o bloco textual grande de recompensas do passe; **“Catálogo de recompensas”** fica no módulo nativo de links como CTA clicável para `/rewards?id=<cartão>`.
- Logo: endpoint e IDs versionados em **v62** para evitar cache da revisão anterior.
- Versão sincronizada para **v62** em servidor, páginas, painel e README.

## Novidades da v59

- Google Wallet: `programLogo` passa a usar uma **URL física versionada** (`/api/wallet/logo-v59/...`) em vez de depender de query string, evitando que a Wallet reaproveite a imagem antiga em cache.
- Logo processada ocupa 100% da área útil do PNG depois da remoção do fundo/margens, mantendo proporção e transparência.
- Programas por pontos: o texto clicável do módulo de links agora é **“Catálogo de recompensas”** e abre diretamente o catálogo.
- O texto não clicável de catálogo foi removido da face principal do cartão por pontos para não simular um link onde o Google não permite interação.
- Versão sincronizada para **v59** no servidor, painel, páginas com `{{VERSION}}` e README.

## Novidades da v58

- Versão da aplicação sincronizada para **v58** no servidor, cartão do usuário, diagnóstico, painel e README.
- Google Wallet: processamento de logo refeito para remover fundos claros/uniformes conectados às bordas e ampliar efetivamente a marca dentro do círculo do `programLogo`.
- Google Wallet: URL da logo usa revisão `r58`, evitando reutilização do asset processado por versões anteriores.
- Cartões por pontos no Google Wallet agora incluem o link **Ver catálogo de recompensas**, apontando diretamente para `/rewards?id=<cartão>`.
- Mantido também o link **Abrir cartão digital**.

## Atualização v56

- Google Wallet: recorte mais robusto de fundos brancos/uniformes ao redor da logo, inclusive bordas com antialiasing/compressão.
- Google Wallet: logo ampliada para ocupar até 94% do canvas processado, mantendo pequena margem de segurança.
- Versão da aplicação atualizada para v56.

## Atualização v55

- Google Wallet: logo do cliente agora tem margens vazias removidas automaticamente e ocupa até 88% da área útil, ficando visualmente maior no círculo do cartão.

- Google Wallet: classes de fidelidade específicas por cliente, permitindo logo e cor independentes.
- `programLogo`: URL pública da logo passa a usar `CLUBE_PUBLIC_URL`, `PUBLIC_BASE_URL` ou, automaticamente no Railway, `RAILWAY_PUBLIC_DOMAIN`.
- Corrige o erro `LoyaltyClass cannot be created without a program logo` quando a URL pública não estava configurada manualmente.
- Mantém a imagem da logo em endpoint PNG dedicado e com cache-busting.

## Histórico de versões

- **v141:** Corrigida a ordem do painel: removida a configuração duplicada, movido o checklist original para depois do QR e adicionados gráficos de gênero, idade e Android x iOS.

**v88**
- Implementação das 23 melhorias aprovadas, com cashback reservado para evolução futura e sem alteração do consentimento de comunicação.

**v79**
- Gestão avançada reorganizada, auditoria em modal separado e fechamento externo dos modais.

**v76**
- Retenção, segmentos, campanhas, cupons, resumo semanal, kit de divulgação e marca Fidelizaê!.

**v75**
- Callback OAuth oficial da Meta e fluxo Conectar WhatsApp corrigido e preparado para Embedded Signup.

**v74**
- Integração de e-commerce por empresa com webhook exclusivo, crédito automático de selos/pontos pela regra existente, idempotência e estorno de cancelamentos/reembolsos.

**v69**
- Remoção do hero redundante dos painéis de operação/administração e navegação com scroll suave entre seções.

**v68**

## v88
Permissões efetivas, validade real de pontos (1–12 meses; padrão 6), aceleradores aplicados, NPS no cartão, observações internas, alertas acionáveis, ciclo de unidades, atribuição financeira de campanhas, compras em selos/pontos, dashboard financeiro, adaptadores de e-commerce, área pessoal do cartão, cupons com desconto calculado, vale-presente enriquecido, remoção do recurso de indicação, modularização inicial, testes/migrações formais, recuperação de senha por token e rate limiting. Cashback permanece reservado para evolução futura.


## v100 — Assinaturas com troca segura de plano
- Upgrades só entram em vigor após autorização da nova assinatura pelo Mercado Pago.
- Downgrades ficam agendados até o fim do ciclo corrente; o plano atual continua ativo até então.
- Webhook não antecipa downgrade ao receber um simples evento `authorized`.
- Estados financeiros normalizados e reconciliação de plano no carregamento da sessão.
- Nova variável opcional `MERCADOPAGO_WEBHOOK_SECRET` para validação HMAC do Webhook.
- Variável obrigatória para cobranças reais continua sendo `MERCADOPAGO_ACCESS_TOKEN`.

## v99 — Assinaturas self-service
- Cadastro público direto pelos cards de planos.
- Plano Iniciante ativa sem pagamento; planos pagos usam Mercado Pago Assinaturas.
- Webhook confirma a assinatura consultando a API do Mercado Pago antes de liberar acesso.
- E-mail automático de ativação e credenciais.
- Upgrade/downgrade integrado ao Perfil; downgrade fica agendado para o fim do ciclo.
- Variável obrigatória: `MERCADOPAGO_ACCESS_TOKEN`. Configure webhook em `/api/webhooks/mercadopago`.


## v129 — Painéis, modais e responsividade

- Painel Fidelizaê!: Segurança / 2FA abre em modal interno.
- Cadastros de empresa e usuário agrupados no submenu “Cadastrar”.
- Tabelas de empresas, usuários e clientes viram cartões responsivos no mobile, sem rolagem horizontal.
- Atualizações da plataforma e Central de notificações têm altura limitada com rolagem vertical.
- Painéis Administrador/Atendente: Programa de Fidelidade abre em modal interno.
- “Editar empresa” fica visível somente para administrador do cliente.
- Segurança de framing preservada: apenas `/security` e `/loyalty360` podem ser embutidas pelo mesmo domínio; demais páginas continuam com bloqueio de framing.

## v128 — Refinamento de ícones da landing
- Bootstrap Icons oficiais aplicados em Acesse o programa (coin), Registre cada compra e QR Code (qr-code-scan), Relacionamento (whatsapp) e Beleza e bem-estar (scissors).
- Mantido o padrão circular e a cor visual unificada da landing page.


## v147 — fechamento técnico
- Recuperação de senha também para Administrador Geral (`manager`).
- HSTS agora é opt-in com `CLUBE_HSTS_ENABLED=1`; por padrão o aplicativo não envia HSTS.
- E-commerce identificado corretamente como integração via webhook, sem prometer OAuth/conexão nativa em um clique.
- Backup exige reautenticação com a senha atual do Administrador Geral, POST + CSRF, rate limit, `Cache-Control: no-store`, auditoria e checksum SHA-256.
- Backup exporta as tabelas persistentes da plataforma. Sessões, desafios 2FA, tokens de reset e rate limits são excluídos por serem transitórios.
- `tools/backup_restore.py` valida checksum/contagens e realiza ensaio de restauração em SQLite isolado com `integrity_check` e `foreign_key_check`.
- Termos e Política de Privacidade atualizados para versão 1.1 e dados jurídicos centralizados por ambiente.

### Dados jurídicos
Dados jurídicos padrão configurados: `CLUBE_LEGAL_COMPANY_NAME=Agência Taboo`, CNPJ `10.995.977/0001-40`, `CLUBE_LEGAL_EMAIL=contato@fidelizae.com.br` e `CLUBE_LEGAL_LGPD_EMAIL=contato@fidelizae.com.br`. O endereço empresarial não é exibido nos documentos jurídicos da plataforma. `CLUBE_LEGAL_CNPJ` continua disponível como sobrescrita opcional no Railway.

### Backup e restauração
O backup contém dados pessoais, hashes de senha e segredos de integração criptografados. Preserve separadamente a mesma `CLUBE_ENCRYPTION_KEY`. Validação: `python tools/backup_restore.py validate backup.json`. Ensaio: `python tools/backup_restore.py restore-sqlite backup.json /tmp/fidelizae-restore.sqlite3`.
