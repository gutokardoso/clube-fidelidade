# Fidelizaê! v110

**Versão atual:** v110

## Novidades da v110

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
