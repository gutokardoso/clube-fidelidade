# Clube Fidelidade v22

## Alterações da v22

- Cadastro do cliente final com 5 campos obrigatórios: nome, e-mail, celular, data de nascimento e CPF.
- Validação de formato de e-mail, celular brasileiro com DDD e CPF com dígitos verificadores.
- Removido o texto de regra/recompensa da página de cadastro.
- Área do atendente com seleção de um cliente ou todos, campo de mensagem e botão verde **ENVIAR** para WhatsApp.
- Quando a WhatsApp Cloud API está configurada, o sistema tenta enviar diretamente; sem credenciais, prepara links `wa.me` individuais para envio manual.
- Área de aniversariantes do mês baseada na data de nascimento cadastrada.
- Atendente continua restrito aos consumidores do cliente/área ao qual está vinculado.

## Alterações da v17

- Removidas da tela inicial as caixas Cliente demo, Perfis, Antifraude e Wallet.
- CTA principal alterado para “Seja um cliente fidelidade”.
- Título “Fidelidade digital, sem aplicativo.” quebrado em duas linhas.
- Texto de apresentação atualizado com destaque para selos e WhatsApp.


## Alterações da v16
- Removidas as quatro caixas de métricas do topo do Painel Taboo.
- Adicionado botão verde **Editar** antes de **Excluir** em cada cliente.
- A edição permite alterar nome, código, meta, recompensa, ícone/modo logo, logo e regras antifraude.
- Se nenhuma nova logo for selecionada, a logo atual é preservada.


Plataforma de fidelidade multi-cliente para operação pela Taboo.

## Alterações da v15

- Contato do consumidor (e-mail ou celular) obrigatório no cadastro.
- A interface administrativa passa a chamar cada campanha/área de **Cliente**.
- O gerente é o acesso geral exclusivo da Taboo.
- Novos usuários criados pelo painel são atendentes e precisam ser vinculados obrigatoriamente a um Cliente.
- Atendentes só podem consultar, pontuar e resgatar cartões do Cliente ao qual estão vinculados.
- A área do atendente mostra o nome do Cliente e inclui **Auditoria de operações** de toda aquela área.
- A auditoria geral foi removida do painel Taboo e passou a existir dentro da área de cada Cliente.
- Clientes com atendentes vinculados não podem ser excluídos até que esses atendentes sejam removidos.
- Mantidos QR/código manual, antifraude, logos por Cliente, exclusão de Clientes/atendentes e PostgreSQL/Railway.

## Railway

O projeto continua usando `DATABASE_URL` para PostgreSQL e as variáveis `CLUBE_ADMIN_*` para o gerente Taboo.

## Alterações v15
- Corrigido o cartão para receber e exibir a `logo_image` cadastrada do cliente no lugar do nome do estabelecimento.
- Adicionado botão **Remover selo** na área do cliente, com auditoria e reversão de recompensa quando a remoção desfaz o selo que completou a meta.
- Painel Taboo agora exibe, por cliente, a quantidade de **Cartões** gerados e o total líquido de **Selos**.


## Novidades v22
- Ao criar um atendente, o sistema tenta enviar automaticamente um e-mail de acesso via SMTP com link, e-mail e senha inicial. Configure `CLUBE_SMTP_HOST`, `CLUBE_SMTP_PORT`, `CLUBE_SMTP_USER`, `CLUBE_SMTP_PASSWORD`, `CLUBE_SMTP_FROM` e `CLUBE_SMTP_SECURITY` no Railway.
- A área do atendente agora lista todos os clientes finais vinculados à sua área e permite editar os cinco dados cadastrais ou remover o cartão/cliente daquela área.
- `CLUBE_LOGIN_URL` permite alterar o link enviado no e-mail; o padrão é `https://clube-fidelidade-production.up.railway.app/login`.


## v22 — WhatsApp Embedded Signup
Configure META_APP_ID, META_APP_SECRET e META_CONFIG_ID uma única vez no Railway. Depois use Editar cliente > WhatsApp > Conectar automaticamente pela Meta > CONECTAR WHATSAPP.
