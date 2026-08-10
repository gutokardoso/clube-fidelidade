# Clube Fidelidade v11

Plataforma de fidelidade multi-cliente para operação pela Taboo.

## Alterações da v11

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
