# Clube Fidelidade v42

Versão multi-cliente com antifraude, QR temporário, fila de mensagens, automações, dashboard, LGPD, perfis Taboo/Administrador do cliente/Atendente e integração configurável com Apple Wallet e Google Wallet.

## Novidades da v42
- Apple Wallet e Google Wallet: geração real de passe quando as credenciais oficiais estiverem configuradas; atualizações são disparadas após selo, remoção e resgate.
- QR temporário: o QR exibido no cartão web é renovado automaticamente e expira. O código textual continua disponível para contingência manual.
- Antifraude: remoção de selo exige motivo, registrado no histórico e na auditoria.
- Mensageria: e-mail e WhatsApp entram em fila, com novas tentativas, status e reprocessamento pelo painel.
- Dashboard por cliente: cartões ativos, novos cadastros, selos, resgates, conclusão e clientes inativos.
- Automações: aniversário, 30 dias sem atividade, falta 1 selo e recompensa disponível, respeitando consentimento de marketing.
- Perfis: Taboo (global), Administrador do cliente e Atendente.
- LGPD: aceite obrigatório da política, opt-ins separados para marketing, exportação e exclusão de dados.
- Confiabilidade: versão centralizada no backend, healthcheck, diagnóstico no Painel Taboo e validação automática no GitHub Actions.

## Variáveis essenciais
`DATABASE_URL`, `CLUBE_ADMIN_EMAIL`, `CLUBE_ADMIN_PASSWORD`, `CLUBE_ENCRYPTION_KEY`, `CLUBE_QR_SECRET` e `CLUBE_PUBLIC_URL`.

## Apple Wallet
Configure `APPLE_PASS_TYPE_ID`, `APPLE_TEAM_ID` e os materiais de assinatura. No Railway, você pode usar arquivos (`APPLE_CERT_PATH`, `APPLE_KEY_PATH`, `APPLE_WWDR_CERT_PATH`) ou o PEM diretamente (`APPLE_CERT_PEM`, `APPLE_KEY_PEM`, `APPLE_WWDR_CERT_PEM`). Se a chave tiver senha, use `APPLE_KEY_PASSWORD`.

## Google Wallet
Configure `GOOGLE_WALLET_ISSUER_ID`, `GOOGLE_SERVICE_ACCOUNT_EMAIL` e `GOOGLE_PRIVATE_KEY`.

Sem credenciais de Wallet, o cartão web continua funcionando normalmente.

## Segurança e privacidade
Nunca envie chaves, tokens ou certificados ao navegador. Credenciais por cliente são armazenadas criptografadas no banco usando `CLUBE_ENCRYPTION_KEY`. Mantenha essa chave fixa após iniciar o uso em produção.


## v42
Dashboard ampliado, histórico individual, ciclo de resgate, permissões administrativas de clientes, filtros/status por empresa, QR de cadastro, exportação CSV, Wallet contextual e landing comercial.


## Operação recomendada (v42)
- Produção e staging devem usar bancos separados. Defina `APP_ENV=staging` no serviço de homologação e nunca reutilize o `DATABASE_URL` de produção.
- Configure `PUBLIC_BASE_URL` com o domínio próprio. No Railway, aponte o domínio via Settings > Networking e mantenha HTTPS.
- O Painel Taboo oferece **BACKUP** em JSON com empresas, equipe, cartões e transações. Faça backups periódicos e teste a restauração em staging antes de qualquer necessidade real.
- Exclusão de empresa no painel agora é arquivamento reversível; use **Restaurar** para reativar.
- Antes de publicar uma versão, rode `python smoke_test.py` em staging e valide cadastro, QR, selo, resgate, e-mail e Wallet.

## v42 — Selos + Pontos e catálogo de recompensas

- Cada empresa pode usar fidelidade por **Selos** ou por **Pontos**.
- Em Pontos, a regra pode ser R$ 2, R$ 3, R$ 5 ou R$ 10 gastos para gerar 1 ponto.
- O atendente informa o valor da compra e o sistema calcula os pontos automaticamente.
- O **administrador da empresa** cadastra, edita, ativa e desativa recompensas do catálogo.
- O **atendente** pode visualizar o catálogo e efetuar resgates, mas não pode alterá-lo.
- O cartão por pontos exibe o saldo e oferece acesso ao catálogo público de recompensas.
- Apple Wallet e Google Wallet passam a exibir saldo de pontos quando o programa for desse tipo.
- Programas antigos permanecem como `stamps` por padrão, preservando compatibilidade.
