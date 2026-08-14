# Clube Fidelidade v35

Versão multi-cliente com antifraude, QR temporário, fila de mensagens, automações, dashboard, LGPD, perfis Taboo/Administrador do cliente/Atendente e integração configurável com Apple Wallet e Google Wallet.

## Novidades da v35
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
