# Clube Fidelidade v54

Versão multi-cliente com antifraude, QR temporário, fila de mensagens, automações, dashboard, LGPD, perfis Taboo/Administrador do cliente/Atendente e integração configurável com Apple Wallet e Google Wallet.

## Atualização v54

- Google Wallet: classes de fidelidade específicas por cliente, permitindo logo e cor independentes.
- `programLogo`: URL pública da logo passa a usar `CLUBE_PUBLIC_URL`, `PUBLIC_BASE_URL` ou, automaticamente no Railway, `RAILWAY_PUBLIC_DOMAIN`.
- Corrige o erro `LoyaltyClass cannot be created without a program logo` quando a URL pública não estava configurada manualmente.
- Mantém a imagem da logo em endpoint PNG dedicado e com cache-busting.

## Versão

**v54**
