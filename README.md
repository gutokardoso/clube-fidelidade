# Clube Fidelidade v55

Versão multi-cliente com antifraude, QR temporário, fila de mensagens, automações, dashboard, LGPD, perfis Taboo/Administrador do cliente/Atendente e integração configurável com Apple Wallet e Google Wallet.

## Atualização v55

- Google Wallet: logo do cliente agora tem margens vazias removidas automaticamente e ocupa até 88% da área útil, ficando visualmente maior no círculo do cartão.

- Google Wallet: classes de fidelidade específicas por cliente, permitindo logo e cor independentes.
- `programLogo`: URL pública da logo passa a usar `CLUBE_PUBLIC_URL`, `PUBLIC_BASE_URL` ou, automaticamente no Railway, `RAILWAY_PUBLIC_DOMAIN`.
- Corrige o erro `LoyaltyClass cannot be created without a program logo` quando a URL pública não estava configurada manualmente.
- Mantém a imagem da logo em endpoint PNG dedicado e com cache-busting.

## Versão

**v55**
