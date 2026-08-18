# Clube Fidelidade v57
## Novidades da v57

- Google Wallet: corrigido o cache da `programLogo`. A URL pública da logo agora inclui uma revisão do processador (`r57`), garantindo que o Google busque novamente a imagem quando o algoritmo de recorte/redimensionamento mudar.
- Mantido o recorte de margens transparentes e de fundo uniforme da v56, agora efetivamente refletido no Google Wallet.
- Marcadores de versão do README e do painel atualizados para v57.


Versão multi-cliente com antifraude, QR temporário, fila de mensagens, automações, dashboard, LGPD, perfis Taboo/Administrador do cliente/Atendente e integração configurável com Apple Wallet e Google Wallet.


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

## Versão

**v55**