# Clube Fidelidade v61


## Novidades da v61

- Google Wallet: redirecionamento para `pay.google.com` sem chamadas síncronas de PATCH/CREATE antes do HTTP 302, reduzindo a espera após o clique.
- Google Wallet: nova `LoyaltyClass` e novo `LoyaltyObject` na revisão **v61**, impedindo reaproveitamento do layout antigo.
- Programas por pontos: removido o bloco textual grande de recompensas do passe; **“Catálogo de recompensas”** fica no módulo nativo de links como CTA clicável para `/rewards?id=<cartão>`.
- Logo: endpoint e IDs versionados em **v61** para evitar cache da revisão anterior.
- Versão sincronizada para **v61** em servidor, páginas, painel e README.

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

## Versão

**v55**
