# Clube Fidelidade v68


## Novidades da v68

- Consolidação do **perfil 360 do cliente**: histórico em modal agora inclui contato, CPF, nascimento, consentimento de marketing, total de movimentações, resgates e última atividade, além da timeline operacional.
- **Catálogo de recompensas avançado**: estoque ilimitado ou controlado, período de disponibilidade e baixa automática de estoque no resgate.
- Resgates por pontos passam a ter registro dedicado para relatórios e auditoria comercial.
- Estrutura de dados preparada para **multiunidade**, permissões granulares e observações internas de clientes, preservando compatibilidade com empresas existentes.
- Painel do administrador ganhou **checklist de configuração** e mantém os indicadores executivos de clientes, retorno, conclusão, inatividade, aniversariantes e comunicação.
- Fluxo de pontos continua baseado no **valor da compra**, com cálculo automático conforme a regra da empresa e confirmação do novo saldo.
- Mantidos automações, níveis VIP, aceleradores, NPS, vale-presente, exportações, auditoria, Wallets e comunicação segmentada já consolidados nas versões anteriores.
- Versão visual e backend sincronizados em **v68**.


- Vale-presente: botão Excluir para administradores, com remoção segura por empresa e auditoria.
- Vale-presente: avisos de consulta e utilização agora aparecem em modal (ex.: “Vale não encontrado!”).

- Vale-presente: geração corrigida no painel do Programa de Fidelidade com token CSRF, validação do valor, estado de carregamento e mensagem de sucesso/erro.
- Clientes cadastrados: coluna e saldo agora seguem automaticamente o tipo de fidelidade da empresa (Pontos ou Selos).

- **Histórico do cliente em modal:** o botão “HISTÓRICO” da lista de clientes agora abre uma janela centralizada, sem deslocar ou substituir a área de atendimento no topo da página.
- O modal exibe nome do cliente, saldo atual, movimentações em timeline, data/hora, atendente responsável, saldo anterior → novo saldo, observações e destaque visual para entradas e saídas.
- Fechamento pelo botão ×, clique no fundo ou tecla `Esc`; em telas pequenas o modal se adapta ao formato mobile e mantém scroll somente no conteúdo do histórico.
- Redesign premium dos painéis de administrador da empresa e atendente mantido: navegação rápida, hero contextual por perfil, atendimento em destaque, cards e tabelas mais limpos, indicadores reorganizados, busca e ações rápidas, responsividade para tablet/mobile e hierarquia visual unificada.
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

## Versão

**v68**
