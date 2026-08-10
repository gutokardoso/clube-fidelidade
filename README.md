# Clube Fidelidade v6

Sistema white-label de fidelidade digital com perfis de gerente e atendente, campanhas, QR individual, selos, recompensas, histórico/auditoria e controles antifraude.

## O que mudou na v6

- Suporte a PostgreSQL via `DATABASE_URL` para produção.
- Fallback automático para SQLite durante desenvolvimento local.
- Compatibilidade com a porta dinâmica da hospedagem (`PORT`) e bind em `0.0.0.0`.
- `railway.json` e `Procfile` prontos para deploy.
- Health check em `/api/health`.
- Cookies `Secure` ativados automaticamente quando PostgreSQL/produção está configurado.
- Credenciais demo não são mais criadas automaticamente em produção.
- Bootstrap seguro do primeiro gerente por variáveis de ambiente.
- Apple Wallet e Google Wallet continuam preparadas para receber credenciais oficiais.

## Teste local

Requer Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

Abra `http://localhost:8000`.

No modo local, se `DATABASE_URL` não estiver definida, o projeto usa SQLite e cria a demonstração:

- Gerente: `gerente@demo.local` / `Gerente123!`
- Atendente: `atendente@demo.local` / `Atendente123!`

Para desativar os usuários demo localmente, defina `CLUBE_SEED_DEMO=0` e informe as variáveis de bootstrap.

## Deploy no Railway + PostgreSQL

1. Suba o conteúdo desta pasta para um repositório GitHub.
2. No Railway, crie um projeto e escolha **Deploy from GitHub Repo**.
3. No mesmo projeto Railway, adicione um serviço PostgreSQL.
4. Faça `DATABASE_URL` do serviço da aplicação apontar para a variável fornecida pelo PostgreSQL.
5. No serviço da aplicação, adicione as variáveis:

```text
CLUBE_COMPANY_NAME=Nome da empresa
CLUBE_COMPANY_SLUG=nome-da-empresa
CLUBE_ADMIN_NAME=Seu nome
CLUBE_ADMIN_EMAIL=seu-email@dominio.com
CLUBE_ADMIN_PASSWORD=uma-senha-forte-com-12-ou-mais-caracteres
CLUBE_SECURE_COOKIE=1
CLUBE_SEED_DEMO=0
```

6. Faça o deploy. O processo inicializa as tabelas automaticamente.
7. Abra `/api/health`. A resposta esperada em produção inclui `"version":"v6"` e `"database":"postgresql"`.
8. Entre em `/login` com o e-mail e senha definidos em `CLUBE_ADMIN_EMAIL` e `CLUBE_ADMIN_PASSWORD`.
9. Pelo painel do gerente, crie os atendentes reais. Não é necessário guardar senha de atendente no código.

### Atenção ao primeiro deploy

Se o PostgreSQL estiver vazio e `CLUBE_SEED_DEMO=0`, o servidor exige `CLUBE_ADMIN_EMAIL` válido e `CLUBE_ADMIN_PASSWORD` com no mínimo 12 caracteres. Isso evita publicar o sistema com credenciais demo conhecidas.

## Variáveis de ambiente

Consulte `.env.example`. Nunca faça commit do arquivo `.env` real, certificados, chaves privadas ou credenciais das Wallets.

## Apple Wallet / Google Wallet

Os pontos de integração estão em `wallet.py`. Os botões reais dependem das credenciais oficiais de emissor/certificados. Essas credenciais devem ser adicionadas à hospedagem como secrets/variáveis e nunca incluídas no ZIP ou GitHub.

## Antifraude implementado

- cartão individual por token aleatório;
- somente usuário autenticado pode creditar/resgatar;
- CSRF em operações autenticadas;
- idempotência para evitar lançamentos duplicados;
- intervalo mínimo entre selos do mesmo cartão;
- limite por cartão/hora;
- limite operacional por atendente/dia;
- múltiplos selos exigem gerente;
- cartões podem ser bloqueados pelo gerente;
- transações e ações administrativas ficam auditadas;
- senha armazenada por hash, nunca em texto puro no banco.

## Testes

```bash
python3 -m unittest discover -s tests -v
```

Os testes automáticos usam SQLite isolado e não precisam de PostgreSQL.


## v6 — formulários resilientes
Login da equipe e adesão do cliente funcionam por POST HTML nativo no servidor, com redirecionamento HTTP 303. Assim, as duas operações essenciais não dependem de JavaScript para funcionar.
