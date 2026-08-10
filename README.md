# Clube Fidelidade v1

Primeira versão funcional do sistema de cartão fidelidade digital.

## Incluído

- Login com perfis de **gerente** e **atendente**.
- Senhas armazenadas com PBKDF2-SHA256 + salt.
- Sessão HttpOnly/SameSite e proteção CSRF nas operações autenticadas.
- Campanhas white-label com meta, recompensa, ícone e código.
- Cadastro público do cliente via campanha.
- Cartão web individual com progresso e QR Code exclusivo.
- Leitura do QR pelo atendente via `BarcodeDetector` quando suportado, com entrada manual como fallback.
- Lançamento de selos exclusivamente pelo backend autenticado.
- Recompensa automática ao completar a meta.
- Resgate de recompensa com transação auditável.
- Antifraude: intervalo mínimo entre créditos, limite por hora/cartão, limite diário/atendente, créditos múltiplos apenas por gerente, idempotência e bloqueio lógico preparado.
- Dashboard do gerente, criação de campanhas e criação de usuários.
- Auditoria de transações com usuário, IP, dispositivo, data e estado anterior/novo.
- Hooks para Apple Wallet e Google Wallet.

## Credenciais demo

Gerente:
- `gerente@demo.local`
- `Gerente123!`

Atendente:
- `atendente@demo.local`
- `Atendente123!`

Troque essas credenciais antes de produção.

## Executar

Requer Python 3.10+.

```bash
python3 -m pip install -r requirements.txt
python3 server.py --host 127.0.0.1 --port 8000
```

Abra `http://127.0.0.1:8000`.

## Fluxo de teste

1. Abra `/join?campaign=CAFE5` e crie um cartão.
2. Abra o cartão gerado e apresente o QR.
3. Em outra aba/dispositivo, entre em `/login` como atendente.
4. Escaneie o QR ou copie o valor `CLUBE:...`.
5. Adicione um selo.
6. O cartão passa a mostrar o novo progresso ao recarregar.
7. Ao atingir 5, o progresso reinicia em 0 e `rewards_available` recebe +1.
8. O atendente pode resgatar a recompensa uma única vez.

> A campanha demo usa intervalo antifraude de 60 segundos. Um gerente pode superar algumas barreiras operacionais que exigem autorização.

## Apple Wallet / Google Wallet

A integração real exige credenciais externas que não podem ser fornecidas no ZIP:

- Apple: conta/certificado de Pass Type ID, Team ID, certificado e chave privada.
- Google: Wallet Issuer ID + Service Account autorizada.

O projeto detecta essas configurações pelas variáveis do `.env.example`. Os endpoints/hook estão isolados em `wallet.py` para que as credenciais sejam ativadas sem alterar a lógica de fidelidade.

**Importante:** esta v1 não inclui certificados ou chaves privadas e, por isso, o botão de adicionar à Apple/Google Wallet permanece desabilitado no modo demo. O cartão web + QR + todo o fluxo de fidelidade funciona normalmente.

## Produção

Antes de publicar para clientes reais, recomenda-se:

- HTTPS obrigatório (`CLUBE_SECURE_COOKIE=1`).
- Banco PostgreSQL em vez de SQLite para múltiplas instâncias/escala horizontal.
- Reverse proxy/WAF e rate limiting na borda.
- Backup do banco.
- Gestão de segredos fora do repositório.
- Política LGPD e consentimento caso sejam coletados e-mail/telefone.
- Configuração oficial dos emissores Apple/Google Wallet.
