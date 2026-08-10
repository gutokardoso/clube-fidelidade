# Clube Fidelidade v8

Plataforma white-label de fidelidade digital com gerente, atendente, cartões por QR, antifraude, recompensas e auditoria.

## Novidades da v8

- Cada nova campanha exige o envio de uma logo própria (PNG, JPG ou WEBP, até 500 KB).
- A página pública de cadastro do cliente exibe a logo da campanha no lugar do texto fixo "CLUBE CAFÉ".
- Gerente pode excluir campanhas pelo painel. A exclusão remove os cartões, selos e transações ligados à campanha; clientes sem nenhum outro cartão são limpos automaticamente.
- Gerente pode excluir usuários da equipe criados no painel.
- Proteções: não é possível excluir o próprio usuário logado, o gerente principal configurado no Railway nem o último gerente ativo.
- Migração automática adiciona `logo_image` a bancos PostgreSQL/SQLite já existentes.

## Produção no Railway

Mantém as mesmas variáveis da v7, incluindo `DATABASE_URL`, `CLUBE_ADMIN_EMAIL`, `CLUBE_ADMIN_PASSWORD` e credenciais opcionais do atendente.

O health check continua em `/api/health` e agora retorna `version: v8`.
