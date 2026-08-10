# Clube Fidelidade v9

Plataforma white-label de fidelidade digital com gerente, atendente, cartões por QR, antifraude, recompensas e auditoria.

## Novidades da v9

- Texto `Intervalo mínimo (s)` alterado para `Intervalo mínimo (em segundos)`.
- Texto `Máx. selos/hora/cartão` alterado para `Máx. selos/hora/cartão (em 1 hora)`.
- O código visível no cartão do cliente agora é exatamente o mesmo conteúdo gravado no QR Code: `CLUBE:<public_id>`.
- A atendente pode escanear o QR Code ou digitar manualmente esse mesmo código para localizar o cartão.
- Crédito de selos, resgate e bloqueio de cartão aceitam o código público do cartão.
- Compatibilidade mantida com o token interno antigo para cartões já existentes.

Mantém também os recursos da v8: logo por campanha, upload de imagem, exclusão de campanhas e usuários, perfis de gerente/atendente e regras antifraude.

## Produção no Railway

Mantém as mesmas variáveis das versões anteriores, incluindo `DATABASE_URL`, `CLUBE_ADMIN_EMAIL`, `CLUBE_ADMIN_PASSWORD` e credenciais opcionais do atendente.

O health check continua em `/api/health` e retorna `version: v9`.
