# webhook-audit

Lê um log de entregas de webhook e aponta os problemas que costumam quebrar uma integração entre sistemas.

Demo independente, sem vínculo com a Verity. Feita por Lucas Saldanha como exemplo pequeno de integração: idempotência, ordem de eventos, assinatura e retentativas.

## O que verifica

| Tipo | Significado |
|---|---|
| `duplicate` | O mesmo `event_id` chegou mais de uma vez. O consumidor precisa ser idempotente. |
| `out_of_order` | O número de sequência de um objeto voltou para trás. |
| `gap` | O número de sequência pulou um valor, então um evento pode ter se perdido. |
| `bad_signature` | O HMAC-SHA256 do corpo não bate com o cabeçalho (só com `--secret`). |
| `slow_retry` | Em 3 ou mais entregas do mesmo evento, o intervalo entre tentativas diminuiu em vez de crescer. |

## Como rodar

Precisa de Python 3.10 ou mais novo. Não tem dependência além do pytest nos testes.

```bash
pip install -e ".[test]"
webhook-audit examples/sample.jsonl --secret example-secret
webhook-audit examples/sample.jsonl --json
pytest -q
```

Cada linha do log é um JSON com `event_id`, `object_id`, `sequence`, `ts` (segundos), `body` e `signature`. O código de saída é 0 sem achados, 1 com achados e 2 se o arquivo estiver inválido.

O arquivo `examples/sample.jsonl` é inventado. Nele o relatório acusa 2 eventos duplicados, 1 salto de sequência, 1 evento fora de ordem, 1 assinatura inválida e 1 retentativa que encurta o intervalo.

## What was tested

- 15 testes automáticos, todos offline, rodando com `pytest` no GitHub Actions.
- Cada tipo de achado tem um teste que o dispara e um que mostra que um log limpo passa.
- Um corpo alterado depois de assinado é rejeitado.
- Linhas em branco são ignoradas, JSON inválido e arquivo ausente dão erro claro.
- O resultado completo sobre o arquivo de exemplo é conferido contagem por contagem.

## What was not tested

- Nenhum log real de produção. Só o arquivo inventado e os casos dos testes.
- Nenhum provedor real de webhook. O formato do log é o meu, não o de Stripe, GitHub ou outro.
- Logs grandes: o programa lê tudo na memória e não foi medido além de poucas linhas.
- Relógios diferentes entre emissor e receptor, e eventos com `ts` fora de ordem.
- A regra de `slow_retry` é uma heurística simples. Ela não conhece o plano de retentativa de cada provedor.
