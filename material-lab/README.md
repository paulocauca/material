# Material Security — Laboratório Replicado (Colab)

Laboratório **executável e autossuficiente** (roda no Google Colab) que reproduz os mecanismos centrais
da **[Material Security](https://material.security)** usando **dados simulados** — sem precisar de
credenciais do Google/Microsoft.

## O que a Material Security faz (contexto)

Plataforma de segurança *API-native* para **Google Workspace + Microsoft 365** que cobre a cadeia de
ataque do workspace: **Email → Identidade (ATO) → Dados → OAuth**. Entra *dentro da caixa postal* via
Gmail API / Microsoft Graph (sem mudar MX, sem agentes, sem gateway).

## Mecanismos replicados neste lab

| Mecanismo da Material | Implementação no lab |
|---|---|
| **Mailbox mirroring** (espelho da caixa) | Cópia da caixa para um store próprio + busca retroativa que sobrevive à exclusão |
| **Detecção de phishing/BEC pós-entrega** | Spoofing (SPF/DKIM/DMARC), VIP impersonation, lookalike (homoglifo/typosquatting/coringa), credential harvesting, quishing, link shortener |
| **"Herd immunity"** (similarity matching) | Shingling + Jaccard sobre conteúdo normalizado → agrupa variantes |
| **"Securing"/redação** | Luhn + CPF/CNPJ + chaves de API + anexo cifrado → substitui por `[REDACTED]` e guarda o original num vault |
| **OAuth kill-switch** | Score de risco (publisher, escopos, token zumbi) + revogação imediata |
| **ATO containment** | Correlação login externo + encaminhamento + export em massa; dano limitado pelo vault |

O fluxo reproduzido: **espelhar → classificar → detectar → "securing" → conter**.

## Como usar

1. Acesse o [Google Colab](https://colab.research.google.com).
2. **File → Upload notebook** e envie `lab_material_email_security.ipynb`
   (ou o `lab_material_email_security.py`, que o Colab converte em células).
3. **Runtime → Run all** — não precisa instalar nada (usa `pandas`/`numpy`/`matplotlib`, pré-instalados).

## Arquivos

- `lab_material_email_security.ipynb` — notebook completo (markdown + código).
- `lab_material_email_security.py` — versão `.py` (mesmo conteúdo, para upload direto).
- `build_notebook.py` — script que gera o `.ipynb` (para reprodutibilidade).

## Lab complementar

- **Observabilidade & SIEM** (`lab_observabilidade_siem.ipynb`): logs, rastreabilidade, auditoria e
  explicabilidade — o par deste lab de email security.

## Validação

O notebook foi executado de ponta a ponta via `jupyter nbconvert --execute` (saída limpa, sem erros).
As detecções disparam corretamente: 16 issues (VIP impersonation/BEC, spoofing, lookalike, credential
harvesting, quishing), clustering das 3 variantes do phishing, redação de cartão/CPF/API key e
kill-switch de OAuth.
