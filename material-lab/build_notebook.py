# -*- coding: utf-8 -*-
"""Gera o notebook .ipynb do lab: replicando os mecanismos da Material Security."""
import json, os

cells = []
_counter = {"n": 0}

def _nid():
    _counter["n"] += 1
    return "cell-" + str(_counter["n"])

def md(text):
    cells.append({"cell_type": "markdown", "metadata": {}, "id": _nid(),
                  "source": [l + "\n" for l in text.split("\n")]})

def code(text):
    cells.append({"cell_type": "code", "metadata": {}, "id": _nid(),
                  "execution_count": None, "outputs": [],
                  "source": [l + "\n" for l in text.split("\n")]})

# =====================================================================
md(r"""# Laboratório — Replicando a Material Security (simulado)
### Email Security API-native: espelho, detecção, redação e OAuth kill-switch

Este notebook é um **laboratório executável e autossuficiente** (roda no Google Colab) que reproduz os
**mecanismos centrais** da Material Security usando **dados simulados** — sem precisar de credenciais
do Google/Microsoft.

O ambiente simulado é o **ClinApp** (domínio legítimo `clinapp.com.br`), um SaaS de saúde com
prontuários e dados sensíveis.

**O que vamos replicar (e a que mecanismo real corresponde):**

| Mecanismo da Material | O que faremos aqui |
|---|---|
| **Mailbox mirroring** (espelho da caixa) | Copiar a caixa para um store próprio e provar que análise retroativa continua funcionando mesmo após a exclusão no provedor |
| **Detecção de phishing/BEC pós-entrega** | Heurísticas: spoofing (SPF/DKIM/DMARC), impersonação de VIP, domínio *lookalike*, coleta de credencial, QR phishing, análise de links |
| **"Herd immunity"** (similarity matching) | Agrupar variantes do mesmo phishing (shingling + Jaccard) e remediar todas a partir de 1 reporte |
| **Sensitive Categories + Redaction ("securing")** | Classificar dados sensíveis (cartão, CPF/CNPJ, chaves) e **substituir a mensagem por um stub redigido**, guardando o original num vault |
| **OAuth Remediation Agent** | Classificar apps OAuth por risco e **revogar token** na hora (kill-switch) |
| **ATO containment** | Detectar conta comprometida (login externo + regra de encaminhamento + export em massa) e limitar o *blast radius* |

> O fluxo que reproduzimos é o mesmo: **espelhar → classificar → detectar → "securing" → conter**.
""")

md(r"""## Configuração""")

code(r"""import re, json, hashlib, random
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

%matplotlib inline
random.seed(42); np.random.seed(42)

ORG_DOMAIN = "clinapp.com.br"
VIPS = {
    "maria.souza": {"nome": "Maria Souza", "cargo": "CFO"},
    "joao.silva":  {"nome": "Joao Silva",  "cargo": "CEO"},
    "carlos.lima": {"nome": "Carlos Lima", "cargo": "CTO"},
}
print("Org:", ORG_DOMAIN, "| VIPs:", {k: v["cargo"] for k, v in VIPS.items()})""")

# =====================================================================
md(r"""---
## 1. MAILBOX MIRRORING — o espelho da caixa

A Material conecta via API e **retém uma cópia** das mensagens (conteúdo + metadados) no storage
próprio. É isso que habilita busca, análise retroativa e remediação pós-entrega — coisas impossíveis
num gateway que só vê o tráfego na borda.

Aqui simulamos: (1) uma caixa de entrada com emails normais e maliciosos, (2) o espelhamento, e
(3) a prova de que o espelho **sobrevive à exclusão** no provedor.""")

code(r"""def email(mid, from_name, from_addr, to, subject, body, spf="pass", dkim="pass", dmarc="pass",
          attachments=None, links=None, ts=None):
    return {
        "id": mid, "ts": ts or "2026-08-25T09:00:00",
        "from_name": from_name, "from_addr": from_addr, "to": to,
        "subject": subject, "body": body,
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "attachments": attachments or [], "links": links or [],
        "labels": ["INBOX"],
    }

# ---------- Caixa de entrada simulada ----------
inbox = [
    # --- emails legítimos ---
    email("m-001", "Ana Pereira", "ana.pereira@clinapp.com.br", "joao.silva@clinapp.com.br",
          "Relatorio de vendas Q3", "Segue o relatorio consolidado do trimestre."),
    email("m-002", "Fatura Fornecedor", "fatura@fornecedor.com.br", "ana.pereira@clinapp.com.br",
          "NF-e 4571", "Segue a nota fiscal em anexo.", attachments=[{"name": "nf-4571.pdf", "encrypted": False}]),
    # --- ameacas injetadas ---
    email("m-101", "Maria Souza", "maria.souza@cl1napp.com.br", "ana.pereira@clinapp.com.br",
          "URGENTE: pagamento fornecedor", "Faca transferencia de R$ 120.000 hoje. Dados bancarios em anexo.",
          spf="fail", dkim="fail", dmarc="fail"),                                     # BEC / VIP impersonation + homoglifo
    email("m-102", "Seguranca ClinApp", "security@clinapp.com.br.evil-login.com", "joao.silva@clinapp.com.br",
          "Sua senha expira", "Sua senha expira em 24h. Verifique para nao perder o acesso.",
          spf="fail", dkim="fail", dmarc="fail",
          links=[{"href": "https://clinapp-login.vercel.app", "text": "Verificar conta"}]),  # coringa + credential harvest
    email("m-103", "No-Reply", "no-reply@cl1napp.com.br", "carlos.lima@clinapp.com.br",
          "Conta bloqueada", "Detectamos atividade suspeita. Verifique sua conta agora.",
          spf="fail", dkim="fail", dmarc="fail",
          links=[{"href": "https://cl1napp.com.br/login", "text": "Desbloquear"}]),
    email("m-104", "Suporte", "suporte@clinapp-atendimento.com", "ana.pereira@clinapp.com.br",
          "Validacao MFA", "Escaneie o QR abaixo para validar seu MFA.",
          spf="fail", dkim="fail", dmarc="fail",
          attachments=[{"name": "mfa-qr.png", "encrypted": False}]),                  # QR phishing (quishing)
    email("m-105", "Admin", "admin@clinapp.com.br", "ana.pereira@clinapp.com.br",
          "Redefinicao de senha", "Clique para redefinir sua senha: https://clinapp.com.br/reset?s=abc123"),  # password reset (alto valor)
    email("m-106", "Ana Pereira", "ana.pereira@clinapp.com.br", "maria.souza@clinapp.com.br",
          "Cartao corporativo", "Use o cartao 4111 1111 1111 1111 para as despesas. CPF do titular: " +
          "529.982.247-25. Chave de API do ambiente: api_key: sk_live_9f8e7d6c5b4a3210abcd"),  # dados sensiveis
    email("m-107", "Contador Externo", "contador@escritorio.com", "ana.pereira@clinapp.com.br",
          "Extrato protegido", "Segue o extrato. Senha do arquivo: 1234.",
          attachments=[{"name": "extrato.zip", "encrypted": True}]),                   # anexo criptografado
]

# Variantes do MESMO phishing (para herd immunity): mesmo template, destinatarios e URLs diferentes
for i, (user, tok) in enumerate([("ana.pereira", "x7k2"), ("bruno.costa", "p9m4"), ("carla.dias", "q3z8")], start=1):
    inbox.append(email(f"m-20{i}", "Financeiro", "financeiro@cl1napp.com.br.evil-login.com",
        f"{user}@clinapp.com.br", "Acesso a fatura pendente",
        f"Sua fatura esta pendente. Acesse https://fatura-clinapp.com/pagar?token={tok} e regularize.",
        spf="fail", dkim="fail", dmarc="fail",
        links=[{"href": f"https://fatura-clinapp.com/pagar?token={tok}", "text": "Pagar agora"}]))

print(f"Caixa de entrada: {len(inbox)} mensagens (legitimas + ameacas injetadas).")""")

code(r"""# ---------- Espelhamento (mailbox mirroring) ----------
MIRROR = {}

def mirror_mailbox(mbox):
    # Copia cada mensagem para o store proprio (independente do provedor).
    for m in mbox:
        MIRROR[m["id"]] = json.loads(json.dumps(m))   # copia profunda
    return MIRROR

mirror_mailbox(inbox)
print(f"Espelho criado com {len(MIRROR)} mensagens retidas.\n")

def search_mirror(q):
    q = q.lower()
    return [m for m in MIRROR.values()
            if q in m["subject"].lower() or q in m["body"].lower() or q in m["from_addr"].lower()]

# --- Cenario: o phishing foi apagado da caixa ao vivo, mas o espelho retem ---
live_inbox = [m for m in inbox if m["id"] != "m-101"]   # admin/atacante apaga a msg-101 do provedor
print("Mensagem m-101 foi DELETADA da caixa ao vivo. Ela ainda existe no espelho?",
      "SIM" if "m-101" in MIRROR else "NAO")

print("\nBusca retroativa no espelho por 'pagamento':")
for m in search_mirror("pagamento"):
    print(f"  {m['id']}  de={m['from_addr']}  assunto='{m['subject']}'")

print("\nBusca retroativa por 'fatura' (pega as 3 variantes do phishing):")
for m in search_mirror("fatura"):
    print(f"  {m['id']}  para={m['to']}  assunto='{m['subject']}'")""")

# =====================================================================
md(r"""---
## 2. DETECÇÃO de phishing / BEC (pós-entrega)

A Material detecta ataques que **não têm link nem anexo malicioso** e que por isso passam por filtros
baseados em assinatura. Vamos implementar heurísticas de detecção e gerar "issues" com evidência e
explicação.""")

code(r"""HOMOGLYPHS = {"0": "o", "1": "i", "5": "s", "3": "e", "7": "t", "@": "a", "$": "s"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly"}

def levenshtein(a, b):
    if a == b: return 0
    if not a: return len(b)
    if not b: return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def lookalike(domain):
    d = domain.lower()
    if d == ORG_DOMAIN:
        return None                                    # legitimo
    if ORG_DOMAIN in d and not d.endswith("." + ORG_DOMAIN):
        return "dominio-coringa (embute o dominio real)"   # clinapp.com.br.evil.com
    base = d.split(".")[0]
    orgbase = ORG_DOMAIN.split(".")[0]
    norm = "".join(HOMOGLYPHS.get(c, c) for c in base)
    if norm == orgbase:
        return "homoglifo (caracteres trocados)"        # cl1napp -> clinapp
    if levenshtein(base, orgbase) <= 1:
        return "typosquatting"
    return None

def detect(m):
    issues = []
    dom = m["from_addr"].split("@")[-1]
    ext = not m["from_addr"].endswith("@" + ORG_DOMAIN)

    # 1) VIP impersonation (BEC): nome de exibicao imita VIP, mas remetente e externo
    for uid, v in VIPS.items():
        if v["nome"].lower() in m["from_name"].lower() and ext:
            issues.append({"id": m["id"], "det": "VIP impersonation (BEC)", "sev": "CRITICA",
                           "evidencia": f"nome='{m['from_name']}' remetente_real={m['from_addr']}",
                           "explicacao": f"Exibicao imita '{v['nome']} ({v['cargo']})' mas o remetente real e externo: {m['from_addr']}."})
            break

    # 2) Spoofing: falha de autenticacao do remetente
    if m["auth"]["dmarc"] == "fail" or m["auth"]["spf"] == "fail":
        issues.append({"id": m["id"], "det": "Spoofing (SPF/DKIM/DMARC)", "sev": "ALTA",
                       "evidencia": str(m["auth"]),
                       "explicacao": f"Falha de autenticacao de {m['from_addr']} ({m['auth']})."})

    # 3) Lookalike domain
    lk = lookalike(dom)
    if lk:
        issues.append({"id": m["id"], "det": "Lookalike domain", "sev": "ALTA",
                       "evidencia": f"dominio={dom}",
                       "explicacao": f"Dominio '{dom}' e suspeito: {lk}."})

    # 4) Credential harvesting (link de login externo)
    if re.search(r"(senha|password|conta).{0,40}(expira|verif|bloque|desbloque)", m["body"], re.I):
        for l in m["links"]:
            if ("login" in l["href"] or "verif" in l["href"] or "desbloque" in l["href"]) and ORG_DOMAIN not in l["href"]:
                issues.append({"id": m["id"], "det": "Credential harvesting", "sev": "ALTA",
                               "evidencia": f"link={l['href']}",
                               "explicacao": f"Corpo pede acao sobre conta/senha com link externo: {l['href']}."})

    # 5) QR phishing (quishing): imagem + pedido de escanear
    if any(a["name"].lower().endswith((".png", ".jpg", ".jpeg")) for a in m["attachments"]) and \
       re.search(r"escan|scan|qr|mfa", m["body"], re.I):
        issues.append({"id": m["id"], "det": "QR phishing (quishing)", "sev": "ALTA",
                       "evidencia": f"anexo={m['attachments'][0]['name']}",
                       "explicacao": "Imagem (possivel QR) com pedido de escaneamento para 'validar' credenciais/MFA."})

    # 6) Link shortener
    for l in m["links"]:
        host = l["href"].split("/")[2] if len(l["href"].split("/")) > 2 else ""
        if host in SHORTENERS:
            issues.append({"id": m["id"], "det": "Link shortener", "sev": "MEDIA",
                           "evidencia": f"link={l['href']}",
                           "explicacao": f"URL encurtada ({host}) ofusca o destino real."})

    return issues

all_issues = []
for m in inbox:
    all_issues.extend(detect(m))

print(f"{len(all_issues)} issues detectadas:\n")
for i in all_issues:
    print(f"[{i['sev']:<8}] {i['det']:<28} {i['id']}")
    print(f"          evidencia: {i['evidencia']}")
    print(f"          explicacao: {i['explicacao']}\n")""")

md(r"""### Resumo dos sinais usados (todos detectáveis sem "ver" link/nexo malicioso)

| Sinal | O que detecta | Tipo de ataque |
|---|---|---|
| SPF/DKIM/DMARC `fail` | remetente forjado | spoofing / BEC |
| display name = VIP + remetente externo | engenharia social | BEC / VEC |
| homoglifo / typosquatting / coringa | domínio parecido | phishing |
| corpo pede ação de senha + link externo | coleta de credencial | credential phishing |
| anexo de imagem + "escanear" | QR malicioso | quishing |
| URL encurtada | destino ofuscado | phishing genérico |""")

# =====================================================================
md(r"""---
## 3. "HERD IMMUNITY" — similarity matching

Quando um usuário reporta um phishing, a Material encontra **todas as variantes** da mesma mensagem na
organização (similaridade de conteúdo) e remedia todas. Um reporte vira cobertura total em minutos.

Implementamos isso com **shingling + similaridade de Jaccard** sobre o conteúdo normalizado (URLs,
números e emails são mascarados para que as variantes se igualem).""")

code(r"""def normalize(m):
    s = (m["subject"] + " " + m["body"]).lower()
    s = re.sub(r"https?://\S+", " URL ", s)
    s = re.sub(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", " EMAIL ", s)
    s = re.sub(r"\d+", " N ", s)
    s = re.sub(r"\W+", " ", s)
    return s

def shingle(s, k=4):
    return set(s[i:i + k] for i in range(len(s) - k + 1))

def jaccard(a, b):
    sa, sb = shingle(a), shingle(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)

def cluster(messages, threshold=0.6):
    norm = [normalize(m) for m in messages]
    seen, groups = set(), []
    for i in range(len(messages)):
        if i in seen:
            continue
        grp = [messages[i]]
        for j in range(i + 1, len(messages)):
            if j in seen:
                continue
            if jaccard(norm[i], norm[j]) >= threshold:
                grp.append(messages[j])
                seen.add(j)
        seen.add(i)
        groups.append(grp)
    return groups

groups = cluster(inbox)
print("Grupos por similaridade (>= 0.6 de Jaccard):")
for g in groups:
    if len(g) > 1:
        print(f"  CLUSTER de {len(g)} mensagens: {[m['id'] + ' para ' + m['to'] for m in g]}")
        print(f"     => 1 reporte do usuario bastaria para remediar TODAS essas variantes.\n")

# Demonstracao da similaridade
a, b = inbox[-3], inbox[-2]
print(f"Similaridade entre '{a['id']}' e '{b['id']}' (mesma campanha): {jaccard(normalize(a), normalize(b)):.2f}")
print(f"Similaridade entre '{a['id']}' e um email legitimo (m-001): {jaccard(normalize(a), normalize(inbox[0])):.2f}")""")

# =====================================================================
md(r"""---
## 4. SENSITIVE CATEGORIES + REDAÇÃO ("securing")

A proteção mais característica da Material: ao detectar conteúdo sensível, ela **substitui a mensagem
por um stub redigido** e move o conteúdo real para um **vault**. O resultado é controle de acesso em
nível de mensagem que **sobrevive ao comprometimento da conta** — um atacante com a senha válida só vê
o stub, não o segredo.

Primeiro classificamos (cartão de crédito via **Luhn**, **CPF/CNPJ** com dígito verificador, chaves de
API e anexos criptografados). Depois "securamos" a mensagem.""")

code(r"""def luhn(num):
    digits = [int(d) for d in re.sub(r"\D", "", num)]
    if len(digits) < 13:
        return False
    s, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0

def valid_cpf(cpf):
    c = re.sub(r"\D", "", cpf)
    if len(c) != 11 or c == c[0] * 11:
        return False
    for i in (9, 10):
        s = sum(int(c[j]) * ((i + 1) - j) for j in range(i))
        if (s * 10) % 11 % 10 != int(c[i]):
            return False
    return True

def valid_cnpj(cnpj):
    c = re.sub(r"\D", "", cnpj)
    if len(c) != 14 or c == c[0] * 14:
        return False
    pesos = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    for i in (12, 13):
        s = sum(int(c[j]) * pesos[j - (12 - i)] for j in range(i))
        d = 11 - (s % 11)
        d = 0 if d >= 10 else d
        if d != int(c[i]):
            return False
    return True

def classify_sensitive(body, attachments):
    findings = []
    for m in re.finditer(r"\b(?:\d[ -]?){13,19}\b", body):
        if luhn(m.group()):
            findings.append(("cartao_de_credito", m.group()))
    for m in re.finditer(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b", body):
        if valid_cpf(m.group()):
            findings.append(("cpf", m.group()))
    for m in re.finditer(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b", body):
        if valid_cnpj(m.group()):
            findings.append(("cnpj", m.group()))
    for m in re.finditer(r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*['\\x22]?([A-Za-z0-9_\-]{16,})", body):
        findings.append(("credencial", m.group(2)))
    for a in attachments:
        if a.get("encrypted") or (a["name"].lower().endswith((".zip", ".7z")) and "senha" in body.lower()):
            findings.append(("anexo_criptografado", a["name"]))
    return findings

for m in inbox:
    f = classify_sensitive(m["body"], m["attachments"])
    if f:
        print(f"{m['id']}: {[(k, v[:22]) for k, v in f]}")""")

code(r"""VAULT = {}   # conteudo sensivel fica AQUI, fora da caixa ao vivo

def secure_message(m):
    findings = classify_sensitive(m["body"], m["attachments"])
    if not findings:
        return m, None
    body = m["body"]
    for kind, val in findings:
        if kind in ("cartao_de_credito", "cpf", "cnpj", "credencial"):
            body = body.replace(val, "[REDACTED]")
    key = hashlib.sha256(m["id"].encode()).hexdigest()[:16]
    VAULT[key] = {"id": m["id"], "original": m["body"], "findings": findings}
    secured = dict(m)
    secured["body"] = body
    secured["secured"] = True
    secured["vault_key"] = key
    return secured, findings

# Secura a mensagem de dados sensiveis (m-106) e a de anexo criptografado (m-107)
for mid in ("m-106", "m-107"):
    m = MIRROR[mid]
    secured, findings = secure_message(m)
    MIRROR[mid] = secured
    print(f"=== {mid} SECURADA ===  achados: {[k for k, _ in findings]}")
    print("  stub (o que fica na caixa):", secured["body"][:120])
    print("  vault_key:", secured["vault_key"], "| original preservado no VAULT:", len(VAULT[secured['vault_key']]['original']), "chars")
    print()

print("=> Um atacante com acesso TOTAL a caixa ao vivo le apenas o STUB.")
print("   O conteudo real esta no VAULT (fora do alcance do mailbox), exigindo autenticacao para desbloquear.")""")

# =====================================================================
md(r"""---
## 5. OAuth REMEDIATION AGENT — kill-switch

Apps OAuth são um vetor direto para Gmail/Drive. A Material monitora **continuamente** o que cada app
faz e **revoga o token na hora** que algo vira malicioso — em vez de só tirar um "retrato" de permissões
e alertar depois (SSPM tradicional).

Vamos: (1) classificar risco de cada app, e (2) demonstrar o kill-switch quando um fornecedor legítimo
é comprometido.""")

code(r"""APPS = [
    {"name": "Slack",        "scopes": ["gmail.read"],                          "publisher": "verified",   "last_used_days": 1,  "users": 40, "status": "ativo"},
    {"name": "MailSync Pro", "scopes": ["gmail.read", "drive", "contacts"],     "publisher": "unverified", "last_used_days": 2,  "users": 3,  "status": "ativo"},
    {"name": "LegacyReport", "scopes": ["gmail.read"],                          "publisher": "verified",   "last_used_days": 400, "users": 1,  "status": "ativo"},
    {"name": "TrustedVendor","scopes": ["gmail.read"],                          "publisher": "verified",   "last_used_days": 0,  "users": 12, "status": "ativo"},
    {"name": "ClipboardAI",  "scopes": ["gmail.read", "drive", "contacts", "calendar"], "publisher": "unverified", "last_used_days": 1, "users": 2, "status": "ativo"},
]

def oauth_risk(a):
    score, reasons = 0, []
    if a["publisher"] == "unverified":
        score += 3; reasons.append("publisher nao verificado")
    if len(a["scopes"]) >= 3:
        score += 2; reasons.append("escopos amplos")
    if a["last_used_days"] > 90:
        score += 2; reasons.append("token zumbi (sem uso recente)")
    if a["users"] == 1:
        score += 1; reasons.append("uso individual isolado")
    return score, reasons

rows = []
for a in APPS:
    s, r = oauth_risk(a)
    rows.append({"app": a["name"], "scopes": len(a["scopes"]), "publisher": a["publisher"],
                 "dias_sem_uso": a["last_used_days"], "risco": s, "motivos": "; ".join(r)})
risco_df = pd.DataFrame(rows).sort_values("risco", ascending=False)
risco_df""")

code(r"""# --- Kill-switch: o fornecedor 'TrustedVendor' foi comprometido (padrao Vercel/Heroku-Travis CI) ---
def kill_switch(apps, compromised_names):
    for a in apps:
        if a["name"] in compromised_names:
            a["status"] = "REVOGADO"
    return [a for a in apps if a["name"] in compromised_names]

print("Antes: TrustedVendor status =", [a["status"] for a in APPS if a["name"] == "TrustedVendor"][0])
revoked = kill_switch(APPS, ["TrustedVendor", "MailSync Pro"])
print("Apos kill-switch, apps REVOGADOS:", [(a["name"], a["status"]) for a in revoked])
print()
print("Monitoramento CONTINUO (Material): revoga o token assim que o comportamento vira malicioso.")
print("SSPM tradicional (polling): detectaria a exposicao no proximo snapshot, dias depois.")
print()
print("Estado final dos apps:")
for a in APPS:
    print(f"  {a['name']:<14} {a['status']:<9} scopes={len(a['scopes'])} publisher={a['publisher']}")""")

# =====================================================================
md(r"""---
## 6. ATO — detecção e contenção (blast radius)

O *blast radius* é o alcance do dano que um atacante consegue causar com uma conta comprometida:
quais arquivos lê, quais senhas redefinem via email, quais OAuth usa, para onde se move lateralmente.
Vamos detectar o padrão clássico de conta comprometida e mostrar como os controles acima **limitam** o
dano.""")

code(r"""def detect_ato(events):
    alerts = []
    login_ext = [e for e in events if e["event"] == "login" and not e["ip"].startswith("10.0.")]
    fwd = [e for e in events if e["event"] == "forward_rule_created"]
    exports = [e for e in events if e["event"] == "record.export"]
    if login_ext and fwd:
        alerts.append({"sev": "CRITICA", "det": "ATO confirmado",
                       "explicacao": f"Login de IP externo {login_ext[0]['ip']} + criacao de encaminhamento para {fwd[0]['target']}."})
    elif login_ext:
        alerts.append({"sev": "ALTA", "det": "Login anômalo",
                       "explicacao": f"Login de IP externo {login_ext[0]['ip']} sem encaminhamento ainda."})
    if exports:
        alerts.append({"sev": "ALTA", "det": "Exfiltração em massa",
                       "explicacao": f"{exports[0]['count']} prontuarios exportados."})
    return alerts

# Sinais pós-comprometimento da conta de 'ana.pereira'
events = [
    {"event": "login",               "ip": "203.0.113.99", "user": "ana.pereira", "ts": "2026-08-25T22:01:00"},
    {"event": "forward_rule_created", "target": "atacante@evil.com", "user": "ana.pereira", "ts": "2026-08-25T22:03:00"},
    {"event": "record.export",       "count": 120, "user": "ana.pereira", "ts": "2026-08-25T22:05:00"},
]
print("Eventos observados na conta comprometida:")
for e in events:
    print("  ", e)

print("\nDetecções de ATO:")
for a in detect_ato(events):
    print(f"  [{a['sev']}] {a['det']}: {a['explicacao']}")

print(
    "CONTEÇÃO (limita o blast radius):\n"
    "  * Email sensivel ja estava 'segurado' (stub + vault) -> o atacante NAO le o conteudo real (Secao 4).\n"
    "  * Redefinicao de senha / acesso por email de recuperacao -> protegido pelo vault (m-105, m-106).\n"
    "  * Encaminhamento detectado e revogado; tokens OAuth do app malicioso revogados (Secao 5).\n"
)""")

# =====================================================================
md(r"""---
## 7. CENÁRIO INTEGRADO — phishing → ATO → exfiltração → contenção

Juntando tudo: um ataque completo, do phishing inicial até a contenção, passando por todos os
mecanismos que construímos.""")

code(r"""print("=== CENARIO INTEGRADO ===\n")

# 1) Phishing chega para a financeira
phish = email("m-9001", "Seguranca ClinApp", "security@clinapp.com.br.evil-login.com",
              "ana.pereira@clinapp.com.br",
              "Acao necessaria: verifique sua conta",
              "Sua senha expira em 2h. Verifique agora para nao perder o acesso.",
              spf="fail", dkim="fail", dmarc="fail",
              links=[{"href": "https://clinapp-login.vercel.app", "text": "Verificar conta"}])
inbox.append(phish)
mirror_mailbox([phish])

print("1) DETECCAO do phishing recebido:")
for i in detect(phish):
    print(f"   [{i['sev']}] {i['det']} -> {i['explicacao']}")

# 2) A usuaria clicou: credencial vazou -> ATO
print("\n2) ATO detectado apos o clique:")
for a in detect_ato(events):
    print(f"   [{a['sev']}] {a['det']} -> {a['explicacao']}")

# 3) App OAuth malicioso surgiu com o acesso da vitima
new_grant = {"name": "MailSync Pro", "scopes": ["gmail.read", "drive", "contacts"],
             "publisher": "unverified", "last_used_days": 0, "users": 1, "status": "ativo"}
s, r = oauth_risk(new_grant)
print(f"\n3) OAuth: app '{new_grant['name']}' risco={s} ({'; '.join(r)}) -> KILL-SWITCH")
kill_switch(APPS, ["MailSync Pro"])
print(f"   Token de '{new_grant['name']}' REVOGADO.")

# 4) Espelho + vault preservam a investigacao e limitam o dano
print("\n4) ESPELHO + VAULT:")
print(f"   Mensagem m-9001 retida no espelho para investigacao: {'m-9001' in MIRROR}")
print(f"   Conteudo sensivel (m-106/m-107) continua no VAULT: {len(VAULT)} entradas protegidas")

# 5) Relatorio final legivel para o analista (explicabilidade)
print("\n=== RELATORIO FINAL PARA O ANALISTA ===")
print("  * Phishing de credential harvesting originado em dominio-coringa (SPF/DKIM/DMARC fail).")
print("  * Conta de 'ana.pereira' comprometida: login externo + encaminhamento + export de 120 prontuarios.")
print("  * Conteudo sensivel preservado no vault (dano limitado); token OAuth revogado; encaminhamento removido.")
print("  * Toda a cadeia rastreavel pelo espelho da caixa e pela trilha de eventos.")""")

# =====================================================================
md(r"""---
## 8. Síntese, mapeamento e exercícios

### O que replicamos (mecanismo da Material → nossa implementação)

| Mecanismo | Implementação |
|---|---|
| Mailbox mirroring | cópia profunda do inbox para um store próprio + busca retroativa que sobrevive à exclusão |
| Detecção pós-entrega | spoofing, VIP impersonation, lookalike (homoglifo/typosquatting/coringa), credential harvesting, quishing, shortener |
| Herd immunity | shingling + Jaccard sobre conteúdo normalizado → agrupa variantes |
| "Securing" | Luhn/CPF/CNPJ/chave + substituição por `[REDACTED]` e vault do original |
| OAuth kill-switch | score de risco (publisher, escopos, token zumbi) + revogação imediata |
| ATO containment | correlação login externo + encaminhamento + export em massa; dano limitado pelo vault |

### Conexão com certificações (CISSP / CISM)
- **CISSP D7 (Operações):** monitoramento, logging, correlação de eventos, resposta a incidentes.
- **CISSP D6 (Avaliação e Teste):** auditoria, accountability, trilhas à prova de adulteração.
- **CISM D3 (Risco):** detecção + contenção de ATO e limitação de *blast radius*.
- **LGPD / ISO 27001:** classificação de dados sensíveis (CPF/CNPJ = dado pessoal), controle de acesso e
  minimização de exposição — exatamente o que a redação/"securing" implementa.

### Exercícios
1. Adicione um email com **homoglifo usando caracteres unicode** (ex.: `с` cirílico em vez de `c`) e faça o detector pegá-lo.
2. Implemente **fuzzy hashing** (ex.: TLSH/ssdeep) no lugar do Jaccard para clustering — qual agrupa melhor?
3. Estenda `classify_sensitive` para **IBAN**, **PIS/PASEP** e **e-mails de redefinição de senha**.
4. Crie uma **regra de risco** que revogue apps com `publisher=unverified` E `scopes >= 3` automaticamente.
5. Simule **dois ataques simultâneos** e confirme que o espelho + clustering separam os incidentes.

### Como evoluir para o real
Este lab abstrai a fonte de dados. Para ir além, conecte os mesmos módulos a APIs reais:
- **Gmail API** (`users.messages.list/get`, `users.history.list` para tempo real, `users.settings` para encaminhamentos);
- **Microsoft Graph API** (mensagens, regras de caixa, audit logs);
- **OpenTelemetry** para os traces (veja o lab de Observabilidade & SIEM que também construímos).

> *Bom laboratório! Altere os dados, adicione novas ameaças e veja cada mecanismo reagir.*
""")

# =====================================================================
nb = {
    "cells": cells,
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.10"},
        "colab": {"provenance": []},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

out = "/root/material-lab/lab_material_email_security.ipynb"
os.makedirs("/root/material-lab", exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(nb, f, ensure_ascii=False, indent=1)

print(f"Notebook gerado: {out}")
print(f"Celulas: {len(cells)} (markdown={sum(1 for c in cells if c['cell_type']=='markdown')}, "
      f"code={sum(1 for c in cells if c['cell_type']=='code')})")
