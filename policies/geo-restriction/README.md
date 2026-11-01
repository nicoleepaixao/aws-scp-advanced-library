# DenyAccessFromNonAllowedCountries

Bloqueia chamadas de API AWS originadas de IPs fora do Brasil e Estados Unidos.

## Como funciona

A policy usa `NotIpAddress` com `aws:SourceIp` — ou seja, nega tudo que **não** estiver na lista de CIDRs permitidos. Se o IP de origem não é brasileiro nem americano, a chamada é bloqueada.

### Exceções (para não quebrar a AWS)

| Condição | Por quê |
|----------|---------|
| `aws:ViaAWSService: false` | Chamadas service-to-service (ex: Lambda invocando DynamoDB, ECS pulling ECR) não têm IP de origem do usuário — vêm da própria AWS. Sem essa exceção, serviços internos quebram. |
| `aws:SourceVpce: vpce-*` | Tráfego via VPC Endpoints é interno à AWS e não tem IP público. Sem essa exceção, qualquer serviço acessado via PrivateLink para de funcionar. |
| IPs específicos `/32` | VPNs corporativas, ferramentas de CI/CD, ou IPs fixos de parceiros que precisam de acesso. |

## Como os IPs confiáveis foram obtidos

### Fonte: LACNIC e ARIN (Regional Internet Registries)

Os blocos IP de cada país são gerenciados por **Regional Internet Registries (RIRs)**:

- **Brasil** → [LACNIC](https://www.lacnic.net/) (Latin America and Caribbean Network Information Centre)
- **Estados Unidos** → [ARIN](https://www.arin.net/) (American Registry for Internet Numbers)

Cada RIR publica um arquivo de delegações atualizado diariamente:

- LACNIC: `https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest`
- ARIN: `https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest`

### Formato do arquivo de delegações

```
lacnic|BR|ipv4|177.0.0.0|1048576|20100625|allocated
lacnic|BR|ipv4|179.0.0.0|524288|20100714|allocated
lacnic|BR|ipv4|186.192.0.0|65536|20080801|allocated
```

Campos: `registry|country_code|type|start_ip|count|date|status`

### Processo de geração dos CIDRs

1. **Download** dos arquivos de delegação do LACNIC e ARIN
2. **Filtrar** por `country_code = BR` (Brasil) e `country_code = US` (EUA)
3. **Converter** `start_ip + count` para notação CIDR
4. **Agregar** blocos adjacentes em supernets maiores (para reduzir o número de entradas)
5. **Usar /13 como máscara padrão** — trade-off entre precisão e tamanho da policy

### Por que /13?

SCPs têm limite de **5.120 caracteres** no JSON da policy. Com ~200 blocos /13, a policy fica próxima do limite. Usar /13 significa que cada bloco cobre 524.288 IPs (8 redes /16).

**Trade-off:**
- `/13` = menos entradas, cabe na SCP, mas pode incluir IPs de países vizinhos que compartilham o bloco
- `/16` ou menor = mais preciso, mas estoura o limite de caracteres da SCP

Na prática, /13 é suficiente porque os blocos LACNIC para Brasil são grandes e contíguos.

### Script para gerar a lista (reproduzível)

```bash
#!/bin/bash
# generate-country-cidrs.sh
# Gera lista de CIDRs /13 para um país a partir dos dados do RIR

COUNTRY="BR"
RIR_URL="https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest"

curl -s "$RIR_URL" | \
  grep "ipv4" | \
  grep "|${COUNTRY}|" | \
  awk -F'|' '{
    ip = $4
    count = $5
    # Calcula o prefixo: 32 - log2(count)
    prefix = 32
    n = count
    while (n > 1) { n = n / 2; prefix-- }
    printf "%s/%d\n", ip, prefix
  }' | \
  # Agrega em /13 (remove duplicatas do mesmo /13)
  awk -F'[./]' '{
    # Calcula o bloco /13 que contém esse IP
    octet1 = $1
    octet2 = int($2 / 8) * 8
    block = octet1 "." octet2 ".0.0/13"
    if (!seen[block]++) print block
  }' | sort -t. -k1,1n -k2,2n
```

### Para EUA (ARIN)

O mesmo processo, mas com:
```bash
RIR_URL="https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
COUNTRY="US"
```

**Nota:** Os blocos dos EUA são muito mais numerosos (~50.000+ delegações). Para caber na SCP, a abordagem usada nessa policy foi incluir apenas os blocos brasileiros + alguns blocos americanos onde estão os serviços mais usados (AWS, GitHub, etc.), e confiar no `aws:ViaAWSService` para cobrir o resto.

### Alternativa: usar aws:SourceIp com GeoIP

A AWS **não oferece** condition key nativa de geolocalização (tipo `aws:SourceCountry`). Por isso a abordagem de listar CIDRs é a única opção em SCPs.

Se você precisa de geo-blocking mais preciso, use:
- **AWS WAF** com geo-match condition (para tráfego HTTP)
- **CloudFront** com geo-restriction (para distribuição de conteúdo)
- **Security Groups** não suportam geo — só CIDR

## Limitações

1. **Tamanho da SCP** — máximo 5.120 caracteres. Com /13 você fica no limite. Se precisar de mais países, precisa de múltiplas SCPs ou agregar mais.
2. **IPs mudam** — LACNIC/ARIN delegam novos blocos regularmente. Recomenda-se atualizar a lista a cada 6 meses.
3. **VPN/proxy** — um atacante usando VPN com IP brasileiro passa pela policy. Isso é geo-restriction, não autenticação.
4. **IPv6** — essa policy só cobre IPv4. Se sua org usa IPv6, precisa de uma policy separada com `aws:SourceIpv6`.
5. **Falsos positivos** — /13 é amplo. Alguns blocos podem incluir IPs de países vizinhos (Argentina, Chile, Colômbia) que compartilham alocações LACNIC.

## Quando usar

- Organizações com operação exclusivamente no Brasil
- Compliance que exige restrição geográfica de acesso administrativo
- Defesa em profundidade contra acesso não autorizado de outros países
- Redução de superfície de ataque em contas de produção

## Quando NÃO usar

- Times distribuídos globalmente (vai bloquear seus próprios engenheiros)
- Contas que recebem webhooks de serviços internacionais
- Ambientes de desenvolvimento onde devs viajam frequentemente

## Referências

- [LACNIC — Delegated Stats](https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest)
- [ARIN — Delegated Stats](https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest)
- [AWS Docs — aws:SourceIp](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourceip)
- [AWS Docs — SCP Syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_syntax.html)
- [AWS Docs — aws:ViaAWSService](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-viaawsservice)
