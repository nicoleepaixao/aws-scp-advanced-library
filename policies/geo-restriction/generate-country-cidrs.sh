#!/bin/bash
# generate-country-cidrs.sh
# Gera lista de CIDRs agregados em /13 para um país a partir dos dados do RIR
#
# Uso:
#   ./generate-country-cidrs.sh BR lacnic    # Brasil
#   ./generate-country-cidrs.sh US arin      # EUA
#
# Fontes:
#   LACNIC: https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest
#   ARIN:   https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest

set -euo pipefail

COUNTRY="${1:-BR}"
RIR="${2:-lacnic}"

case "$RIR" in
  lacnic) URL="https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest" ;;
  arin)   URL="https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest" ;;
  ripe)   URL="https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest" ;;
  apnic)  URL="https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest" ;;
  *)      echo "RIR inválido: $RIR (use: lacnic, arin, ripe, apnic)"; exit 1 ;;
esac

echo "# CIDRs /13 para country=$COUNTRY via $RIR"
echo "# Fonte: $URL"
echo "# Gerado em: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

curl -s "$URL" | \
  grep "|${COUNTRY}|ipv4|" | \
  awk -F'|' '{
    ip = $4
    count = $5
    # Calcula prefixo CIDR
    prefix = 32
    n = count
    while (n > 1) { n = n / 2; prefix-- }
    printf "%s/%d\n", ip, prefix
  }' | \
  # Agrega em blocos /13
  awk -F'[./]' '{
    octet1 = $1
    octet2 = int($2 / 8) * 8
    block = octet1 "." octet2 ".0.0/13"
    if (!seen[block]++) print block
  }' | sort -t. -k1,1n -k2,2n
