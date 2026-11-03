# Geo restriction: deny API calls from outside Brazil and the US

File: [`deny-access-from-non-allowed-countries.json`](deny-access-from-non-allowed-countries.json)

Denies any AWS API call whose source IP is not in the allowed list of 270 CIDR blocks (Brazil from LACNIC, the US from ARIN, aggregated into `/13`).

## How it works

`NotIpAddress` on `aws:SourceIp` denies everything that is **not** in the list. Two exceptions keep AWS working:

| Condition | Why |
|---|---|
| `BoolIfExists aws:ViaAWSService = false` | Calls made by an AWS service on your behalf (Lambda to DynamoDB, ECS pulling from ECR) do not carry your IP. Without this, internal calls break. |
| `StringNotLike aws:SourceVpce = vpce-*` | Traffic through a VPC endpoint has no public IP. Without this, everything behind PrivateLink stops. |

Add fixed `/32` addresses (corporate VPN, CI runners) to the list when needed.

## Where the IP blocks come from

Each Regional Internet Registry publishes its delegations daily:

- LACNIC (Brazil): `https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest`
- ARIN (US): `https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest`

[`generate-country-cidrs.sh`](generate-country-cidrs.sh) downloads the file, filters by country, converts `start_ip + count` to CIDR and aggregates into `/13`:

```bash
./generate-country-cidrs.sh BR lacnic
./generate-country-cidrs.sh US arin
```

## Size

An SCP can have up to **10,240 characters**. Through the console, whitespace between JSON elements is removed and does not count; through the CLI or SDK every character counts. This file has 8,375 characters formatted and **4,691 minified**, so send it minified from the CLI. The `/13` aggregation was chosen when the limit was 5,120; with today's limit you can use smaller, more precise blocks.

## Limitations

1. **IP lists change.** Regenerate every six months.
2. **VPN or proxy.** An attacker with a Brazilian IP passes. This reduces the attack surface; it is not authentication.
3. **IPv4 only.** Use `aws:SourceIp` with IPv6 ranges in a separate statement if you need it.
4. **False positives.** A `/13` can include addresses from neighbouring countries.
5. **AWS has no country condition key.** For HTTP traffic, prefer AWS WAF geo match or CloudFront geo restriction.

## When to use

Use it in organizations that operate only from Brazil and the US, for production accounts and administrative access. Do not use it for globally distributed teams or accounts that receive calls from international partners.
