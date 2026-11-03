# IMDSv2 enforcement

File: [`enforce-imdsv2.json`](enforce-imdsv2.json)

| Statement | Denies |
|---|---|
| `RequireIMDSv2OnRunInstances` | Launching an instance without `HttpTokens=required` |
| `LimitMetadataHopLimitOnRunInstances` | Launching with a metadata hop limit greater than 2 |

## Why

IMDSv1 answers any GET request, so an SSRF in the application can read the instance role credentials. IMDSv2 requires a session token obtained with a PUT, which SSRF payloads usually cannot send. A hop limit of 2 lets containers on the instance reach the metadata service and stops it one network hop further.

## What it does not cover

Instances that already exist. Use `aws ec2 modify-instance-metadata-options --http-tokens required` on them, and set the account default with `aws ec2 modify-instance-metadata-defaults`.
