# Require encryption: TLS for S3 and encrypted storage

File: [`require-encryption.json`](require-encryption.json)

| Statement | Denies |
|---|---|
| `DenyS3WithoutTls` | Any S3 call over plain HTTP (`aws:SecureTransport = false`) |
| `DenyS3PutObjectWithUnapprovedEncryption` | Uploads that **ask** for an encryption type other than SSE-S3 (`AES256`), SSE-KMS (`aws:kms`) or DSSE-KMS. Uploads without the header are allowed: S3 encrypts every new object by default since January 2023. |
| `DenyUnencryptedEbsVolumes` | `ec2:CreateVolume` with `Encrypted = false` |
| `DenyDisablingEbsDefaultEncryption` | Turning off EBS encryption by default (platform roles exempt) |
| `DenyUnencryptedRds` | RDS instances and clusters with `StorageEncrypted = false` |
| `DenyUnencryptedEfs` | EFS file systems with `Encrypted = false` |

## Why the S3 rule checks that the header exists

A condition like `StringNotEqualsIfExists` is **true when the key is missing**, so it would deny every upload that relies on the bucket default encryption, which is most SDK uploads. The policy uses `Null = false` together with `StringNotEquals`, so it only acts when the header is present. The test `test_encryption_s3_put_object_headers` covers this.

## Pair it with

Turn on EBS encryption by default in each Region. With it on, a volume created without the `Encrypted` parameter is encrypted anyway.
