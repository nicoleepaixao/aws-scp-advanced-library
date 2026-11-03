# Region restriction: only us-east-1 and sa-east-1

File: [`deny-non-approved-regions.json`](deny-non-approved-regions.json)

Denies every action outside the approved Regions, so nobody creates resources in a Region that is not monitored, budgeted or covered by your compliance scope.

## How it works

- `StringNotEquals aws:RequestedRegion` denies requests to any Region other than `us-east-1` and `sa-east-1`.
- `NotAction` lists **global services** (IAM, STS, Organizations, Route 53, CloudFront, Support, billing and others, following the AWS example). Their API endpoints live in `us-east-1`, so blocking them would break the console and identity.
- `ArnNotLike aws:PrincipalArn` exempts the platform roles (`OrganizationAccountAccessRole`, `AWSControlTowerExecution`, `break-glass-admin`).

## Change the Regions

Edit the list in `aws:RequestedRegion`. Keep `us-east-1` if you use CloudFront, ACM certificates for CloudFront or global services that only exist there.

## Watch out

- New AWS global services may need to be added to `NotAction`.
- Services that call other Regions on your behalf (for example cross-Region replication) run as the service, not as your principal, and keep working.
