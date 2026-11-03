# IAM lockdown: no long-lived users, protected roles and security baseline

File: [`iam-lockdown.json`](iam-lockdown.json)

| Statement | What it blocks | Why |
|---|---|---|
| `DenyLongLivedIamUserCredentials` | `iam:CreateUser`, `iam:CreateAccessKey`, console passwords | People use SSO (IAM Identity Center) and workloads use roles. Access keys are the most common leaked credential. |
| `ProtectPlatformRoles` | Changing or deleting `OrganizationAccountAccessRole`, `AWSControlTowerExecution`, `break-glass-admin` and SSO roles (`aws-reserved/*`) | A compromised developer role cannot take over or remove the roles the platform team uses to recover the account. |
| `ProtectSecurityBaseline` | Stopping or deleting CloudTrail, AWS Config, GuardDuty, Security Hub and IAM Access Analyzer | The first thing an attacker does is turn off the logs. |
| `DenyLeavingOrganization` | `organizations:LeaveOrganization` | An account outside the organization loses every SCP. No exception, not even for admins. |
| `DenyRootUser` | Any action by the root user of member accounts | Root is for the few tasks that require it; use the management account to unlock it when needed. |

Every statement except `DenyLeavingOrganization` and `DenyRootUser` exempts the platform roles through `ArnNotLike aws:PrincipalArn`.

## Before attaching

- Make sure no pipeline still uses IAM user access keys.
- SCPs never affect the management account, so its root user is not covered.
- Some root-only tasks (for example closing the account) need the SCP detached temporarily, or AWS centralized root access.
