# Tag enforcement: owner, cost-center and environment

File: [`require-tags.json`](require-tags.json)

New EC2 instances, EBS volumes, RDS instances and clusters, and Lambda functions must be created with three tags:

| Tag | Rule |
|---|---|
| `owner` | required |
| `cost-center` | required |
| `environment` | required, one of `dev`, `staging`, `prod` |

`DenyRemovingRequiredTags` stops anyone except the platform roles from deleting these tags later.

## How it works

`Null aws:RequestTag/<key> = true` denies the create call when the tag is missing in the request. The `Resource` element limits the rule to the resource types above, so `ec2:RunInstances` still works for the subnet, security group and network interface it also touches.

With `ec2:RunInstances`, tag both the instance and its volumes:

```bash
aws ec2 run-instances ... \
  --tag-specifications \
  'ResourceType=instance,Tags=[{Key=owner,Value=nicole},{Key=cost-center,Value=platform},{Key=environment,Value=prod}]' \
  'ResourceType=volume,Tags=[{Key=owner,Value=nicole},{Key=cost-center,Value=platform},{Key=environment,Value=prod}]'
```

## Watch out

Tag keys in conditions are case sensitive. Pair this SCP with an AWS Organizations **tag policy** to standardize the case and allowed values across all services.
