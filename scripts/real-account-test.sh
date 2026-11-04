#!/usr/bin/env bash
# Real-account test: attaches each SCP to a sandbox member account, one at a time,
# and checks what is denied and what still works. Every call is a --dry-run or
# targets a resource that does not exist, so nothing is created and nothing costs money.
#
#   ACCOUNT_ID=<sandbox account> MGMT_PROFILE=<management profile> \
#   MEMBER_PROFILE=<admin profile in the sandbox account> ./scripts/real-account-test.sh
#
# Never run it against an account with workloads: while a policy is attached, it applies
# to every principal in the account except the exempt admin roles.
set -u
ACC=${ACCOUNT_ID:?set ACCOUNT_ID}; LIB=$(cd "$(dirname "$0")/../policies" && pwd)
MG="--profile ${MGMT_PROFILE:?set MGMT_PROFILE}"; MP=${MEMBER_PROFILE:?set MEMBER_PROFILE}; ROLE=scp-test-role
declare -A PID

cleanup() {
  echo "== cleanup"
  for k in "${!PID[@]}"; do
    aws organizations detach-policy $MG --policy-id "${PID[$k]}" --target-id $ACC 2>/dev/null
    aws organizations delete-policy $MG --policy-id "${PID[$k]}" && echo "SCP $k deleted"
  done
  aws iam delete-user --profile $MP --user-name scp-test-should-not-exist 2>/dev/null && echo "!! test user deleted"
  aws iam detach-role-policy --profile $MP --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
  aws iam delete-role --profile $MP --role-name $ROLE 2>/dev/null && echo "role $ROLE deleted"
}
trap cleanup EXIT

echo "== test role (not exempt from the SCPs)"
aws iam create-role --profile $MP --role-name $ROLE --query Role.Arn --output text \
  --assume-role-policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::$ACC:root\"},\"Action\":\"sts:AssumeRole\"}]}"
aws iam attach-role-policy --profile $MP --role-name $ROLE --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
sleep 15
creds() {
  read -r AK SK ST < <(aws sts assume-role --profile $MP --role-arn arn:aws:iam::$ACC:role/$ROLE \
    --role-session-name scp-test --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
  export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$ST AWS_DEFAULT_REGION=us-east-1
}
T() { env -u AWS_PROFILE AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN=$AWS_SESSION_TOKEN aws "$@" 2>&1; }
creds
AMI=$(T ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)
TAGS='ResourceType=instance,Tags=[{Key=owner,Value=nicole},{Key=cost-center,Value=platform},{Key=environment,Value=prod}] ResourceType=volume,Tags=[{Key=owner,Value=nicole},{Key=cost-center,Value=platform},{Key=environment,Value=prod}]'
RUN="ec2 run-instances --dry-run --image-id $AMI --instance-type t3.micro"

# policy|expected with the SCP|description|command
TESTS=(
"region|DENY|EC2 in eu-west-1|ec2 describe-vpcs --region eu-west-1"
"region|ALLOW|EC2 in us-east-1|ec2 describe-vpcs --region us-east-1"
"region|ALLOW|IAM (global service)|iam list-roles --max-items 1"
"iam|DENY|create an IAM user|iam create-user --user-name scp-test-should-not-exist"
"iam|DENY|change OrganizationAccountAccessRole|iam delete-role-policy --role-name OrganizationAccountAccessRole --policy-name nao-existe"
"iam|ALLOW|change a regular role|iam delete-role-policy --role-name scp-test-role --policy-name nao-existe"
"iam|DENY|stop CloudTrail|cloudtrail stop-logging --name nao-existe"
"enc|DENY|unencrypted EBS volume|ec2 create-volume --dry-run --size 1 --availability-zone us-east-1a --no-encrypted"
"enc|ALLOW|encrypted EBS volume|ec2 create-volume --dry-run --size 1 --availability-zone us-east-1a --encrypted"
"enc|DENY|disable EBS default encryption|ec2 disable-ebs-encryption-by-default --dry-run"
"tags|DENY|EC2 without tags|$RUN --metadata-options HttpTokens=required"
"tags|ALLOW|EC2 with owner, cost-center and environment|$RUN --metadata-options HttpTokens=required --tag-specifications $TAGS"
"imds|DENY|EC2 with IMDSv1|$RUN --metadata-options HttpTokens=optional"
"imds|ALLOW|EC2 with IMDSv2|$RUN --metadata-options HttpTokens=required,HttpPutResponseHopLimit=2"
)
classify() {
  case "$1" in
    *DryRunOperation*|*NoSuchEntity*|*TrailNotFound*|*TrailNotFoundException*) echo ALLOW ;;
    *AccessDenied*|*UnauthorizedOperation*|*"explicit deny"*) echo DENY ;;
    *error*|*Error*) echo "ERROR: $(echo "$1" | head -c 160)" ;;
    *) echo ALLOW ;;
  esac
}
run() { # $1 = policy key, or "" for the baseline
  local fail=0 k exp desc cmd got want r t
  for t in "${TESTS[@]}"; do
    IFS='|' read -r k exp desc cmd <<<"$t"
    [ -n "$1" ] && [ "$k" != "$1" ] && continue
    got=$(classify "$(T $cmd)")
    want=$exp; [ -z "$1" ] && want=ALLOW
    [ "$got" = "$want" ] && r=OK || { r=FAIL; fail=1; }
    printf '  %-6s %-5s expected %-5s got %-5s %s\n' "$r" "$k" "$want" "$got" "$desc"
  done
  return $fail
}

echo "== baseline (no test SCP attached: everything must pass)"
run "" ; T iam delete-user --user-name scp-test-should-not-exist >/dev/null

declare -A FILE=([region]=region-restriction/deny-non-approved-regions.json [iam]=iam-lockdown/iam-lockdown.json
  [enc]=require-encryption/require-encryption.json [tags]=tag-enforcement/require-tags.json [imds]=imdsv2-enforcement/enforce-imdsv2.json)
TOTAL=0
for k in region iam enc tags imds; do
  doc=$(python3 -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1])),separators=(',',':')))" "$LIB/${FILE[$k]}")
  PID[$k]=$(aws organizations create-policy $MG --type SERVICE_CONTROL_POLICY --name "scp-test-$k" \
    --description "temporary test" --content "$doc" --query Policy.PolicySummary.Id --output text)
  aws organizations attach-policy $MG --policy-id "${PID[$k]}" --target-id $ACC
  echo "== SCP $k attached (${PID[$k]}), waiting for propagation"; sleep 45; creds
  run "$k" || TOTAL=1
  T iam delete-user --user-name scp-test-should-not-exist >/dev/null 2>&1
  aws organizations detach-policy $MG --policy-id "${PID[$k]}" --target-id $ACC
  aws organizations delete-policy $MG --policy-id "${PID[$k]}"; unset "PID[$k]"
  sleep 20
done
[ $TOTAL = 0 ] && echo "== RESULT: every SCP behaved as expected" || echo "== RESULT: at least one check failed"
