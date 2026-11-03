"""What each SCP blocks and what it must keep working."""
from scp_eval import is_denied, load

ADMIN = "arn:aws:iam::111122223333:role/OrganizationAccountAccessRole"
DEV = "arn:aws:iam::111122223333:role/developer"
ROOT_USER = "arn:aws:iam::111122223333:root"
INSTANCE = "arn:aws:ec2:us-east-1:111122223333:instance/*"
VOLUME = "arn:aws:ec2:us-east-1:111122223333:volume/*"
GOOD_TAGS = {"aws:RequestTag/owner": "nicole", "aws:RequestTag/cost-center": "platform",
             "aws:RequestTag/environment": "prod"}


# region-restriction
REGION = load("region-restriction/deny-non-approved-regions.json")


def test_region_blocks_unapproved_region():
    assert is_denied(REGION, "ec2:RunInstances", context={
        "aws:RequestedRegion": "eu-west-1", "aws:PrincipalArn": DEV})


def test_region_allows_approved_regions():
    for region in ("us-east-1", "sa-east-1"):
        assert not is_denied(REGION, "ec2:RunInstances", context={
            "aws:RequestedRegion": region, "aws:PrincipalArn": DEV})


def test_region_keeps_global_services_working():
    for action in ("iam:CreateRole", "sts:AssumeRole", "route53:ChangeResourceRecordSets",
                   "cloudfront:CreateDistribution", "support:DescribeCases"):
        assert not is_denied(REGION, action, context={
            "aws:RequestedRegion": "us-east-1", "aws:PrincipalArn": DEV})
        assert not is_denied(REGION, action, context={
            "aws:RequestedRegion": "eu-west-1", "aws:PrincipalArn": DEV})


def test_region_admin_role_is_exempt():
    assert not is_denied(REGION, "ec2:RunInstances", context={
        "aws:RequestedRegion": "eu-west-1", "aws:PrincipalArn": ADMIN})


# iam-lockdown
IAM = load("iam-lockdown/iam-lockdown.json")


def test_iam_blocks_users_and_access_keys():
    for action in ("iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile"):
        assert is_denied(IAM, action, context={"aws:PrincipalArn": DEV})
        assert not is_denied(IAM, action, context={"aws:PrincipalArn": ADMIN})


def test_iam_protects_platform_roles_only():
    protected = "arn:aws:iam::111122223333:role/OrganizationAccountAccessRole"
    app_role = "arn:aws:iam::111122223333:role/my-app"
    assert is_denied(IAM, "iam:AttachRolePolicy", protected, {"aws:PrincipalArn": DEV})
    assert not is_denied(IAM, "iam:AttachRolePolicy", app_role, {"aws:PrincipalArn": DEV})


def test_iam_protects_security_baseline():
    for action in ("cloudtrail:StopLogging", "guardduty:DeleteDetector",
                   "config:StopConfigurationRecorder", "securityhub:DisableSecurityHub"):
        assert is_denied(IAM, action, context={"aws:PrincipalArn": DEV})
    assert not is_denied(IAM, "cloudtrail:LookupEvents", context={"aws:PrincipalArn": DEV})


def test_iam_no_one_leaves_the_organization():
    assert is_denied(IAM, "organizations:LeaveOrganization", context={"aws:PrincipalArn": ADMIN})


def test_iam_blocks_root_user_in_member_accounts():
    assert is_denied(IAM, "s3:ListAllMyBuckets", context={"aws:PrincipalArn": ROOT_USER})
    assert not is_denied(IAM, "s3:ListAllMyBuckets", context={"aws:PrincipalArn": DEV})


# require-encryption
ENC = load("require-encryption/require-encryption.json")


def test_encryption_blocks_s3_without_tls():
    assert is_denied(ENC, "s3:GetObject", context={"aws:SecureTransport": "false"})
    assert not is_denied(ENC, "s3:GetObject", context={"aws:SecureTransport": "true"})


def test_encryption_s3_put_object_headers():
    tls = {"aws:SecureTransport": "true"}
    assert not is_denied(ENC, "s3:PutObject", context=tls)  # bucket default encryption
    assert not is_denied(ENC, "s3:PutObject", context={**tls, "s3:x-amz-server-side-encryption": "aws:kms"})
    assert is_denied(ENC, "s3:PutObject", context={**tls, "s3:x-amz-server-side-encryption": "none"})


def test_encryption_blocks_unencrypted_storage():
    assert is_denied(ENC, "ec2:CreateVolume", context={"ec2:Encrypted": "false"})
    assert not is_denied(ENC, "ec2:CreateVolume", context={"ec2:Encrypted": "true"})
    assert is_denied(ENC, "rds:CreateDBInstance", context={"rds:StorageEncrypted": "false"})
    assert not is_denied(ENC, "rds:CreateDBCluster", context={"rds:StorageEncrypted": "true"})
    assert is_denied(ENC, "elasticfilesystem:CreateFileSystem",
                     context={"elasticfilesystem:Encrypted": "false"})


def test_encryption_default_ebs_encryption_is_protected():
    assert is_denied(ENC, "ec2:DisableEbsEncryptionByDefault", context={"aws:PrincipalArn": DEV})
    assert not is_denied(ENC, "ec2:DisableEbsEncryptionByDefault", context={"aws:PrincipalArn": ADMIN})


# tag-enforcement
TAGS = load("tag-enforcement/require-tags.json")


def test_tags_allow_create_with_all_tags():
    assert not is_denied(TAGS, "ec2:RunInstances", INSTANCE, GOOD_TAGS)
    assert not is_denied(TAGS, "ec2:RunInstances", VOLUME, GOOD_TAGS)


def test_tags_block_missing_or_invalid_tags():
    for missing in GOOD_TAGS:
        context = {k: v for k, v in GOOD_TAGS.items() if k != missing}
        assert is_denied(TAGS, "ec2:RunInstances", INSTANCE, context), missing
    assert is_denied(TAGS, "ec2:RunInstances", INSTANCE,
                     {**GOOD_TAGS, "aws:RequestTag/environment": "test"})


def test_tags_only_apply_to_tagged_resource_types():
    subnet = "arn:aws:ec2:us-east-1:111122223333:subnet/*"
    assert not is_denied(TAGS, "ec2:RunInstances", subnet, {})


def test_tags_cannot_be_removed():
    assert is_denied(TAGS, "ec2:DeleteTags", context={"aws:TagKeys": ["owner"], "aws:PrincipalArn": DEV})
    assert not is_denied(TAGS, "ec2:DeleteTags", context={"aws:TagKeys": ["team"], "aws:PrincipalArn": DEV})


# imdsv2-enforcement
IMDS = load("imdsv2-enforcement/enforce-imdsv2.json")


def test_imdsv2_required():
    ok = {"ec2:MetadataHttpTokens": "required", "ec2:MetadataHttpPutResponseHopLimit": "2"}
    assert not is_denied(IMDS, "ec2:RunInstances", INSTANCE, ok)
    assert is_denied(IMDS, "ec2:RunInstances", INSTANCE, {**ok, "ec2:MetadataHttpTokens": "optional"})
    assert is_denied(IMDS, "ec2:RunInstances", INSTANCE, {**ok, "ec2:MetadataHttpPutResponseHopLimit": "3"})


# geo-restriction
GEO = load("geo-restriction/deny-access-from-non-allowed-countries.json")
ALLOWED_IP = GEO["Statement"][0]["Condition"]["NotIpAddress"]["aws:SourceIp"][0].split("/")[0]


def test_geo_blocks_unknown_country_ip():
    assert is_denied(GEO, "s3:ListBucket", context={
        "aws:SourceIp": "203.0.113.10", "aws:ViaAWSService": "false"})


def test_geo_allows_listed_ip_service_calls_and_vpc_endpoints():
    assert not is_denied(GEO, "s3:ListBucket", context={"aws:SourceIp": ALLOWED_IP})
    assert not is_denied(GEO, "s3:ListBucket", context={
        "aws:SourceIp": "203.0.113.10", "aws:ViaAWSService": "true"})
    assert not is_denied(GEO, "s3:ListBucket", context={
        "aws:SourceIp": "203.0.113.10", "aws:SourceVpce": "vpce-0abc"})
