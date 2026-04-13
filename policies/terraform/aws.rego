package terraform.aws

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_s3_public_access[msg] {
    resource := input.resource.aws_s3_bucket_public_access_block[_]
    resource.block_public_acls == false
    msg = sprintf("S3 bucket %v: public ACLs not blocked", [resource.id])
}

deny_s3_public_access[msg] {
    resource := input.resource.aws_s3_bucket_public_access_block[_]
    resource.block_public_policy == false
    msg = sprintf("S3 bucket %v: public policies not blocked", [resource.id])
}

deny_security_group_wide_open[msg] {
    resource := input.resource.aws_security_group_rule[_]
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port == 22
    msg = sprintf("security group %v: SSH open to 0.0.0.0/0", [resource.security_group_id])
}

deny_security_group_wide_open[msg] {
    resource := input.resource.aws_security_group_rule[_]
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port == 3389
    msg = sprintf("security group %v: RDP open to 0.0.0.0/0", [resource.security_group_id])
}

deny_security_group_wide_open[msg] {
    resource := input.resource.aws_security_group_rule[_]
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port == 3306
    msg = sprintf("security group %v: MySQL open to 0.0.0.0/0", [resource.security_group_id])
}

deny_iam_wildcard_action[msg] {
    resource := input.resource.aws_iam_role_policy[_]
    contains(resource.policy, "*")
    contains(resource.policy, "Action")
    msg = sprintf("IAM role %v: policy may contain wildcard actions", [resource.name])
}

deny_iam_wildcard_action[msg] {
    resource := input.resource.aws_iam_user_policy[_]
    contains(resource.policy, "\"*\"")
    msg = sprintf("IAM user %v: policy contains wildcard action", [resource.name])
}

deny_unencrypted_ebs[msg] {
    resource := input.resource.aws_ebs_volume[_]
    not resource.encrypted
    msg = sprintf("EBS volume %v: not encrypted", [resource.id])
}

deny_unencrypted_rds[msg] {
    resource := input.resource.aws_db_instance[_]
    not resource.storage_encrypted
    msg = sprintf("RDS instance %v: storage not encrypted", [resource.identifier])
}
