package terraform.aws

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_s3_public_access_blocked {
    input := {"resource": {"aws_s3_bucket_public_access_block": [{"id": "my-bucket", "block_public_acls": false}]}}
    deny_s3_public_access[_] with input as input
}

test_security_group_ssh_open {
    input := {"resource": {"aws_security_group_rule": [{"security_group_id": "sg-123", "from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]}}
    deny_security_group_wide_open[_] with input as input
}

test_iam_wildcard_detected {
    input := {"resource": {"aws_iam_role_policy": [{"name": "my-role", "policy": "{\"Action\": \"*\"}"}]}}
    deny_iam_wildcard_action[_] with input as input
}

test_ebs_encryption {
    input := {"resource": {"aws_ebs_volume": [{"id": "vol-123"}]}}
    deny_unencrypted_ebs[_] with input as input
}
