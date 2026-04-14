package terraform.gcp

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_public_bucket[msg] {
    resource := input.resource.google_storage_bucket_iam_member[_]
    resource.member == "allUsers"
    msg = sprintf("bucket %v: public access to allUsers", [resource.bucket])
}

deny_public_bucket[msg] {
    resource := input.resource.google_storage_bucket_iam_member[_]
    resource.member == "allAuthenticatedUsers"
    msg = sprintf("bucket %v: public access to allAuthenticatedUsers", [resource.bucket])
}

deny_public_bucket[msg] {
    resource := input.resource.google_storage_bucket[_]
    resource.uniform_bucket_level_access == false
    msg = sprintf("bucket %v: uniform bucket-level access disabled", [resource.name])
}

deny_public_bucket[msg] {
    resource := input.resource.google_storage_bucket[_]
    not resource.uniform_bucket_level_access
    msg = sprintf("bucket %v: uniform bucket-level access not set", [resource.name])
}

deny_public_sql[msg] {
    resource := input.resource.google_sql_database_instance[_]
    resource.settings[0].ip_configuration[0].ipv4_enabled == true
    msg = sprintf("Cloud SQL %v: IPv4 public access enabled", [resource.name])
}

deny_public_sql[msg] {
    resource := input.resource.google_sql_database_instance[_]
    resource.settings[0].ip_configuration[0].authorized_networks[_].value == "0.0.0.0/0"
    msg = sprintf("Cloud SQL %v: open to 0.0.0.0/0", [resource.name])
}

deny_no_vpc_connector[msg] {
    resource := input.resource.google_cloud_function[_]
    not resource.vpc_connector
    msg = sprintf("cloud function %v: no VPC connector", [resource.name])
}
