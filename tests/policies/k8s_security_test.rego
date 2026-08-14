package k8s.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_privileged_container {
    input := {"spec": {"containers": [{"name": "nginx", "securityContext": {"privileged": true}}], "metadata": {"name": "test"}}}
    deny_privileged[_] with input as input
}

test_nonroot_fails_when_not_set {
    input := {"spec": {"containers": [{"name": "nginx", "securityContext": {}}], "metadata": {"name": "test"}}}
    count(deny_run_as_root) > 0 with input as input
}

test_host_network_detected {
    inp := {"spec": {"hostNetwork": true, "containers": [{"name": "nginx"}], "metadata": {"name": "test"}}}
    data.k8s.security.deny_host_network with input as inp
}

test_readonly_rootfs_notice {
    input := {"spec": {"containers": [{"name": "nginx", "securityContext": {"readOnlyRootFilesystem": false}}], "metadata": {"name": "test"}}}
    deny_no_readonly_rootfs[_] with input as input
}
