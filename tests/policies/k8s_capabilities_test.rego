package k8s.capabilities

import future.keywords.contains
import future.keywords.if
import future.keywords.in

test_add_cap_sys_admin {
    input := {"spec": {"containers": [{"name": "c1", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}], "metadata": {"name": "test"}}}
    deny_add_capabilities[_] with input as input
}

test_drop_all_not_set {
    input := {"spec": {"containers": [{"name": "c1", "securityContext": {"capabilities": {"add": []}}}], "metadata": {"name": "test"}}}
    deny_no_drop_all[_] with input as input
}
