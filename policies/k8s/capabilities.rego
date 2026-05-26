package k8s.capabilities

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_add_capabilities[msg] {
    container := input.spec.containers[_]
    caps := container.securityContext.capabilities.add
    caps[_] == "SYS_ADMIN"
    msg = sprintf("container %v: SYS_ADMIN capability added", [container.name])
}

deny_add_capabilities[msg] {
    container := input.spec.containers[_]
    caps := container.securityContext.capabilities.add
    caps[_] == "NET_ADMIN"
    msg = sprintf("container %v: NET_ADMIN capability added", [container.name])
}

deny_add_capabilities[msg] {
    container := input.spec.containers[_]
    caps := container.securityContext.capabilities.add
    caps[_] == "SYS_PTRACE"
    msg = sprintf("container %v: SYS_PTRACE capability added", [container.name])
}

deny_no_drop_all[msg] {
    container := input.spec.containers[_]
    not container.securityContext.capabilities.drop[_] == "ALL"
    msg = sprintf("container %v: not dropping all capabilities", [container.name])
}
