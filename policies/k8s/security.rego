package k8s.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# containers running as root
deny_privileged[msg] {
    container := input.spec.containers[_]
    container.securityContext.privileged == true
    msg = sprintf("container %v is privileged", [container.name])
}

deny_run_as_root[msg] {
    container := input.spec.containers[_]
    sc := container.securityContext
    sc.runAsNonRoot == false
    msg = sprintf("container %v allows running as root", [container.name])
}

deny_run_as_root[msg] {
    container := input.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg = sprintf("container %v: runAsNonRoot not set", [container.name])
}

deny_host_network[msg] {
    input.spec.hostNetwork == true
    msg = sprintf("pod %v uses host network", [input.metadata.name])
}

deny_host_pid[msg] {
    input.spec.hostPID == true
    msg = sprintf("pod %v shares host PID namespace", [input.metadata.name])
}

deny_no_readonly_rootfs[msg] {
    container := input.spec.containers[_]
    container.securityContext.readOnlyRootFilesystem == false
    msg = sprintf("container %v: rootfs not read-only", [container.name])
}

deny_no_readonly_rootfs[msg] {
    container := input.spec.containers[_]
    not container.securityContext.readOnlyRootFilesystem
    msg = sprintf("container %v: readOnlyRootFilesystem not set", [container.name])
}
