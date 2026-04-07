package k8s.resources

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_no_limits[msg] {
    container := input.spec.containers[_]
    not container.resources.limits
    msg = sprintf("container %v: resource limits not defined", [container.name])
}

deny_no_limits[msg] {
    container := input.spec.containers[_]
    not container.resources.requests
    msg = sprintf("container %v: resource requests not defined", [container.name])
}

deny_no_cpu_limit[msg] {
    container := input.spec.containers[_]
    not container.resources.limits.cpu
    msg = sprintf("container %v: CPU limit not set", [container.name])
}

deny_no_memory_limit[msg] {
    container := input.spec.containers[_]
    not container.resources.limits.memory
    msg = sprintf("container %v: memory limit not set", [container.name])
}

deny_cpu_limit_excessive[msg] {
    container := input.spec.containers[_]
    cpu := container.resources.limits.cpu
    to_number(cpu) > 8
    msg = sprintf("container %v: CPU limit %v exceeds 8 cores", [container.name, cpu])
}

deny_memory_limit_excessive[msg] {
    container := input.spec.containers[_]
    mem := container.resources.limits.memory
    contains(mem, "Gi")
    value := trim_right(mem, "Gi")
    to_number(value) > 16
    msg = sprintf("container %v: memory limit %v exceeds 16Gi", [container.name, mem])
}

deny_no_probes[msg] {
    container := input.spec.containers[_]
    not container.livenessProbe
    not container.readinessProbe
    msg = sprintf("container %v: no liveness or readiness probes", [container.name])
}
