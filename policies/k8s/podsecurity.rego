package k8s.podsecurity

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_no_fsgroup[msg] {
    input.spec.securityContext.fsGroup == null
    msg = sprintf("pod %v: fsGroup not set in pod securityContext", [input.metadata.name])
}

deny_no_runasgroup[msg] {
    input.spec.securityContext.runAsGroup == null
    msg = sprintf("pod %v: runAsGroup not set", [input.metadata.name])
}

deny_no_runasuser[msg] {
    input.spec.securityContext.runAsUser == null
    msg = sprintf("pod %v: runAsUser not set", [input.metadata.name])
}

deny_no_seccomp[msg] {
    input.spec.securityContext.seccompProfile.type == "Unconfined"
    msg = sprintf("pod %v: seccomp is Unconfined", [input.metadata.name])
}
