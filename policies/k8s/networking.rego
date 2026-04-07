package k8s.networking

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_no_network_policy[msg] {
    input.kind == "Namespace"
    not input.metadata.labels["policy.networking.k8s.io/network-policy"]
    msg = sprintf("namespace %v has no network policy label", [input.metadata.name])
}

# hostPort should only be used when absolutely necessary
deny_host_port[msg] {
    container := input.spec.containers[_]
    container.ports[_].hostPort != 0
    msg = sprintf("container %v uses hostPort", [container.name])
}

# verify no LoadBalancer services without strict session affinity
deny_loadbalancer_no_session_affinity[msg] {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    input.spec.sessionAffinity == "None"
    msg = sprintf("LoadBalancer service %v has no session affinity", [input.metadata.name])
}

# warn about services of type NodePort
deny_nodeport[msg] {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg = sprintf("service %v uses NodePort (consider ClusterIP + ingress)", [input.metadata.name])
}
