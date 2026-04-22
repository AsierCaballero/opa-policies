package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_root_user[msg] {
    lines := input.content
    contains(lines, "USER root")
    msg = "container runs as root user"
}

deny_root_user[msg] {
    lines := input.content
    not contains(lines, "USER ")
    msg = "no USER directive found (defaults to root)"
}

deny_add[msg] {
    lines := input.content
    contains(lines, "ADD ")
    # ADD unpacks archives automatically; prefer COPY
    msg = "use COPY instead of ADD unless archive auto-extraction is intentional"
}

deny_no_tag[msg] {
    lines := input.content
    match := regex.find_n("FROM\\s+([^\\s]+)", lines, -1)
    some m
    image := match[m]
    not contains(image, ":")
    msg = sprintf("base image %v has no tag (uses :latest)", [image])
}

deny_latest_tag[msg] {
    lines := input.content
    match := regex.find_n("FROM\\s+([^\\s]+)", lines, -1)
    some m
    image := match[m]
    contains(image, ":latest")
    msg = sprintf("base image %v uses :latest tag", [image])
}

deny_no_healthcheck[msg] {
    lines := input.content
    not contains(lines, "HEALTHCHECK ")
    msg = "no HEALTHCHECK instruction found"
}

deny_exposed_port_80[msg] {
    lines := input.content
    contains(lines, "EXPOSE 80")
    msg = "EXPOSE 80: consider using higher port (>1024)"
}

deny_multistage_copy_as_root[msg] {
    lines := input.content
    contains(lines, "COPY --from=")
    not contains(lines, "USER ")
    msg = "multistage COPY without USER: files owned by root"
}

deny_no_init[msg] {
    lines := input.content
    not contains(lines, "init")
    contains(lines, "CMD ")
    msg = "no init process specified (consider tini or dumb-init)"
}

deny_stale_base_image[msg] {
    lines := input.content
    contains(lines, "ubuntu:18.04")
    msg = "ubuntu:18.04 is EOL since 2023"
}
