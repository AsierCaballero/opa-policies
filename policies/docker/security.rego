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
    msg = "no USER directive (defaults to root)"
}

deny_add_instead_of_copy[msg] {
    lines := input.content
    contains(lines, "ADD ")
    msg = "ADD unpacks archives; prefer COPY"
}

deny_no_tag[msg] {
    image := input.base_image
    not contains(image, ":")
    msg = sprintf("base image %v has no tag (defaults to :latest)", [image])
}

deny_latest_tag[msg] {
    image := input.base_image
    contains(image, ":latest")
    msg = sprintf("base image %v uses :latest", [image])
}

deny_no_healthcheck[msg] {
    lines := input.content
    not contains(lines, "HEALTHCHECK")
    msg = "no HEALTHCHECK instruction"
}

deny_exposed_port_80[msg] {
    lines := input.content
    contains(lines, "EXPOSE 80")
    msg = "EXPOSE 80: consider a higher port (>1024)"
}

deny_no_init[msg] {
    lines := input.content
    not contains(lines, "init")
    contains(lines, "CMD ")
    msg = "no init process (consider tini/dumb-init)"
}

deny_stale_base_image[msg] {
    lines := input.content
    contains(lines, "ubuntu:18.04")
    msg = "ubuntu:18.04 is EOL since April 2023"
}
