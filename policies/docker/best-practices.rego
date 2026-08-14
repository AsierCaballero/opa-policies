package docker.security

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# warn about missing WORKDIR
deny_no_workdir[msg] {
    lines := input.content
    not contains(lines, "WORKDIR ")
    msg = "no WORKDIR set; files land in /"
}

# warn about COPY of secrets
deny_copying_dotenv[msg] {
    lines := input.content
    contains(lines, "COPY .env")
    msg = "COPY .env may leak secrets into the image"
}

# RUN pip without --no-cache-dir
deny_pip_no_cache[msg] {
    lines := input.content
    contains(lines, "pip install")
    not contains(lines, "--no-cache-dir")
    msg = "pip install without --no-cache-dir increases image size"
}

# RUN apt-get without no-install-recommends
deny_apt_no_recommends[msg] {
    lines := input.content
    contains(lines, "apt-get install")
    not contains(lines, "no-install-recommends")
    msg = "apt-get install without --no-install-recommends pulls unnecessary packages"
}

# multiple FROM statements for multistage but no COPY --from=
deny_multistage_missing_copy[msg] {
    lines := input.content
    froms := [line | line := split(lines, "\n")[_]; startswith(line, "FROM ")]
    count(froms) > 1
    not contains(lines, "COPY --from=")
    msg = "multiple FROM stages but no COPY --from= detected"
}
