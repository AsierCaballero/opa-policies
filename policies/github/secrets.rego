package github.secrets

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_hardcoded_secret[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    env := object.get(step, "env", {})
    key := object.keys(env)[_]
    val := env[key]
    contains(lower(key), "token")
    not contains(val, "${{ secrets.")
    msg = sprintf("step %v: env var %v may contain a hardcoded token", [step.name, key])
}

deny_hardcoded_secret[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    env := object.get(step, "env", {})
    key := object.keys(env)[_]
    val := env[key]
    contains(lower(key), "password")
    not contains(val, "${{ secrets.")
    msg = sprintf("step %v: env var %v may contain a hardcoded password", [step.name, key])
}

deny_hardcoded_secret[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    env := object.get(step, "env", {})
    key := object.keys(env)[_]
    val := env[key]
    contains(lower(key), "secret")
    not contains(val, "${{ secrets.")
    msg = sprintf("step %v: env var %v may be a secret value", [step.name, key])
}

deny_github_token_in_env[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    env := object.get(step, "env", {})
    env["GITHUB_TOKEN"] != "${{ secrets.GITHUB_TOKEN }}"
    msg = sprintf("step %v: GITHUB_TOKEN exposed in env block", [step.name])
}
