package github.workflows

import future.keywords.contains
import future.keywords.if
import future.keywords.in

deny_unpinned_action[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    action := step.uses
    not contains(action, "@")
    not startswith(action, "./")
    msg = sprintf("step %v: action %v not pinned to a commit SHA or tag", [step.name, action])
}

deny_untrusted_checkout[msg] {
    input.on.workflow_dispatch
    job := input.jobs[_]
    step := job.steps[_]
    step.uses == "actions/checkout@v4"
    step.with["repository"] != "${{ github.repository }}"
    msg = "workflow checks out a different repository; verify trust model"
}

deny_wildcard_permissions[msg] {
    input.permissions == "write-all"
    msg = "workflow uses write-all permissions; scope to least privilege"
}

deny_wildcard_permissions[msg] {
    job := input.jobs[_]
    job.permissions == "write-all"
    msg = sprintf("job %v uses write-all permissions", [job.name])
}

deny_secret_in_env[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    env := step.env
    env["ACTIONS_STEP_DEBUG"] == "true"
    msg = sprintf("step %v: debug mode on; secrets may leak in logs", [step.name])
}

deny_no_verification[msg] {
    job := input.jobs[_]
    step := job.steps[_]
    contains(step.uses, "/")
    not contains(step.uses, "@")
    msg = sprintf("step %v: action %v not version-pinned", [step.name, step.uses])
}

deny_self_hosted_no_isolation[msg] {
    job := input.jobs[_]
    job["runs-on"] == "self-hosted"
    not job.environment
    msg = sprintf("job %v runs on self-hosted runner without environment isolation", [job.name])
}
