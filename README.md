# opa-policies

[![CI](https://img.shields.io/github/actions/workflow/status/AsierCaballero/opa-policies/ci.yml?label=CI&logo=github)](https://github.com/AsierCaballero/opa-policies/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Policy-as-code library and CLI validator for Kubernetes, Terraform, Docker, and GitHub Actions. Built on [Open Policy Agent](https://www.openpolicyagent.org/).

## Who this is for

Platform and security teams that need **guardrails in CI** before merge: privileged pods, open
security groups, unpinned Actions, root containers. Useful in regulated contexts (finance, pharma, public sector) where I typically engage.

**Limitations:** starting policy pack (~50 rules) — extend per org; not a substitute for runtime admission alone.

**Engagements:** [Calendly](https://calendly.com/asier-caballero) · [Profile](https://github.com/AsierCaballero)

## 30-second demo

```bash
make build
./opa-policies validate examples/k8s/bad-pod.yaml
```

Expected (excerpt):

```text
Policy                  File                        Severity   Status   Message
------                  ----                        --------   ------   -------
k8s/security.rego       examples/k8s/bad-pod.yaml   high       FAIL     container nginx is privileged
k8s/security.rego       examples/k8s/bad-pod.yaml   high       FAIL     container nginx allows running as root
k8s/security.rego       examples/k8s/bad-pod.yaml   high       FAIL     pod nginx-bad uses host network
```

SARIF for CI:

```bash
./opa-policies validate examples/k8s/bad-pod.yaml -f sarif
```

## Overview

opa-policies bundles ~50 Rego policies across four infrastructure domains and provides a CLI to validate your manifests without leaving the terminal.

```
opa-policies validate manifest.yaml
opa-policies list
opa-policies validate examples/k8s/bad-pod.yaml -f sarif
```

## Policy Catalog

### Kubernetes (15 policies)
- Privileged containers, root user, hostNetwork, hostPID
- CPU/memory limits and requests
- ReadOnlyRootFilesystem, liveness/readiness probes
- Network policies, LoadBalancer session affinity, NodePort warnings

### Terraform (15 policies)
- **AWS**: S3 public access, security group rules, IAM wildcards, EBS/RDS encryption
- **Azure**: SQL public access, storage encryption, NSG attachments, VM public IPs
- **GCP**: bucket IAM, uniform access, Cloud SQL exposure, VPC connectors

### GitHub Actions (10 policies)
- Action pinning (SHA/tag), untrusted checkout detection
- write-all permissions, secret leaks in env, self-hosted isolation
- Hardcoded tokens, passwords, and secret values

### Docker (8 policies)
- Root user, ADD vs COPY, untagged/latest base images
- HEALTHCHECK, pip cache, apt-get recommends, secret copy

## Usage

```bash
# Build
make build

# Validate a file (auto-detects type)
./opa-policies validate examples/k8s/bad-pod.yaml

# Table output (default)
./opa-policies validate examples/terraform/bad-aws.tf

# SARIF output (CI integration)
./opa-policies validate examples/github/bad-workflow.yaml -f sarif

# JUnit XML output
./opa-policies validate examples/docker/bad.Dockerfile -f junit

# List available policies
./opa-policies list

# Run tests
make test
```

## Architecture

```
CLI (cobra) → Engine (OPA rego) → Policies (.rego)
                ↓
         Reporter (table/sarif/junit)
```

Policy files are loaded from `./policies/<domain>/` at startup.

## CI Integration

```yaml
# .github/workflows/validate.yml
- run: ./opa-policies validate infra/ -f sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```
