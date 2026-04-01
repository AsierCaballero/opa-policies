# opa-policies

Policy-as-code library and CLI validator for Kubernetes, Terraform, Docker, and GitHub Actions. Built on [Open Policy Agent](https://www.openpolicyagent.org/).

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
