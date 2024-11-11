<p align="center"> 
  <img alt="Logo" src="assets/torch-banner.png" height="400">
</p>  

<div align="center">

## Keep your secrets safe.

[![Go Report Card](https://goreportcard.com/badge/github.com/torchsecurity/torch-secret-analyzer)](https://goreportcard.com/report/github.com/torchsecurity/torch-secret-analyzer)
[![License](https://img.shields.io/badge/license-AGPL--3.0-brightgreen)](/LICENSE)

</div>

---

# About Torch Secrets Analyzer

Torch Secrets Analyzer is a tool that helps analyze access to secrets stored in a secrets manager.

It answers questions like:
- Who can access a certain secret in my secrets manager?
- Who actually pulled that secret in a certain timeframe?
- Which of my services (e.g. Lambdas, K8s) are using which secret?

## Supported Secrets Managers
- AWS Secrets Manager
- HashiCorp Vault (coming soon)

# Installation 🛠️

### Brew

```bash
brew tap torchsecurity/torch
brew install torchsecurity/torch/torch
```

### Install via `go install`

If you have Go installed, you can install Torch with:

```bash
go install github.com/torchsecurity/torch-secret-analyzer/cmd/torch@latest
```

# AWS Secrets Manager

## Configuration

Torch Secrets Analyzer uses your local AWS profile to access AWS Secrets Manager. It requires no additional permissions or configuration.

### Check AWS profile

To check the AWS profile under which the tool runs, run the command:

```bash
torch aws auth print
```

### Configure a new AWS profile (or an existing one)

Torch Secrets Analyzer supports using both credential and SSO profiles.

Configure a credential profile:

```bash
torch aws auth config [--profile]
```

Configure an SSO profile:

```bash
torch aws auth config sso [--profile]
```

## Analyze actual access to a secret

Torch analyzes AWS Cloudtrail events and crosses information with AWS Secrets Manager to identify who are the "consumers" of a given secret in a given timeframe.

Run the following command to see the people and services that accessed a certain secret:

```bash
torch aws consumers list-actual --secret-id <your-secret-id> [--region <aws-region>] [--profile <your-local-aws-profile-to-use>] [--days-back <14>]
```

Expected output:

```bash
Listing all actual consumers of the secret based on AWS CloudTrail Events, filtering for read events in the last 14 days...

Human:
* user:admin (last read on 2024-10-02T13:17:48Z)

Machine:
* eks:billing-svc (last read on 2024-10-13T01:25:07Z)
* lambda:stripeAuditLogs (last read on 2024-10-12T23:13:31Z)
```

## Analyze permissions to pull a secret

Torch analyzes and correlates data across AWS IAM and AWS Secrets Manager to identify which users and services have permission to access a certain secret.

This feature is coming soon

# Hashicorp Value

This feature is coming Soon

# Contributing :heart:

Contributions are very welcome! Please see our [contribution guidelines first](CONTRIBUTING.md).

# About Torch Security

We're building the future of secrets management. Does that pique your interest?

Follow us on [LinkedIn](https://www.linkedin.com/company/torchsec) for exciting updates, or [📧 let's connect](mailto:hello@torch.security)


