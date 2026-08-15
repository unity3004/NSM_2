# Product Requirements Document
## Vaultis — Enterprise Secrets Management Platform

**Document Owner:** Principal Product Manager, Security Platform
**Status:** Draft v1.0 — For Cross-Functional Review
**Classification:** Internal — Confidential

---

## 1. Vision

Every modern enterprise runs on secrets — API keys, database credentials, TLS certificates, encryption keys, tokens, and service-to-service identities — scattered across clouds, CI/CD pipelines, containers, and legacy systems. When secrets sprawl unmanaged, they become the single largest attack surface in the enterprise: hardcoded in source control, logged in plaintext, shared over Slack, and never rotated.

**Vaultis** will be the trust fabric of the modern enterprise: a unified, identity-aware platform for securing, storing, brokering, and auditing every secret and every machine identity across any cloud, any runtime, and any team — with zero standing secrets as the default posture, not the exception.

Our vision is a world where developers never see a long-lived credential, security teams have real-time visibility into every access event, and compliance is a byproduct of normal operation rather than a quarterly fire drill. Vaultis will be to secrets what identity providers became to human authentication — the default, trusted, non-negotiable layer every system authenticates through.

---

## 2. Goals

**Business Goals**
- Establish Vaultis as a top-3 secrets management platform within 24 months of GA, measured by paid enterprise logo count.
- Achieve $50M ARR within 3 years through a usage-based + tiered enterprise licensing model.
- Land-and-expand motion: start with secrets storage, expand into PKI, encryption-as-a-service, and machine identity (workload identity federation).
- Achieve SOC 2 Type II, ISO 27001, and FedRAMP Moderate certification within 18 months to unlock regulated industries (finance, healthcare, government).

**Product Goals**
- Provide a single control plane for secrets across AWS, Azure, GCP, on-prem, and Kubernetes.
- Reduce time-to-first-secret for a new developer from hours to under 5 minutes.
- Eliminate long-lived static credentials via dynamic secrets and short-lived tokens by default.
- Provide sub-50ms p99 latency for secret read operations at the edge/regional layer.
- Deliver an audit trail that is tamper-evident, queryable, and exportable to any SIEM within seconds of the event.

**User Goals**
- Developers: retrieve secrets programmatically without ever handling raw credentials or managing rotation manually.
- Security teams: enforce least-privilege access policies centrally and detect anomalous access in real time.
- Platform/DevOps teams: integrate secrets management into CI/CD and infrastructure-as-code with minimal friction.
- Auditors/Compliance: generate evidence for audits (SOC 2, PCI-DSS, HIPAA) with a few clicks, not weeks of log-scraping.

---

## 3. Non-Goals

To maintain focus and avoid scope creep, the following are explicitly **out of scope** for v1 (GA) and clearly called out to stakeholders:

- **Not a full Identity Provider (IdP)/SSO replacement.** Vaultis will integrate with Okta, Azure AD, Ping, etc., but will not replace human workforce identity/SSO.
- **Not a general-purpose configuration management tool.** Vaultis stores secrets and manages identity-based access, not application configuration or feature flags.
- **Not a SIEM.** We emit audit logs and integrate with SIEMs (Splunk, Datadog, Sentinel) but will not build log analytics/dashboarding as a core product surface in v1.
- **Not a password manager for end-user/human consumer use cases.** This is a machine-and-service-oriented enterprise platform, not a browser extension for personal password storage.
- **No blockchain/crypto-wallet key management in v1.** HSM-backed key management for traditional PKI/encryption use cases only; crypto-asset custody is deferred to Future Scope.
- **No on-by-default multi-region active-active writes in v1.** Initial release supports active-passive DR with regional read replicas; active-active is a fast-follow.
- **No custom plugin marketplace/third-party plugin SDK in v1.** We ship first-party integrations only at GA; a partner SDK is Future Scope.

---

## 4. Target Users

| Segment | Description | Why They Need Vaultis |
|---|---|---|
| **Platform/Infrastructure Engineering Teams** | Own Kubernetes, CI/CD, cloud infra for the org | Need centralized secrets injection into pipelines and clusters without secret sprawl |
| **Application Developers** | Build and ship services daily | Need frictionless, secure secret retrieval in code without slowing down velocity |
| **Security Engineering / AppSec** | Own org-wide security posture | Need policy enforcement, anomaly detection, and revocation capability |
| **Compliance & Risk / Internal Audit** | Own regulatory obligations | Need continuous, exportable audit evidence and access reviews |
| **SRE / Incident Response** | On-call for production reliability and security incidents | Need instant secret rotation/revocation during a breach ("break glass") |
| **CISOs / VP Engineering (Economic Buyers)** | Own budget and risk tolerance | Need a defensible, auditable, board-reportable secrets strategy |

**Primary Company Profile:** Mid-market to enterprise organizations (500–50,000+ employees) with multi-cloud or hybrid infrastructure, regulated or security-conscious industries (fintech, healthcare, SaaS, government contractors), and mature DevOps/platform engineering practices.

---

## 5. User Personas

### Persona 1: Priya Nair — Platform Engineering Lead
- **Role:** Leads a platform team of 8 supporting 200+ engineers across 40 microservices.
- **Goals:** Standardize secrets access across Kubernetes and Terraform-provisioned infra; reduce on-call pages related to expired credentials.
- **Pain Points:** Secrets currently live in a patchwork of cloud-native secret managers, environment variables, and one legacy on-prem Vault cluster nobody wants to touch. Rotation is manual and often skipped.
- **Success Looks Like:** One control plane, Terraform provider + Kubernetes CSI driver adopted org-wide, zero manual rotations.

### Persona 2: Marcus Webb — Senior Backend Developer
- **Role:** Ships features for a payments microservice; not a security specialist.
- **Goals:** Get a database credential or API key into his service with minimal ceremony; not be blocked by security review for routine work.
- **Pain Points:** Currently has to file a ticket to security to get a new credential provisioned, which takes 2 days.
- **Success Looks Like:** Self-service, policy-gated secret access via SDK/CLI in under 5 minutes, with automatic rotation he never has to think about.

### Persona 3: Elena Fischer — Director of Security Engineering (Economic Buyer)
- **Role:** Owns security tooling budget and reports to the CISO.
- **Goals:** Demonstrable reduction in credential-related risk; pass SOC 2 and PCI-DSS audits without heroics; real-time visibility into who accessed what.
- **Pain Points:** No unified view of secret sprawl across 5 cloud accounts and 3 business units acquired via M&A. Cannot answer "who can access production database credentials" today without a multi-day investigation.
- **Success Looks Like:** A single dashboard answering access questions instantly; audit prep time cut from 3 weeks to 2 days.

### Persona 4: Jordan Kim — Compliance Manager
- **Role:** Prepares audit evidence for SOC 2, ISO 27001, and customer security questionnaires.
- **Goals:** Pull access logs, rotation histories, and policy attestations on demand.
- **Pain Points:** Currently manually screenshots dashboards from 4 different tools for every audit cycle.
- **Success Looks Like:** One-click compliance report export mapped to control frameworks.

### Persona 5: Sam Alvarez — SRE / Incident Commander
- **Role:** First responder during security incidents and outages.
- **Goals:** Instantly revoke or rotate a compromised credential across every system it touches.
- **Pain Points:** During a past incident, rotating one leaked API key took 6 hours because it was referenced in 14 different places.
- **Success Looks Like:** A single "revoke and rotate" action that propagates everywhere within seconds, with automatic dependent-service notification.

---

## 6. Functional Requirements

### 6.1 Secrets Storage & Management
- FR-1: Support static secret storage (key-value, arbitrary JSON blobs, files) with versioning and rollback.
- FR-2: Support dynamic secrets generation for databases (PostgreSQL, MySQL, MongoDB, Snowflake), cloud IAM (AWS, GCP, Azure), and message brokers (Kafka, RabbitMQ) — credentials generated on-demand with automatic TTL-based expiry.
- FR-3: Support secret leasing with configurable TTL, renewal, and automatic revocation on lease expiry.
- FR-4: Support automatic secret rotation on a configurable schedule (time-based) and on-demand (event-based, e.g., employee offboarding).
- FR-5: Support secret templating/injection into environment variables, config files, and application memory without writing to disk.
- FR-6: Support soft-delete and configurable retention/purge policies for deleted secrets.

### 6.2 Identity & Access Management
- FR-7: Native support for workload identity federation (no long-lived static credentials for machine-to-machine auth) via OIDC/SPIFFE/SVID-compatible identities.
- FR-8: Support human authentication via SSO/SAML/OIDC (Okta, Azure AD, Google Workspace) with MFA enforcement.
- FR-9: Support machine authentication via cloud-native IAM (AWS IAM, Azure Managed Identity, GCP Workload Identity), Kubernetes service account tokens, TLS client certs, and JWT/OIDC.
- FR-10: Fine-grained, attribute-based access control (ABAC) and role-based access control (RBAC) policy engine supporting path-based and metadata-based rules.
- FR-11: Policy-as-code: policies defined declaratively (HCL/YAML/JSON), version-controlled, and deployable via CI/CD.
- FR-12: Time-bound and just-in-time (JIT) access grants requiring approval workflows for privileged secrets.
- FR-13: "Break glass" emergency access procedure with mandatory post-hoc review and automatic time-limited expiry.

### 6.3 Encryption & Key Management
- FR-14: Encryption-as-a-Service (EaaS) API allowing applications to encrypt/decrypt/sign/verify data without ever handling raw keys (envelope encryption).
- FR-15: Support Bring Your Own Key (BYOK) and Hold Your Own Key (HYOK) models with customer-managed HSMs (AWS CloudHSM, Azure Dedicated HSM, on-prem HSM via PKCS#11).
- FR-16: Automatic key rotation with configurable rewrap policies for previously encrypted data.
- FR-17: Support for transit encryption use cases: tokenization, format-preserving encryption (FPE), and data masking for PII/PCI data.

### 6.4 PKI & Certificate Management
- FR-18: Built-in Certificate Authority (root and intermediate) for issuing short-lived TLS certificates.
- FR-19: ACME protocol support for automated certificate issuance and renewal.
- FR-20: Certificate lifecycle dashboard with expiry alerting and automatic renewal pipelines.

### 6.5 Platform Integrations
- FR-21: Native Kubernetes integration: CSI secrets store driver, sidecar injector, and admission controller for auto-injecting secrets into pods.
- FR-22: Terraform, Pulumi, and CloudFormation providers for infrastructure-as-code secret provisioning and policy management.
- FR-23: CI/CD integrations (GitHub Actions, GitLab CI, Jenkins, CircleCI) with short-lived, scoped tokens per pipeline run (no static CI secrets).
- FR-24: SDKs for Go, Python, Java, Node.js, .NET, and a CLI for all supported platforms.
- FR-25: REST API and gRPC API with full feature parity; OpenAPI spec published.
- FR-26: Secret scanning integration to detect secrets accidentally committed to source control and auto-trigger rotation.

### 6.6 Multi-Tenancy & Namespace Management
- FR-27: Support hierarchical namespaces for multi-team/multi-business-unit isolation within a single cluster, with delegated administration.
- FR-28: Support multi-cluster federation for organizations requiring geographic or regulatory data residency separation.

### 6.7 Observability & Audit
- FR-29: Immutable, tamper-evident audit log of every request (who, what, when, from where, result) with cryptographic chaining for integrity verification.
- FR-30: Real-time audit log streaming to SIEM/log aggregation platforms (Splunk, Datadog, Elastic, Sentinel).
- FR-31: Built-in anomaly detection for unusual access patterns (e.g., secret accessed from new geography, bulk secret enumeration).
- FR-32: Access review dashboards for periodic entitlement/attestation reviews.
- FR-33: Usage analytics: secret access frequency, stale/unused secret identification, blast-radius reporting per credential.

### 6.8 Administration & Operability
- FR-34: Web-based admin UI for policy management, namespace administration, and audit exploration.
- FR-35: Disaster recovery: automated backup, point-in-time restore, and cross-region replication.
- FR-36: Auto-unsealing (cloud KMS-backed) to eliminate manual unseal procedures after restart.
- FR-37: Zero-downtime upgrades and rolling cluster updates.

---

## 7. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Availability** | 99.99% uptime SLA for the control plane (≈52 minutes downtime/year); 99.999% for the secret-read data plane in regional deployments |
| **Scalability** | Support 1M+ secrets per namespace, 100K+ requests/second per cluster, horizontal scaling of data plane nodes |
| **Latency** | p50 < 15ms, p99 < 50ms for cached/regional secret reads; p99 < 200ms for dynamic secret generation |
| **Durability** | 11 nines durability for stored secrets via replicated, encrypted storage backend |
| **Portability** | Deployable as SaaS (multi-tenant), single-tenant dedicated cloud, or fully self-hosted/air-gapped |
| **Interoperability** | Open API standards (REST, gRPC, OpenAPI); no proprietary lock-in for policy language (HCL/YAML/JSON) |
| **Maintainability** | Modular plugin architecture for secret engines and auth methods; backward-compatible API versioning (N-2 support) |
| **Observability** | Full OpenTelemetry instrumentation (metrics, traces, logs) exportable to Prometheus/Grafana/Datadog |
| **Localization** | Admin UI supports i18n (English, Spanish, German, Japanese, French at GA; extensible framework) |
| **Accessibility** | Admin UI WCAG 2.1 AA compliant |

---

## 8. Security Requirements

- SEC-1: **Encryption at rest** using AES-256-GCM for all stored secrets; encryption keys never stored alongside encrypted data (envelope encryption with a root key hierarchy).
- SEC-2: **Encryption in transit** enforced via TLS 1.3 minimum for all client-server and inter-node communication; mutual TLS (mTLS) for service-to-service.
- SEC-3: **Zero standing privilege by default** — all dynamic credentials and access grants are short-lived (default TTL ≤ 1 hour, configurable) unless explicitly overridden with justification and approval.
- SEC-4: **Shamir's Secret Sharing / multi-party unseal** for self-hosted deployments requiring manual unseal; cloud auto-unseal must be backed by a dedicated KMS with its own access controls.
- SEC-5: **HSM-backed root key protection** available for FIPS 140-2 Level 3 compliance requirements.
- SEC-6: **No secret ever transits or is stored in Vaultis's own logs, metrics, or telemetry** — audit logs record metadata (path, identity, timestamp, action) only, never secret values.
- SEC-7: **Principle of least privilege enforced by default deny** — all access policies default-deny; explicit grants required.
- SEC-8: **Multi-factor authentication mandatory** for all human administrative access; step-up authentication required for privileged operations (root token generation, policy changes affecting production namespaces).
- SEC-9: **Supply chain security** — all released binaries signed and reproducible; SBOM (Software Bill of Materials) published per release; dependencies continuously scanned for CVEs.
- SEC-10: **Penetration testing** conducted quarterly by an independent third party; results (redacted) available to enterprise customers under NDA.
- SEC-11: **Bug bounty program** launched at GA with defined scope and SLA-bound triage (critical findings triaged within 24 hours).
- SEC-12: **Tenant isolation** in multi-tenant SaaS deployment guaranteed via cryptographic and logical separation; no shared encryption keys across tenants.
- SEC-13: **Secure software development lifecycle (SSDLC)** — mandatory threat modeling for new features touching the storage or crypto layer, static/dynamic analysis in CI, and security review gate before release.
- SEC-14: **Incident response commitment** — customer notification within 72 hours of confirmed security incident affecting their data, per contractual and regulatory obligations.

---

## 9. Performance Requirements

- PERF-1: Cluster must sustain 100,000 secret-read requests/second at p99 < 50ms under standard reference hardware (published in a benchmarking whitepaper at GA).
- PERF-2: Dynamic secret generation (e.g., new database credential) must complete within p99 < 200ms.
- PERF-3: Policy evaluation engine must resolve access decisions in < 5ms at p99, independent of policy set size up to 100,000 rules.
- PERF-4: System must support horizontal scale-out of read replicas with linear throughput scaling up to 20 nodes per cluster (benchmarked and published).
- PERF-5: Audit log write path must not block the secret-read critical path; asynchronous durable write-ahead logging with < 1s propagation to SIEM under normal load.
- PERF-6: Bulk secret migration/import tooling must sustain a minimum of 10,000 secrets/minute for enterprise onboarding and migration from legacy tools.
- PERF-7: Cold-start latency for a newly provisioned regional cluster must be under 10 minutes for SaaS tier.
- PERF-8: Load testing benchmarks published and re-validated with every major release; regression budget of no more than 5% latency degradation release-over-release without explicit sign-off.

---

## 10. Compliance Requirements

| Framework | Target Timeline | Notes |
|---|---|---|
| **SOC 2 Type II** | GA + 6 months | Table stakes for enterprise sales; audited annually thereafter |
| **ISO/IEC 27001** | GA + 12 months | Required for EU and APAC enterprise deals |
| **PCI-DSS v4.0** | GA + 9 months | Required for fintech/payments customers; scope includes tokenization/encryption engine |
| **HIPAA / HITECH** | GA + 12 months | BAA (Business Associate Agreement) offering for healthcare customers |
| **FedRAMP Moderate** | GA + 18–24 months | Required to sell into US federal government and contractors |
| **GDPR / CCPA** | GA | Data residency controls, right-to-erasure support for audit metadata (not secret content), DPA available at launch |
| **FIPS 140-2/140-3** | GA + 6 months | Validated cryptographic modules for regulated/government customers |
| **NIST 800-53 / 800-171** | GA + 12 months | Mapped controls documentation for government/defense contractors |

**Compliance Product Requirements:**
- Continuous compliance reporting mapped to control frameworks (auto-generated evidence packages).
- Data residency controls allowing customers to pin storage and processing to specific geographic regions.
- Configurable data retention and legal hold capabilities for audit logs.
- Signed Data Processing Agreements (DPA) and sub-processor transparency list maintained publicly.
- Right for enterprise customers to conduct their own audits/pen tests under a defined program.

---

## 11. Use Cases

**UC-1: Dynamic Database Credential Issuance**
A CI/CD pipeline requests a short-lived PostgreSQL credential to run integration tests. Vaultis authenticates the pipeline via its OIDC identity, evaluates policy, generates a unique database user with a 15-minute TTL, and automatically revokes it on lease expiry or job completion — whichever comes first.

**UC-2: Kubernetes Pod Secret Injection**
A pod starts up; the Vaultis sidecar injector authenticates the pod via its Kubernetes service account, retrieves the required secrets, and mounts them into an in-memory volume — never touching disk, never visible via `kubectl describe`.

**UC-3: Emergency Credential Revocation ("Break Glass")**
During a security incident, an SRE identifies a potentially compromised API key. They invoke the revoke-and-rotate action; Vaultis immediately invalidates the credential, generates a replacement, propagates it to all dependent services via webhook, and files an automatic incident record for post-hoc review.

**UC-4: Encryption-as-a-Service for PII**
An application needs to encrypt customer social security numbers before storing them in a database. Rather than managing keys itself, the application calls Vaultis's transit encryption API to encrypt/decrypt on the fly; keys never leave Vaultis, and the app only ever handles ciphertext.

**UC-5: Automated Certificate Rotation**
An internal service mesh requires mTLS certificates for every service. Vaultis's built-in CA issues 24-hour certificates automatically renewed via ACME before expiry, eliminating manual certificate management and expiry-related outages.

**UC-6: Compliance Evidence Generation**
A compliance manager needs to demonstrate to a SOC 2 auditor that access to production payment-processing secrets is restricted to authorized personnel and reviewed quarterly. They generate a one-click evidence package showing policy definitions, access logs, and attestation records for the audit period.

**UC-7: Multi-Cloud Secret Federation**
An enterprise with workloads on AWS, Azure, and GCP needs a single source of truth for secrets rather than three disconnected cloud-native secret managers. Vaultis provides one control plane with regional data planes in each cloud for latency and data residency.

**UC-8: Secret Sprawl Detection & Remediation**
Security scanning detects a hardcoded API key committed to a GitHub repository. Vaultis's integration automatically triggers rotation of the exposed credential and opens a remediation ticket, closing the exposure window before it can be exploited.

---

## 12. User Stories

**Developer Stories**
- As a developer, I want to retrieve a database credential via SDK call in my application startup code, so that I never hardcode credentials in my repository.
- As a developer, I want my local development environment to authenticate to Vaultis using my SSO identity, so that I don't need a separate set of dev credentials.
- As a developer, I want clear error messages when a policy denies my access request, so that I can self-service request the correct access instead of filing a support ticket.

**Platform Engineer Stories**
- As a platform engineer, I want to define secrets access policy as code in the same repository as my infrastructure, so that access changes go through the same review process as infrastructure changes.
- As a platform engineer, I want a Kubernetes CSI driver that auto-mounts secrets into pods, so that I don't need custom init containers for every service.
- As a platform engineer, I want zero-downtime cluster upgrades, so that secret retrieval is never interrupted during platform maintenance.

**Security Engineer Stories**
- As a security engineer, I want to see a real-time feed of all privileged secret access, so that I can detect anomalous behavior before it becomes a breach.
- As a security engineer, I want to set org-wide maximum TTL policies, so that no team can create indefinitely-lived credentials regardless of local configuration.
- As a security engineer, I want to revoke every credential associated with a compromised identity in a single action, so that I can contain an incident within minutes, not hours.

**Compliance/Audit Stories**
- As a compliance manager, I want to export an access log filtered by resource and time range in a standard format, so that I can provide audit evidence without engineering support.
- As a compliance manager, I want automated quarterly access review workflows, so that entitlement reviews happen consistently without manual tracking in spreadsheets.

**Executive/Buyer Stories**
- As a CISO, I want a dashboard showing our organization's overall secret hygiene score (rotation compliance, stale secrets, over-privileged access), so that I can report risk posture to the board.
- As a VP of Engineering, I want to understand the cost/usage relationship of the platform across business units, so that I can allocate budget appropriately via chargeback.

---

## 13. Success Metrics

**Adoption Metrics**
- Number of enterprise logos onboarded (target: 150 within 24 months of GA).
- Percentage of customer secrets under dynamic (vs. static) management (target: 70%+ within 12 months of customer onboarding).
- Weekly active developers using SDK/CLI per customer account (engagement depth).
- Time-to-first-secret for new customer onboarding (target: < 1 day from contract signature).

**Product Health Metrics**
- Control plane uptime against 99.99% SLA (tracked monthly, reported publicly via status page).
- p99 secret-read latency against 50ms target (tracked continuously).
- Mean time to revoke a compromised credential (target: < 5 minutes end-to-end).
- Percentage of secrets past their recommended rotation window (target: < 2% org-wide, trending down).

**Business Metrics**
- Net Revenue Retention (NRR) — target 120%+ driven by expansion into PKI, EaaS, and additional workloads.
- Gross margin on SaaS tier (target: 75%+ at scale).
- Sales cycle length for enterprise deals (target: reduce from 6 months to 4 months by year 2 via compliance certifications removing procurement friction).

**Security & Trust Metrics**
- Zero critical security incidents resulting in customer secret exposure (non-negotiable trust metric).
- Time to patch critical CVEs in dependencies (target: < 48 hours).
- Bug bounty program: mean time to triage critical findings (target: < 24 hours).

**Customer Satisfaction Metrics**
- Net Promoter Score (NPS) among platform/security engineering users (target: 50+).
- Customer Effort Score for secret onboarding/migration.
- Support ticket volume per 1,000 API calls (trending down release-over-release).

---

## 14. Future Scope

The following are explicitly deferred beyond GA but represent the long-term platform roadmap:

- **Secrets Risk Scoring & AI-Driven Anomaly Detection:** ML-based behavioral baselining to flag access patterns that deviate from historical norms, beyond simple rule-based anomaly detection.
- **Partner Plugin SDK & Marketplace:** Allow third parties to build and distribute custom secret engines and auth methods.
- **Active-Active Multi-Region Writes:** Full multi-master replication for global, always-on write availability.
- **Crypto-Asset Custody / Wallet Key Management:** Extend HSM-backed key management to support blockchain wallet and crypto-asset custody use cases.
- **Autonomous Remediation:** Auto-remediate detected secret sprawl (e.g., automatically rotate and notify on detecting a hardcoded secret in source control, without requiring human trigger).
- **Confidential Computing Integration:** Use of secure enclaves (AWS Nitro Enclaves, Azure Confidential Computing) so that even Vaultis's own infrastructure operators cannot access plaintext secrets during processing.
- **Passwordless/Certificate-Based Human Access Expansion:** Move human administrative access fully to certificate-based, passwordless authentication.
- **Deeper FinOps Integration:** Cost attribution and chargeback reporting tied to secrets/key usage per business unit.
- **Expanded Data Residency & Sovereign Cloud Support:** Dedicated sovereign cloud deployments for government and highly regulated markets (e.g., EU sovereign cloud, Gov Cloud variants).
- **Native Secrets Management for Edge/IoT Fleets:** Lightweight agent for resource-constrained edge devices with intermittent connectivity.
- **Self-Service Compliance Automation Marketplace:** Pre-built, customer-configurable compliance report templates for emerging frameworks (DORA, NIS2, etc.) as regulatory landscape evolves.

---

## Appendix: Open Questions for Cross-Functional Review

1. Pricing model — should dynamic secrets/EaaS be metered separately from base platform licensing, or bundled into tiers?
2. Should the self-hosted/air-gapped edition ship on the same release cadence as SaaS, or lag by a stabilization window?
3. What is our position on supporting community/open-source edition to drive top-of-funnel adoption, and how do we prevent channel conflict with the commercial product?
4. Do we build our own HSM integration layer, or partner exclusively with cloud-native KMS providers for v1 and defer on-prem HSM to a fast-follow?

