# Development plan

The project starts from an empty repository. Target NetBox 4.5.0 through 4.7.5 pending integration tests against the exact endpoints of that range. The Python versions supported upstream are 3.12 through 3.14. Verify OPNsense Community 26.7.9 against the tagged controller and model sources. Installation requires only the existing NetBox database and workers.

## Architecture and trust boundaries

NetBox models, permission-gated views and jobs own durable state. The policy engine resolves inventory into deterministic snapshots. The reconciler compares desired, last applied and observed resources and records a plan. Drivers implement protocol translation and HTTPS I/O. A PostgreSQL per-firewall lock serializes plugin jobs and privileged actions. A durable attempt journal survives a worker failure or ambiguous response.

A compromised inventory editor can alter tags, assignments and addresses. Approval binds the resolved prefixes and assignment identities to a policy revision. Recurring jobs detect new eligible members and require reapproval before changing access. Endpoint authorization comes from deployment configuration and uses exact HTTPS IP origins. Credentials are injected into workers. The OPNsense API stages changes globally and does not expose an atomic compare-and-swap. Writes require an administrative maintenance-window attestation and exact firmware opt-in. Full normalization or credentials changes invalidate deployment authorization.

## Milestones

1. Installable NetBox plugin, models and migrations, firewall list and read-only OPNsense inventory. Gate on installation, migration and strict fixture parsing.
2. Inventory selectors, service definitions, templates and policy preview. Gate on deterministic output, explicit VRF and service addressing, and empty/ambiguous selector rejection.
3. Baseline, ownership, drift transitions, exceptions, scheduling and webhook. Gate on bounded jobs, stable event identity and expiration.
4. Approval, deployment planning, group updates and native UUID tracking. Gate on permission, non-destructive, partial failure and repeat execution tests.
5. Packaging, contributor and operator guides, security checks, CI and release workflows. An isolated appliance and external publishing prerequisites gate the live release.

## Screen layout

```
Firewall dashboard   [mode] [last success] [state]
                     [drift] [resources] [audit action]
Policy list          [filter] [policy] [firewall] [approval]
Policy detail        [intent] [resolved preview] [approve]
Deployment detail    [desired] [current] [plan] [attempt]
Drift list           [filter] [state] [first/last seen]
Inventory object     [matching policies] [resolution]
```
