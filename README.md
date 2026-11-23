# NetBox Firewall

NetBox Firewall resolves approved NetBox inventory into declarative firewall policy and audits the firewall for configuration drift. The plugin uses NetBox's database and workers. Audit is read-only by default. Deployments preserve manual rules, report changed or missing managed rules, and keep native UUID mappings even when a policy is removed.

| Component | Initial compatibility |
| --- | --- |
| NetBox | 4.5.0–4.7.5. The compatibility matrix exercises both endpoints. Use a current patched release within the supported range. |
| Python | 3.12–3.14, matching upstream NetBox support |
| OPNsense | Community 26.7.9 API supported by source-derived fixtures. Deployment requires explicit opt-in and disposable-appliance qualification. |
| Runtime | NetBox PostgreSQL, Redis and RQ workers |

See the [NetBox dependency matrix](https://github.com/netbox-community/netbox/blob/main/docs/installation/upgrading.md), [background job API](https://netbox.readthedocs.io/en/stable/plugins/development/background-jobs/) and [OPNsense firewall API](https://docs.opnsense.org/development/api/core/firewall.html).

## Quick start

1. Install the wheel in NetBox's Python environment and add `netbox_firewall` to `PLUGINS`.
2. Configure an exact allowlisted HTTPS IP origin and read-only OPNsense credentials. Run NetBox migrations and restart the web service and worker.
3. Add the appliance under **Firewall → Firewalls** and queue an audit. Review the rule baseline and API coverage.
4. Define an internal enforcement scope and two address groups. For example, select a source network with `{"networks":["192.0.2.0/24"]}` and destinations with `{"tags":["fw-web"],"service_ip_tag":"fw-service"}`.
5. Create a policy using the HTTPS service. Open it, inspect the resolved rule and member identities, and approve the revision.
6. Follow the controlled write activation procedure in the [installation guide](docs/installation.md). Use a disposable appliance for the first deployment.

A new matching member invalidates the existing approval. Approving the new resolution queues a job that updates the owned alias in an active write window. In additive mode the alias retains withdrawn members and raises a finding. Expired policies and exceptions require action on the firewall.

## Design and limits

- NetBox owns selectors, approvals, deployment journals, native mappings and compliance history.
- Policy evaluation resolves inventory deterministically and enforces explicit service, IP, interface and VRF boundaries.
- The reconciliation engine plans new rules and owned group changes. Manual rules and orphaned resources are preserved.
- The OPNsense driver inventories MVC rules, configured aliases, and reported legacy rules. Generated rules, runtime enforcement and alias consumers outside the selected API have coverage gaps. Applying configuration can reload unrelated staged changes. The plugin cannot provide an atomic appliance transaction.

See [installation and operations](docs/installation.md), [architecture and selectors](docs/architecture.md), [driver development](docs/drivers.md), [security](SECURITY.md), and [contributing](CONTRIBUTING.md).

Licensed under Apache-2.0.
