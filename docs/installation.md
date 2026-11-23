# Installation and operations

Use an active supported NetBox release, PostgreSQL and Redis supported by that release, and a NetBox RQ worker. Connect the worker to PostgreSQL directly or through session pooling. Transaction-mode poolers cannot preserve PostgreSQL session advisory locks.

## Install

1. Back up the NetBox database. Install the verified wheel in the same Python environment or image as NetBox web and worker processes. For a checkout, run `python -m build` and install the resulting wheel.
2. Add `"netbox_firewall"` to the existing `PLUGINS` list and merge the configuration below into `PLUGINS_CONFIG`. Inject credential values through your service manager or container secret injection. Mount your CA file in the NetBox worker and web containers if a private CA is needed.
3. From NetBox's application directory, run `python manage.py migrate --noinput` and follow your installation's normal static file and restart procedures. Restart each NetBox worker so it registers the recurring job. Keep the NetBox worker listening to the queues recommended by its release.
4. Add the matching **Firewall** object. Queue an audit from its detail page or wait for the worker schedule. Review **Drift events** and **Firewalls**. A baseline is recorded only after a successful inventory response.

```python
PLUGINS_CONFIG = {
    "netbox_firewall": {
        "audit_interval": 5,
        "endpoints": {
            "https://192.0.2.10": {
                "driver": "opnsense",
                "ca_bundle": "/etc/netbox/firewall-ca.pem",
                "read_key_env": "NB_LAB_READ_KEY",
                "read_secret_env": "NB_LAB_READ_SECRET",
            },
        },
        # Optional HTTPS IP origin. Receives POST /firewall-alerts.
        "webhook": None,
    },
}
```

Use canonical IP origins, with brackets for IPv6 and an explicit port for non-default HTTPS. The certificate must include the IP in the subject alternative name. The application uses no DNS resolution for these origins, ignores environment proxy configuration and rejects redirects. Restrict worker egress to configured endpoints. Grant the OPNsense read account the permissions needed for filter/rule and alias inventory, and interface listing. Confirm the actual 26.7.9 ACL grouping before issuing keys. Where a single appliance ACL couples reads and changes, treat the audit credential as privileged and enforce method restrictions at a trusted management gateway if needed.

## Configure an enforcement scope

Scopes live in the firewall's JSON settings. A scope names the native ingress interface, an exact NetBox VRF ID or null for global routing, internal trust, and approved source and destination bounds and services.

```json
{
  "internal-app": {
    "interface": "opt1",
    "vrf": null,
    "trust": "internal",
    "sources": ["192.0.2.0/24"],
    "destinations": ["198.51.100.0/24"],
    "services": ["tcp/443"]
  }
}
```

Confirm the native interface is internal and dedicated to the intended policy. No site membership infers enforcement. Choose named groups and a service for the policy, set the zone to `internal-app`, and select the deployment option. Inspect the preview before approving. The built-in templates supply service, action and logging. NetBox retains the policy identity across renames.

## Qualify and activate writes

1. On a disposable OPNsense Community 26.7.9 instance, compare the API inventory with the native UI, including configured manual rules. Export its configuration. Set up test endpoints and independent traffic probes for both allowed and denied paths.
2. Use a separate deployment credential. Verify the appliance grants POST access to the required rule and alias endpoints and read access to firmware identity, legacy-rule count, PF rule statistics, and PF alias tables. The API privileges can include vendor mutations beyond what the driver invokes. Restrict credentials, appliance management access, and network identity accordingly.
3. Set `firmware` to `"26.7.9"`, configure `write_key_env` and `write_secret_env` with separate environment variable names, and set `write_until` to a timezone-aware ISO 8601 time within the next 24 hours. Treat it as an exclusive maintenance window. Ensure no unrelated staged changes or simultaneous administrators can alter the configuration. For alias updates set `exclusive_aliases` to `True` only after verifying that managed aliases are reserved for the plugin across the entire appliance, including NAT and plugins.
4. Reload NetBox web and worker settings, queue a new read-only audit, and inspect its status. Use **Activate deployment in configured window** on the firewall page. Approve the exact policy resolution and run **Queue deployment**, or allow the scheduled worker to run. Keep firewall policies staged in small batches.
5. Inspect the deployment record and OPNsense UI and run independent traffic probes. Exercise the tag-change approval and alias update, unmanaged and acknowledged manual rule, expiration, managed-rule edit and policy removal. Use a lab proxy that truncates or rejects inventory responses to check that writes stop. Re-run jobs to confirm UUID stability.

The plugin opens a separate write session after read-only planning, requires matching snapshots, journals each remote mutation and checks the resulting configuration. When the write window ends, audits continue and writes are blocked. Configuration-level verification still requires runtime traffic validation before production use.

## Recovery, upgrades and uninstall

If a run is partial, disable deployment and inspect its operations and the appliance. A response timeout can leave a staged resource. Review the current native configuration and the recorded UUIDs. Use one allowlisted origin per appliance so all its jobs share the same lock. Restore the appliance to the pre-run state or handle those resources manually, then record recovery on the deployment and re-audit. The plugin never adopts marker matches automatically. Non-destructive manual recovery can leave a conflict until the operator resolves ownership outside the plugin.

Before upgrading, disable deployment, back up the NetBox database and appliance, install the new package with its supported NetBox version, run migrations and restart services. A changed driver normalization or connection profile requires a fresh audit and activation. Preserve the database so UUID mappings, exceptions and drift history survive. To roll back, use the previous package and a compatible database backup or a reviewed Django migration rollback. Rollback does not touch the appliance.

For uninstall, disable deployment and remove the plugin from NetBox settings. Restart workers and web processes, then uninstall the package from the environment. Retain the database backup and appliance mapping records for operational recovery. Only remove plugin database tables as part of an explicit data removal procedure. Existing firewall resources remain in place.
