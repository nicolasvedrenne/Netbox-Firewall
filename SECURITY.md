# Security policy

## Reporting

After repository publication, use GitHub private vulnerability reporting. Provide affected versions, relevant conditions and reproducible evidence from an isolated environment. Remove credentials and production addresses from reports.

## Permission and governance model

Grant permissions through NetBox Object Permissions. In addition to model view/add/change/delete, configure these additional actions with object constraints as appropriate:

| Object type | Additional action |
| --- | --- |
| Firewall | `manage_connection`, `activate_deployment`, `synchronize` |
| Firewall policy | `approve` |
| Firewall exception | `acknowledge` |

Limit policy and group editing and restrict resolution snapshots and drift evidence to trusted operators. Policy viewing exposes the policy's resolved addresses and source of inventory membership. Restrict approval to security reviewers and activation to firewall operators. Keep inventory editing separate from those permissions. Configure NetBox object constraints around sensitive tags where supported. A user's ability to modify a tag, VM, address assignment or selector cannot approve the resulting revision. Operators should confirm inventory ownership and freshness when reviewing. Once a rule is applied, removing an inventory object does not automatically revoke access in additive mode.

## Threat model

| Threat | Mitigations and remaining exposure |
| --- | --- |
| Compromised NetBox user | Separate approval, activation and connection permissions, explicit network bounds, exact revision approval and a bounded write window. A compromised privileged approver or service account can still authorize changes within its grants. |
| Malicious tag, assignment or inventory edit | Hash the resolved membership, selector intent, and concrete IP and assignment identities. Require new approval for each change. Run regular inventories. NetBox can still contain stale or false operational data. |
| Compromised firewall credential | Inject separate credentials through the process environment. Use appliance ACLs, TLS, restricted egress and no rule deletion API in the driver. OPNsense privileges may permit additional operations outside the plugin. |
| API spoofing and SSRF | Exact administrator-configured HTTPS origins, a fixed IP or approved management CIDRs for DNS origins, strict certificate validation and optional private CA. Reject redirects, userinfo, paths and proxy inheritance. DNS results outside the configured CIDRs block all requests. The job pins the validated address. Network admins still control routing, DNS and trust anchors. |
| Partial or malformed inventory | Validate shape, counts and unique identifiers, reject unsupported firmware for writes, recheck snapshots and keep open findings after errors. The appliance can report a structurally valid but incomplete backend view. |
| Concurrent changes or ambiguous writes | Serialize plugin jobs using session locks, require a maintenance window, check pre/post state and persist per-operation journaling. The API has no external compare-and-swap and another appliance writer can race the plugin. |
| Accidental expansion or outage | Explicit non-WAN ingress scope, bounded prefixes and service allowlist, ordered planning, group exclusivity and hard failure on ambiguous precedence. An authorized rule still changes network access and global reloads can affect other traffic. |
| Malicious dependency or driver | Limit dependencies, scan advisory and secret databases, pin Actions, and review driver source and supply chain. Installed Python packages run with NetBox's privileges. |
| Sensitive response content | Keep credential references in host configuration and values in the environment. Use sanitized errors, skip non-network alias content and configured alias authentication fields, and send only event IDs and states to webhooks. Restrict view access to stored configuration evidence. |

## Incident response

Disable deployment, suspend relevant workers if necessary, rotate appliance API credentials and review NetBox approvals, plans, operation journals, drift records and appliance audit logs. Review live traffic and configured state separately. Restore from operator-verified backups according to your appliance change procedure and audit before enabling deployment again.
