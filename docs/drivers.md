# Firewall driver development

Implement the typed [FirewallDriver interface](../netbox_firewall/drivers/base.py) and register an installed Python package factory under `netbox_firewall.drivers`. The factory takes the validated HTTPS origin, administrator-controlled configuration mapping and a read/write session flag. For a DNS origin, the worker supplies a resolved and validated `connect_ip` to the read and write sessions.

```toml
[project.entry-points."netbox_firewall.drivers"]
example = "netbox_firewall_example:factory"
```

The core uses native IDs and semantic snapshots. A driver must provide exact matches, a stable configuration fingerprint, complete coverage within its declared inventory scope, and a clear limitation statement. Unknown values cannot default to wildcard or default vendor behavior. Raise a sanitized error for malformed, partial or inconsistent inventory. Use distinct read and write sessions and report applicability via `write_eligible`. Only set `alias_dependency_complete` when you can establish exclusive use of plugin-managed groups for the planned policy, including dependencies outside the rule listing.

Use the common HTTPS transport. Enforce TLS verification and the connection allowlist, block redirects, bound request duration and size, and avoid automatic mutation retries. Never log credentials or raw response bodies. Do not expose deletion operations or implement a create-only rule by changing existing rules. Normalize match qualifiers, default action semantics, ordering, address family, negation, enabled state, runtime or configured state, and alias semantics separately as needed. Increment `normalization_version` when equivalence changes. Only trusted contributors and platform operators may install drivers because entry points run Python inside NetBox.

Reuse the shared [conformance suite](../tests/drivers/conformance.py) with an appliance fixture and add tests for errors, translated match semantics, observability limits, reload behavior and timeouts. Validate against an isolated test appliance before claiming support.

## OPNsense Community 26.7.9

The built-in implementation uses GET `filter/searchRule`, `alias/searchItem`, and `filter/getInterfaceList`. It validates grid counts and rejects truncated inventories. For deployments it also checks GET `core/firmware/info` and requires zero legacy rules from GET `firewall/migration/count_rules`. Legacy rules remain visible for read-only review when reported by the appliance. It uses POST `alias/addItem`, `alias/setItem/{uuid}`, `alias/reconfigure`, `filter/addRule`, and `filter/apply` with the tagged API controller's model payloads. Static alias content uses newline-separated network values. Rule creation uses one ingress interface, quick evaluation and a sequence within OPNsense's priority class. Existing unmanaged rules with ambiguous precedence block writes.

After apply, the driver checks the loaded PF rule UUID via GET `filter_util/rule_stats` and compares changed alias tables via GET `alias_util/list/{name}`. The tagged configd script returns `OK` on process success even when the reload script restored a previous ruleset. Runtime evidence is required for deployment verification. OPNsense does not prove end-to-end reachability or the effect of other generated rules.

OPNsense can expose legacy rules in the 26.7.9 filter grid. Automatically generated rows can lack stable identifiers and are excluded from drift ownership. The grid merges configured MVC data and a backend view of reported legacy rules. The backend can omit legacy or automatic data when its enumeration fails. Alias references in NAT and third-party modules are outside this inventory. Read-only audit reports this coverage. Write activation and alias exclusivity require an operator-maintained configuration window.

Source references include the [tagged filter controller](https://github.com/opnsense/core/blob/26.7.9/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterController.php), [filter model](https://github.com/opnsense/core/blob/26.7.9/src/opnsense/mvc/app/models/OPNsense/Firewall/Filter.xml), [alias controller](https://github.com/opnsense/core/blob/26.7.9/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/AliasController.php) and [reload script](https://github.com/opnsense/core/blob/26.7.9/src/etc/inc/filter.inc).
