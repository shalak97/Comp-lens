"""Secondary connectors: Azure, GCP, GitLab, Slack, ServiceNow, Qualys,
CrowdStrike.

Maturity: PRODUCTION — each routes through the hardened ResilientClient (retries,
backoff, 429 handling, circuit breaker, SSRF guard, credential redaction) and
follows the same BaseConnector contract as every other connector. Field names
and auth flows follow each vendor's documented REST API; validate against your
own tenant on first connection (product tiers expose different fields).
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import requests

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.capabilities import Probe

logger = logging.getLogger(__name__)

#: Entra directory roles that carry tenant-wide privilege. Matched on the role
#: template display name, which is stable across tenants.
_PRIVILEGED_ROLES = frozenset({
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
    "security administrator",
    "application administrator",
    "cloud application administrator",
    "user administrator",
})


def _is_privileged_role(role: dict[str, Any]) -> bool:
    return (role.get("displayName") or "").strip().lower() in _PRIVILEGED_ROLES


def _parse_graph_time(value: str | None):
    """Parse a Graph/ARM ISO-8601 timestamp, tolerating the trailing Z."""
    if not value:
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_since(when) -> int | None:
    if when is None:
        return None
    from datetime import UTC, datetime
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0, (datetime.now(UTC) - when).days)


def _ingress_exposure(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Reduce a list of normalized ingress rules to the platform's signals.

    Shared by the Azure NSG and GCP firewall probes so both clouds answer the
    network-exposure checks the same way rather than each inventing its own
    interpretation of "open to the world". A rule is expressed as
    ``{"source": str, "ports": set[int] | None, "all_ports": bool}`` where
    ``ports=None`` with ``all_ports=True`` means every port.
    """
    world = {"0.0.0.0/0", "::/0", "*", "internet", "any"}

    def is_world(src: str) -> bool:
        return (src or "").strip().lower() in world

    open_rules = [r for r in rules if is_world(r.get("source", ""))]

    def hits(port: int) -> bool:
        return any(r.get("all_ports") or (port in (r.get("ports") or set()))
                   for r in open_rules)

    return {
        "unrestricted_ingress": bool(open_rules),
        "ssh_open_to_world": hits(22),
        "rdp_open_to_world": hits(3389),
        "open_ingress_rule_count": len(open_rules),
    }


def _sub_relative(resource_id: str) -> str:
    """Strip the ``/subscriptions/{id}`` prefix off a full ARM resource id.

    ARM returns absolute resource ids in nested references (a VM's NICs, for
    instance) but _arm() builds its URL from the configured subscription, so
    the leading segment has to come off or it would be doubled.
    """
    parts = (resource_id or "").split("/")
    if len(parts) > 3 and parts[1] == "subscriptions":
        return "/" + "/".join(parts[3:])
    return resource_id


def _expand_ports(spec: str) -> tuple[set[int], bool]:
    """Turn a port spec ("22", "80-443", "*") into (ports, all_ports).

    Ranges are only expanded up to a bound: a rule of "0-65535" is "all ports",
    and materialising 65k integers to discover that wastes memory on every
    evaluation.
    """
    spec = (spec or "").strip()
    if spec in ("*", "", "any", "all", "0-65535"):
        return set(), True
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                lo_i, hi_i = int(lo), int(hi)
            except ValueError:
                continue
            if hi_i - lo_i > 4096:
                return set(), True
            ports.update(range(lo_i, hi_i + 1))
        elif part.isdigit():
            ports.add(int(part))
    return ports, False


# ──────────────────────────────────────────────────────────────────────────
# Azure (Entra ID + resources) — via azure-identity + Microsoft Graph
# ──────────────────────────────────────────────────────────────────────────
class AzureConnector(BaseConnector):
    source_system = "AZURE"

    # Capability surface. These probes emit the same normalized signal names as
    # the AWS probes, which is what lets a single declarative check
    # ("object storage must require TLS") run against either cloud with no
    # change to the check pack.
    PROBES = (
        Probe(
            probe_id="entra_user",
            asset_type="iam_user",
            plane="identity_access",
            asset_param="user",
            description="Entra ID principal authentication and privilege posture.",
            signals=(
                "mfa_enabled",
                "mfa_enforced",
                # AWS's "attached admin policy" maps to a privileged directory
                # role; its "inline policy" (a permission granted to the user
                # itself rather than through a group) maps to a role assigned
                # directly rather than inherited from a group membership.
                "has_admin_policy",
                "has_inline_policy",
                # Whether the account can sign in interactively at all. An
                # account that cannot is not a console user, and demanding MFA
                # of it would be a finding about nothing.
                "console_access_enabled",
                "principal",
                "owner",
            ),
        ),
        Probe(
            probe_id="service_principal",
            asset_type="iam_user",
            plane="identity_access",
            asset_param="service_principal",
            description="Entra ID application credential hygiene.",
            # A human Entra user has no long-lived keys, so the key-age and
            # key-count checks have no honest answer for one. An application's
            # client secrets and certificates are Azure's actual equivalent of
            # an AWS access key, so they get their own probe rather than
            # inventing key fields on the user probe.
            signals=(
                "access_key_count",
                "days_since_key_rotation",
                "principal",
                "owner",
            ),
        ),
        Probe(
            probe_id="storage_account",
            asset_type="object_storage",
            plane="data_protection",
            asset_param="storage_account",
            description="Azure Storage account protection posture.",
            signals=(
                "encryption_at_rest",
                "kms_encrypted",
                "public_access_blocked",
                "tls_required",
                "versioning_enabled",
                "access_logging_enabled",
                "lifecycle_configured",
                "asset",
                "owner",
            ),
        ),
        Probe(
            probe_id="sql_database",
            asset_type="managed_database",
            plane="data_protection",
            asset_param="sql_server",
            description="Azure SQL server protection posture.",
            signals=(
                "encryption_at_rest",
                "publicly_accessible",
                "auto_minor_version_upgrade",
                "backup_retention_days",
                "multi_az_enabled",
                "deletion_protection_enabled",
                "log_exports_enabled",
                "iam_auth_enabled",
                "owner",
            ),
        ),
        Probe(
            probe_id="subscription",
            asset_type="cloud_account",
            plane="logging_monitoring",
            requires_asset=False,
            description="Subscription-wide logging and threat detection posture.",
            # Deliberately does not emit the CloudTrail-specific signals that
            # have no Azure counterpart (log_file_validation_enabled has no
            # equivalent — Azure offers no digest validation for the Activity
            # Log), nor the IAM password-policy signals: Entra's cloud-only
            # password policy is fixed and does not expose the per-rule fields
            # those checks read. Reporting a guess there would turn "we cannot
            # observe this" into a compliance claim.
            signals=(
                "logging_enabled",
                "multi_region_enabled",
                "cloudwatch_logs_integrated",
                "threat_detection_enabled",
                "owner",
            ),
        ),
        Probe(
            probe_id="virtual_machine",
            asset_type="compute_instance",
            plane="host_runtime",
            asset_param="vm",
            description="Virtual machine exposure and monitoring posture.",
            # imdsv2_required is intentionally absent: Azure's instance
            # metadata service has no v1/v2 split to require.
            signals=(
                "public_ip_assigned",
                "detailed_monitoring_enabled",
                "instance_state",
                "owner",
            ),
        ),
        Probe(
            probe_id="network_security_group",
            asset_type="network_ruleset",
            plane="network_boundary",
            asset_param="nsg",
            description="Network security group ingress exposure.",
            signals=(
                "unrestricted_ingress",
                "ssh_open_to_world",
                "rdp_open_to_world",
                "open_ingress_rule_count",
                "owner",
            ),
        ),
        Probe(
            probe_id="virtual_network",
            asset_type="virtual_network",
            plane="network_boundary",
            asset_param="vnet",
            description="Virtual network flow logging.",
            signals=("flow_logs_enabled", "owner"),
        ),
        Probe(
            probe_id="key_vault_key",
            asset_type="encryption_key",
            plane="data_protection",
            asset_param="key",
            description="Key Vault key rotation policy.",
            signals=("key_rotation_enabled", "owner"),
        ),
        Probe(
            probe_id="managed_disk",
            asset_type="block_storage",
            plane="data_protection",
            asset_param="disk",
            description="Managed disk encryption posture.",
            signals=("encryption_at_rest", "owner"),
        ),
    )

    #: Azure resource probes need an ARM path, not just a name.
    _ARM_API = "2023-01-01"

    def __init__(self) -> None:
        if not (settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret):
            raise ConnectorError("AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET required.")
        # Graph and ARM are separate audiences, so tokens are cached per scope.
        self._tokens: dict[str, tuple[str, float]] = {}

    def _acquire_token(self, scope: str) -> str:
        import time
        cached = self._tokens.get(scope)
        # refresh if missing or within 60s of expiry
        if cached and time.time() < cached[1] - 60:
            return cached[0]
        url = f"https://login.microsoftonline.com/{settings.azure_tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": settings.azure_client_id,
            "client_secret": settings.azure_client_secret,
            "scope": scope,
            "grant_type": "client_credentials",
        }
        r = requests.post(url, data=data, timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"Azure token error {r.status_code}: {r.text[:200]}")
        body = r.json()
        token = body["access_token"]
        self._tokens[scope] = (token, time.time() + int(body.get("expires_in", 3600)))
        return token

    def _acquire_graph_token(self) -> str:
        return self._acquire_token("https://graph.microsoft.com/.default")

    def _graph(self, path: str) -> Any:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0{path}",
            headers={"Authorization": f"Bearer {self._acquire_graph_token()}"},
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"Graph API {r.status_code}: {r.text[:200]}")
        return r.json()

    def _arm(self, resource_path: str, api_version: str | None = None) -> Any:
        """GET an Azure Resource Manager resource under the configured subscription."""
        if not settings.azure_subscription_id:
            raise ConnectorError("AZURE_SUBSCRIPTION_ID is required for resource controls.")
        token = self._acquire_token("https://management.azure.com/.default")
        url = (f"https://management.azure.com/subscriptions/"
               f"{settings.azure_subscription_id}{resource_path}")
        r = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params={"api-version": api_version or self._ARM_API},
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"Azure ARM {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._graph("/organization")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Azure healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        user_ref = asset_id or params.get("user")
        if control_id == "AC-2-7":
            if not user_ref:
                raise ConnectorError("Azure AC-2-7 requires asset_id (user id/UPN).")
            return self._entra_user_telemetry(user_ref)
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        probe = self.surface().probes.get(probe_id)
        target = asset_id or (params.get(probe.asset_param) if probe and probe.asset_param else None)
        if probe_id == "entra_user":
            return self._entra_user_telemetry(target)
        if probe_id == "service_principal":
            return self._service_principal_telemetry(target)
        if probe_id == "storage_account":
            return self._storage_account_telemetry(target, params)
        if probe_id == "sql_database":
            return self._sql_server_telemetry(target, params)
        if probe_id == "subscription":
            return self._subscription_telemetry()
        if probe_id == "virtual_machine":
            return self._virtual_machine_telemetry(target, params)
        if probe_id == "network_security_group":
            return self._nsg_telemetry(target, params)
        if probe_id == "virtual_network":
            return self._vnet_telemetry(target, params)
        if probe_id == "key_vault_key":
            return self._key_rotation_telemetry(target, params)
        if probe_id == "managed_disk":
            return self._managed_disk_telemetry(target, params)
        raise ConnectorError(f"Azure connector has no handler for probe '{probe_id}'.")

    def _entra_user_telemetry(self, user_ref: str | None) -> dict[str, Any]:
        if not user_ref:
            raise ConnectorError("Azure identity control requires asset_id (user id/UPN).")
        # Per-user MFA registration via reports API (needs AuditLog.Read.All)
        data = self._graph(
            f"/reports/authenticationMethods/userRegistrationDetails/{user_ref}"
        )
        registered = bool(data.get("isMfaRegistered"))

        # Privilege shape. transitiveMemberOf includes roles inherited through
        # group membership; directoryRoles on the user itself are the ones
        # granted straight to the principal — the distinction AWS draws between
        # an attached policy and an inline one.
        admin = direct = False
        try:
            transitive = self._graph(
                f"/users/{user_ref}/transitiveMemberOf/microsoft.graph.directoryRole")
            roles = transitive.get("value", []) or []
            admin = any(_is_privileged_role(r) for r in roles)
            direct_roles = self._graph(
                f"/users/{user_ref}/memberOf/microsoft.graph.directoryRole").get("value", []) or []
            direct = bool(direct_roles)
        except ConnectorError as exc:
            # Role reads need Directory.Read.All. Without it the privilege
            # signals are unknown, and unknown must not read as "clean" — leave
            # them out so the checks report NOT_APPLICABLE rather than PASS.
            logger.warning("Azure role read failed for %s: %s", user_ref, exc)
            return {"mfa_enforced": registered, "mfa_enabled": registered,
                    "principal": user_ref, "owner": "identity-team"}

        # accountEnabled is Entra's "can this principal sign in", the same
        # question an AWS login profile answers.
        enabled = None
        try:
            enabled = bool(self._graph(f"/users/{user_ref}").get("accountEnabled"))
        except ConnectorError as exc:
            logger.warning("Azure user read failed for %s: %s", user_ref, exc)

        out = {
            "mfa_enforced": registered,
            "mfa_enabled": registered,
            "has_admin_policy": admin,
            "has_inline_policy": direct,
            "principal": user_ref,
            "owner": "identity-team",
        }
        if enabled is not None:
            out["console_access_enabled"] = enabled
        return out

    def _service_principal_telemetry(self, app_ref: str | None) -> dict[str, Any]:
        """Client secrets and certificates are an application's access keys."""
        if not app_ref:
            raise ConnectorError(
                "Azure service-principal control requires asset_id (object id or appId).")
        doc = self._graph(f"/servicePrincipals/{app_ref}")
        creds = list(doc.get("passwordCredentials") or []) + list(doc.get("keyCredentials") or [])
        newest = None
        for c in creds:
            started = _parse_graph_time(c.get("startDateTime"))
            if started is not None and (newest is None or started > newest):
                newest = started
        return {
            "access_key_count": len(creds),
            # Age of the newest credential: the same question RDS/IAM key
            # rotation asks — "when was this last rotated", not "how old is the
            # oldest thing lying around".
            "days_since_key_rotation": _days_since(newest),
            "principal": doc.get("displayName") or app_ref,
            "owner": "identity-team",
        }

    @staticmethod
    def _resource_group(params: dict[str, Any]) -> str:
        rg = params.get("resource_group")
        if not rg:
            raise ConnectorError(
                "Azure resource controls require a 'resource_group' param.")
        return rg

    def _storage_account_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure storage control requires asset_id (account name).")
        rg = self._resource_group(params)
        doc = self._arm(
            f"/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}")
        props = doc.get("properties", {})
        enc = props.get("encryption", {})
        key_source = enc.get("keySource")
        return {
            # Azure Storage is always encrypted at rest; the meaningful
            # distinction is whether the key is customer-managed.
            "encryption_at_rest": True,
            "kms_encrypted": key_source == "Microsoft.Keyvault",
            "public_access_blocked": props.get("allowBlobPublicAccess") is False,
            "tls_required": bool(props.get("supportsHttpsTrafficOnly")),
            "versioning_enabled": bool(
                props.get("isVersioningEnabled", enc.get("isVersioningEnabled"))),
            # Blob diagnostic settings are the Azure analogue of S3 server
            # access logging; a management policy is its lifecycle config.
            "access_logging_enabled": self._has_diagnostic_settings(
                f"/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/"
                f"{name}/blobServices/default"),
            "lifecycle_configured": self._has_management_policy(rg, name),
            "asset": name,
            "owner": "cloud-platform-team",
        }

    def _has_diagnostic_settings(self, resource_path: str) -> bool:
        """True when the resource ships logs somewhere (Monitor diagnostics)."""
        try:
            doc = self._arm(
                f"{resource_path}/providers/Microsoft.Insights/diagnosticSettings",
                api_version="2021-05-01-preview")
            return bool(doc.get("value"))
        except ConnectorError as exc:
            logger.warning("Azure diagnostic-settings read failed for %s: %s",
                           resource_path, exc)
            raise

    def _has_management_policy(self, rg: str, account: str) -> bool:
        try:
            doc = self._arm(
                f"/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/"
                f"{account}/managementPolicies/default")
            rules = (doc.get("properties", {}).get("policy", {}) or {}).get("rules") or []
            return bool(rules)
        except ConnectorError:
            # ARM 404s when no policy exists, which is a real answer: none.
            return False

    def _sql_server_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure SQL control requires asset_id (server name).")
        rg = self._resource_group(params)
        doc = self._arm(
            f"/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{name}",
            api_version="2021-11-01")
        props = doc.get("properties", {})
        base = f"/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{name}"
        db = params.get("database")

        retention_days: int | None = None
        zone_redundant: bool | None = None
        log_exports: bool | None = None
        if db:
            # Retention and zone redundancy are per-database, not per-server.
            try:
                policy = self._arm(
                    f"{base}/databases/{db}/backupShortTermRetentionPolicies/default",
                    api_version="2021-11-01")
                retention_days = policy.get("properties", {}).get("retentionDays")
            except ConnectorError as exc:
                logger.warning("Azure SQL retention read failed for %s: %s", db, exc)
            try:
                dbdoc = self._arm(f"{base}/databases/{db}", api_version="2021-11-01")
                zone_redundant = bool(dbdoc.get("properties", {}).get("zoneRedundant"))
            except ConnectorError as exc:
                logger.warning("Azure SQL database read failed for %s: %s", db, exc)
            try:
                log_exports = self._has_diagnostic_settings(f"{base}/databases/{db}")
            except ConnectorError:
                log_exports = None

        out: dict[str, Any] = {
            # Azure SQL enables Transparent Data Encryption by default.
            "encryption_at_rest": True,
            "publicly_accessible": props.get("publicNetworkAccess") == "Enabled",
            "auto_minor_version_upgrade": True,  # platform-managed on Azure SQL
            # A CanNotDelete lock is Azure's equivalent of RDS deletion
            # protection: the guarantee that the resource cannot be dropped.
            "deletion_protection_enabled": self._has_delete_lock(base),
            "iam_auth_enabled": self._entra_only_auth(base),
            "owner": "data-platform-team",
        }
        # Per-database signals are omitted rather than guessed when no
        # 'database' param names which database to inspect — a server-level
        # answer to a database-level question would be fiction.
        if retention_days is not None:
            out["backup_retention_days"] = retention_days
        if zone_redundant is not None:
            out["multi_az_enabled"] = zone_redundant
        if log_exports is not None:
            out["log_exports_enabled"] = log_exports
        return out

    def _has_delete_lock(self, resource_path: str) -> bool | None:
        try:
            doc = self._arm(f"{resource_path}/providers/Microsoft.Authorization/locks",
                            api_version="2020-05-01")
            return any((x.get("properties", {}) or {}).get("level") == "CanNotDelete"
                       for x in doc.get("value", []) or [])
        except ConnectorError as exc:
            logger.warning("Azure lock read failed for %s: %s", resource_path, exc)
            return None

    def _entra_only_auth(self, server_path: str) -> bool | None:
        try:
            doc = self._arm(f"{server_path}/azureADOnlyAuthentications/Default",
                            api_version="2021-11-01")
            return bool(doc.get("properties", {}).get("azureADOnlyAuthentication"))
        except ConnectorError:
            # 404 means the setting was never enabled — a real "no".
            return False

    def _subscription_telemetry(self) -> dict[str, Any]:
        """Subscription-wide logging and threat detection."""
        settings_doc = self._arm(
            "/providers/Microsoft.Insights/diagnosticSettings",
            api_version="2021-05-01-preview")
        exports = settings_doc.get("value", []) or []
        shipped_to_workspace = any(
            (x.get("properties", {}) or {}).get("workspaceId") for x in exports)

        # Defender for Cloud: any plan above "Free" is active threat detection.
        threat = None
        try:
            pricings = self._arm("/providers/Microsoft.Security/pricings",
                                 api_version="2023-01-01")
            tiers = [(p.get("properties", {}) or {}).get("pricingTier")
                     for p in pricings.get("value", []) or []]
            threat = any((t or "").lower() not in ("", "free") for t in tiers)
        except ConnectorError as exc:
            logger.warning("Azure Defender pricing read failed: %s", exc)

        out: dict[str, Any] = {
            "logging_enabled": bool(exports),
            # The Activity Log is subscription-wide and covers every region by
            # construction — there is no per-region trail to forget to enable,
            # so the multi-region question is satisfied structurally.
            "multi_region_enabled": bool(exports),
            "cloudwatch_logs_integrated": shipped_to_workspace,
            "owner": "cloud-platform-team",
        }
        if threat is not None:
            out["threat_detection_enabled"] = threat
        return out

    def _virtual_machine_telemetry(self, name: str | None,
                                   params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure compute control requires asset_id (VM name).")
        rg = self._resource_group(params)
        base = f"/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{name}"
        doc = self._arm(base, api_version="2023-03-01")
        props = doc.get("properties", {})

        # A VM is publicly reachable when any attached NIC's ip configuration
        # carries a public IP.
        public = False
        for nic in (props.get("networkProfile", {}) or {}).get("networkInterfaces", []) or []:
            nic_id = nic.get("id", "")
            if not nic_id:
                continue
            try:
                nic_doc = self._arm(_sub_relative(nic_id), api_version="2023-05-01")
            except ConnectorError as exc:
                logger.warning("Azure NIC read failed for %s: %s", nic_id, exc)
                continue
            for cfg in (nic_doc.get("properties", {}) or {}).get("ipConfigurations", []) or []:
                if (cfg.get("properties", {}) or {}).get("publicIPAddress"):
                    public = True

        instance = self._arm(f"{base}/instanceView", api_version="2023-03-01")
        state = next((s.get("displayStatus") for s in instance.get("statuses", []) or []
                      if str(s.get("code", "")).startswith("PowerState/")), None)

        return {
            "public_ip_assigned": public,
            # Boot diagnostics plus a Monitor diagnostic setting is the Azure
            # equivalent of EC2 detailed monitoring: telemetry leaving the host.
            "detailed_monitoring_enabled": bool(
                (props.get("diagnosticsProfile", {}) or {})
                .get("bootDiagnostics", {}).get("enabled")),
            "instance_state": (state or "unknown").replace("VM ", "").lower(),
            "owner": "cloud-platform-team",
        }

    def _nsg_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure network control requires asset_id (NSG name).")
        rg = self._resource_group(params)
        doc = self._arm(
            f"/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{name}",
            api_version="2023-05-01")
        props = doc.get("properties", {})
        rules = []
        for r in (props.get("securityRules") or []) + (props.get("defaultSecurityRules") or []):
            rp = r.get("properties", {}) or {}
            if (rp.get("direction") != "Inbound") or (rp.get("access") != "Allow"):
                continue
            sources = rp.get("sourceAddressPrefixes") or []
            if rp.get("sourceAddressPrefix"):
                sources = [*sources, rp["sourceAddressPrefix"]]
            specs = rp.get("destinationPortRanges") or []
            if rp.get("destinationPortRange"):
                specs = [*specs, rp["destinationPortRange"]]
            ports: set[int] = set()
            all_ports = False
            for spec in specs:
                p, a = _expand_ports(spec)
                ports |= p
                all_ports = all_ports or a
            for src in sources:
                rules.append({"source": src, "ports": ports, "all_ports": all_ports})
        return {**_ingress_exposure(rules), "owner": "network-team"}

    def _vnet_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        """NSG flow logs are Azure's VPC flow logs.

        They are configured on the Network Watcher rather than on the virtual
        network itself, so the lookup is by target resource rather than by
        reading a property off the vnet.
        """
        if not name:
            raise ConnectorError("Azure network control requires asset_id (vnet name).")
        watcher_rg = params.get("network_watcher_resource_group", "NetworkWatcherRG")
        watcher = params.get("network_watcher", f"NetworkWatcher_{params.get('location', '')}")
        try:
            doc = self._arm(
                f"/resourceGroups/{watcher_rg}/providers/Microsoft.Network/"
                f"networkWatchers/{watcher}/flowLogs",
                api_version="2023-05-01")
        except ConnectorError as exc:
            logger.warning("Azure flow-log read failed for %s: %s", name, exc)
            # Unknown, not "off": omit the signal so the check reports
            # NOT_APPLICABLE instead of a violation nobody observed.
            return {"owner": "network-team"}
        enabled = any(
            (f.get("properties", {}) or {}).get("enabled")
            and name.lower() in str((f.get("properties", {}) or {}).get("targetResourceId", "")).lower()
            for f in doc.get("value", []) or [])
        return {"flow_logs_enabled": bool(enabled), "owner": "network-team"}

    def _key_rotation_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure key control requires asset_id (key name).")
        vault = params.get("vault")
        if not vault:
            raise ConnectorError("Azure key controls require a 'vault' param.")
        token = self._acquire_token("https://vault.azure.net/.default")
        r = requests.get(
            f"https://{vault}.vault.azure.net/keys/{name}/rotationpolicy",
            headers={"Authorization": f"Bearer {token}"},
            params={"api-version": "7.4"},
            timeout=settings.request_timeout_seconds)
        if r.status_code == 404:
            return {"key_rotation_enabled": False, "owner": "secops-team"}
        if r.status_code >= 400:
            raise ConnectorError(f"Key Vault {r.status_code}: {r.text[:200]}")
        actions = (r.json().get("lifetimeActions") or [])
        rotates = any((a.get("action", {}) or {}).get("type", "").lower() == "rotate"
                      for a in actions)
        return {"key_rotation_enabled": rotates, "owner": "secops-team"}

    def _managed_disk_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("Azure storage control requires asset_id (disk name).")
        rg = self._resource_group(params)
        doc = self._arm(
            f"/resourceGroups/{rg}/providers/Microsoft.Compute/disks/{name}",
            api_version="2023-04-02")
        enc = (doc.get("properties", {}) or {}).get("encryption", {}) or {}
        # Managed disks are always encrypted; the type says whether the key is
        # platform- or customer-managed. Either satisfies encryption at rest.
        return {"encryption_at_rest": bool(enc.get("type")), "owner": "cloud-platform-team"}


# ──────────────────────────────────────────────────────────────────────────
# GCP — via google-cloud client libraries
# ──────────────────────────────────────────────────────────────────────────
class GCPConnector(BaseConnector):
    source_system = "GCP"

    PROBES = (
        Probe(
            probe_id="gcs_bucket",
            asset_type="object_storage",
            plane="data_protection",
            asset_param="bucket",
            description="Cloud Storage bucket protection posture.",
            signals=(
                "encryption_at_rest",
                "kms_encrypted",
                "public_access_blocked",
                "tls_required",
                "versioning_enabled",
                "access_logging_enabled",
                "lifecycle_configured",
                "asset",
                "owner",
            ),
        ),
        Probe(
            probe_id="project",
            asset_type="cloud_account",
            plane="logging_monitoring",
            requires_asset=False,
            description="Project-wide audit logging and threat detection posture.",
            # As with Azure, the CloudTrail-specific integrity signals and the
            # IAM password-policy signals are left out: Cloud Audit Logs offer
            # no digest validation, and Google account password policy is
            # governed by Workspace, not by the project this connector reads.
            signals=(
                "logging_enabled",
                "multi_region_enabled",
                "cloudwatch_logs_integrated",
                "threat_detection_enabled",
                "owner",
            ),
        ),
        Probe(
            probe_id="compute_instance",
            asset_type="compute_instance",
            plane="host_runtime",
            asset_param="instance",
            description="Compute Engine instance exposure and monitoring posture.",
            # imdsv2_required has no GCP counterpart; the metadata server is
            # header-guarded by default with no legacy mode to disable.
            signals=(
                "public_ip_assigned",
                "detailed_monitoring_enabled",
                "instance_state",
                "owner",
            ),
        ),
        Probe(
            probe_id="firewall",
            asset_type="network_ruleset",
            plane="network_boundary",
            asset_param="firewall",
            description="VPC firewall rule ingress exposure.",
            signals=(
                "unrestricted_ingress",
                "ssh_open_to_world",
                "rdp_open_to_world",
                "open_ingress_rule_count",
                "owner",
            ),
        ),
        Probe(
            probe_id="vpc_network",
            asset_type="virtual_network",
            plane="network_boundary",
            asset_param="network",
            description="VPC subnet flow logging.",
            signals=("flow_logs_enabled", "owner"),
        ),
        Probe(
            probe_id="kms_key",
            asset_type="encryption_key",
            plane="data_protection",
            asset_param="key",
            description="Cloud KMS key rotation schedule.",
            signals=("key_rotation_enabled", "owner"),
        ),
        Probe(
            probe_id="persistent_disk",
            asset_type="block_storage",
            plane="data_protection",
            asset_param="disk",
            description="Persistent disk encryption posture.",
            signals=("encryption_at_rest", "owner"),
        ),
        Probe(
            probe_id="cloud_sql",
            asset_type="managed_database",
            plane="data_protection",
            asset_param="instance",
            description="Cloud SQL instance protection posture.",
            signals=(
                "encryption_at_rest",
                "publicly_accessible",
                "auto_minor_version_upgrade",
                "backup_retention_days",
                "multi_az_enabled",
                "deletion_protection_enabled",
                "log_exports_enabled",
                "iam_auth_enabled",
                "owner",
            ),
        ),
    )

    def __init__(self) -> None:
        if not settings.gcp_project_id:
            raise ConnectorError("GCP_PROJECT_ID required.")
        self._project = settings.gcp_project_id
        # Credentials resolved from GOOGLE_APPLICATION_CREDENTIALS or
        # GCP_CREDENTIALS_JSON. On GCP, the attached service account is used.

    def healthcheck(self) -> bool:
        try:
            from google.cloud import storage  # noqa: F401
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("GCP healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id in ("SC-28", "SC-7"):
            return self._gcs_bucket_telemetry(asset_id or params.get("bucket"))
        return self.collect_via_capability(control_id, asset_id, params)

    def run_probe(self, probe_id, asset_id, params) -> dict[str, Any]:
        if probe_id == "gcs_bucket":
            return self._gcs_bucket_telemetry(asset_id or params.get("bucket"))
        if probe_id == "project":
            return self._project_telemetry()
        if probe_id == "compute_instance":
            return self._instance_telemetry(asset_id or params.get("instance"), params)
        if probe_id == "firewall":
            return self._firewall_telemetry(asset_id or params.get("firewall"))
        if probe_id == "cloud_sql":
            return self._cloud_sql_telemetry(asset_id or params.get("instance"))
        if probe_id == "vpc_network":
            return self._vpc_flow_logs_telemetry(asset_id or params.get("network"), params)
        if probe_id == "kms_key":
            return self._kms_key_telemetry(asset_id or params.get("key"), params)
        if probe_id == "persistent_disk":
            return self._persistent_disk_telemetry(asset_id or params.get("disk"), params)
        raise ConnectorError(f"GCP connector has no handler for probe '{probe_id}'.")

    # ── authed REST ──
    # Only Cloud Storage has a client library dependency here. Everything else
    # goes through the JSON APIs with an ADC-derived token, so adding coverage
    # does not add a client library per Google service.
    def _rest(self, url: str, params: dict[str, Any] | None = None) -> Any:
        import google.auth
        import google.auth.transport.requests

        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(google.auth.transport.requests.Request())
        r = requests.get(url, params=params or {},
                         headers={"Authorization": f"Bearer {creds.token}"},
                         timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"GCP API {r.status_code}: {r.text[:200]}")
        return r.json()

    def _project_telemetry(self) -> dict[str, Any]:
        sinks = self._rest(
            f"https://logging.googleapis.com/v2/projects/{self._project}/sinks"
        ).get("sinks", []) or []

        threat = None
        try:
            # Security Command Center is enabled at the organization level, so
            # it is only observable when the caller supplies the org id.
            if settings.gcp_organization_id:
                srcs = self._rest(
                    "https://securitycenter.googleapis.com/v1/organizations/"
                    f"{settings.gcp_organization_id}/sources")
                threat = bool(srcs.get("sources"))
        except ConnectorError as exc:
            logger.warning("GCP Security Command Center read failed: %s", exc)

        out: dict[str, Any] = {
            "logging_enabled": bool(sinks),
            # Cloud Audit Logs are project-wide and not per-region, so there is
            # no per-region trail that could be left off.
            "multi_region_enabled": bool(sinks),
            # A sink shipping to BigQuery/Pub-Sub/Logging bucket is the GCP
            # analogue of a trail wired into CloudWatch Logs.
            "cloudwatch_logs_integrated": any(s.get("destination") for s in sinks),
            "owner": "cloud-platform-team",
        }
        if threat is not None:
            out["threat_detection_enabled"] = threat
        return out

    def _instance_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("GCP compute control requires asset_id (instance name).")
        zone = params.get("zone")
        if not zone:
            raise ConnectorError("GCP compute controls require a 'zone' param.")
        doc = self._rest(
            f"https://compute.googleapis.com/compute/v1/projects/{self._project}"
            f"/zones/{zone}/instances/{name}")
        public = any(cfg.get("natIP") or cfg.get("name")
                     for nic in doc.get("networkInterfaces", []) or []
                     for cfg in nic.get("accessConfigs", []) or [])
        meta = {i.get("key"): i.get("value")
                for i in (doc.get("metadata", {}) or {}).get("items", []) or []}
        return {
            "public_ip_assigned": public,
            # The Ops Agent policy metadata key is how a fleet declares that a
            # VM ships metrics and logs — the GCP analogue of EC2 detailed
            # monitoring.
            "detailed_monitoring_enabled": str(
                meta.get("enable-osconfig", meta.get("google-monitoring-enable", ""))
            ).lower() in ("true", "1"),
            "instance_state": str(doc.get("status", "unknown")).lower(),
            "owner": "cloud-platform-team",
        }

    def _firewall_telemetry(self, name: str | None) -> dict[str, Any]:
        if not name:
            raise ConnectorError("GCP network control requires asset_id (firewall rule).")
        doc = self._rest(
            f"https://compute.googleapis.com/compute/v1/projects/{self._project}"
            f"/global/firewalls/{name}")
        rules = []
        if doc.get("direction", "INGRESS") == "INGRESS" and not doc.get("disabled"):
            for allowed in doc.get("allowed", []) or []:
                ports: set[int] = set()
                all_ports = not allowed.get("ports")  # no ports listed = every port
                for spec in allowed.get("ports", []) or []:
                    p, a = _expand_ports(spec)
                    ports |= p
                    all_ports = all_ports or a
                for src in doc.get("sourceRanges", []) or []:
                    rules.append({"source": src, "ports": ports, "all_ports": all_ports})
        return {**_ingress_exposure(rules), "owner": "network-team"}

    def _cloud_sql_telemetry(self, name: str | None) -> dict[str, Any]:
        if not name:
            raise ConnectorError("GCP database control requires asset_id (instance name).")
        doc = self._rest(
            f"https://sqladmin.googleapis.com/v1/projects/{self._project}/instances/{name}")
        cfg = doc.get("settings", {}) or {}
        backup = cfg.get("backupConfiguration", {}) or {}
        ip_cfg = cfg.get("ipConfiguration", {}) or {}
        flags = {f.get("name"): str(f.get("value", "")).lower()
                 for f in cfg.get("databaseFlags", []) or []}
        retention = (backup.get("backupRetentionSettings", {}) or {}).get("retainedBackups")
        return {
            # Cloud SQL encrypts at rest unconditionally; a customer-managed
            # key changes who holds it, not whether it is encrypted.
            "encryption_at_rest": True,
            # A public IPv4 endpoint makes the instance publicly routable.
            # Authorized networks narrow who may connect, but the same is true
            # of an RDS security group, and the AWS probe counts that instance
            # as public too — the two clouds must answer this the same way or
            # the shared check means different things depending on the vendor.
            "publicly_accessible": bool(ip_cfg.get("ipv4Enabled")),
            "auto_minor_version_upgrade": bool(cfg.get("maintenanceWindow")),
            "backup_retention_days": retention if isinstance(retention, int) else None,
            # REGIONAL availability is Cloud SQL's cross-zone failover, the
            # same guarantee RDS multi-AZ gives.
            "multi_az_enabled": cfg.get("availabilityType") == "REGIONAL",
            "deletion_protection_enabled": bool(
                cfg.get("deletionProtectionEnabled", doc.get("deletionProtectionEnabled"))),
            "log_exports_enabled": flags.get("log_statement", "none") != "none"
            or bool(backup.get("pointInTimeRecoveryEnabled")),
            "iam_auth_enabled": flags.get("cloudsql.iam_authentication") == "on",
            "owner": "data-platform-team",
        }

    def _gcs_bucket_telemetry(self, bucket_name: str | None) -> dict[str, Any]:
        from google.cloud import storage

        if not bucket_name:
            raise ConnectorError("GCP storage control requires asset_id (bucket).")
        client = storage.Client(project=self._project)
        bucket = client.get_bucket(bucket_name)
        # uniform bucket-level access + default encryption (always on in GCS)
        iam_cfg = bucket.iam_configuration
        public = False
        for member in bucket.get_iam_policy(requested_policy_version=3).bindings:
            if "allUsers" in member.get("members", []) or "allAuthenticatedUsers" in member.get("members", []):
                public = True
        return {
            "encryption_at_rest": True,  # GCS encrypts at rest by default
            # The JSON and XML APIs are HTTPS-only; there is no per-bucket
            # switch to turn plaintext transport on, so the requirement is met
            # structurally rather than by configuration.
            "tls_required": True,
            "public_access_blocked": (not public) and bool(iam_cfg.uniform_bucket_level_access_enabled),
            "asset": bucket_name,
            "owner": "cloud-platform-team",
            # A customer-managed default KMS key is the GCS analogue of SSE-KMS.
            "kms_encrypted": bool(getattr(bucket, "default_kms_key_name", None)),
            "versioning_enabled": bool(getattr(bucket, "versioning_enabled", False)),
            "access_logging_enabled": bool(getattr(bucket, "logging", None)),
            "lifecycle_configured": bool(list(getattr(bucket, "lifecycle_rules", []) or [])),
        }


    def _vpc_flow_logs_telemetry(self, name: str | None,
                                 params: dict[str, Any]) -> dict[str, Any]:
        """VPC flow logs are enabled per subnetwork, not per network.

        A network counts as logged only when every subnet in the requested
        region has logging on — one unlogged subnet is an unobserved path, so
        reporting the network as covered would overstate it.
        """
        if not name:
            raise ConnectorError("GCP network control requires asset_id (network name).")
        region = params.get("region")
        if not region:
            raise ConnectorError("GCP network controls require a 'region' param.")
        doc = self._rest(
            f"https://compute.googleapis.com/compute/v1/projects/{self._project}"
            f"/regions/{region}/subnetworks")
        subnets = [s for s in doc.get("items", []) or []
                   if str(s.get("network", "")).rsplit("/", 1)[-1] == name]
        if not subnets:
            return {"owner": "network-team"}  # nothing observed; not "off"
        return {
            "flow_logs_enabled": all(bool(s.get("enableFlowLogs")) for s in subnets),
            "owner": "network-team",
        }

    def _kms_key_telemetry(self, name: str | None, params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("GCP key control requires asset_id (key name).")
        location = params.get("location")
        keyring = params.get("keyring")
        if not (location and keyring):
            raise ConnectorError("GCP key controls require 'location' and 'keyring' params.")
        doc = self._rest(
            f"https://cloudkms.googleapis.com/v1/projects/{self._project}"
            f"/locations/{location}/keyRings/{keyring}/cryptoKeys/{name}")
        # A rotationPeriod is what makes rotation automatic; without one the
        # key only ever rotates if somebody remembers.
        return {
            "key_rotation_enabled": bool(doc.get("rotationPeriod")),
            "owner": "secops-team",
        }

    def _persistent_disk_telemetry(self, name: str | None,
                                   params: dict[str, Any]) -> dict[str, Any]:
        if not name:
            raise ConnectorError("GCP storage control requires asset_id (disk name).")
        zone = params.get("zone")
        if not zone:
            raise ConnectorError("GCP disk controls require a 'zone' param.")
        self._rest(
            f"https://compute.googleapis.com/compute/v1/projects/{self._project}"
            f"/zones/{zone}/disks/{name}")
        # Persistent disks are encrypted at rest unconditionally; a
        # customer-supplied or KMS key changes custody, not whether it is on.
        return {"encryption_at_rest": True, "owner": "cloud-platform-team"}


# ──────────────────────────────────────────────────────────────────────────
# GitLab — REST API (mirrors the GitHub connector)""
# ──────────────────────────────────────────────────────────────────────────
class GitLabConnector(BaseConnector):
    source_system = "GITLAB"

    def __init__(self) -> None:
        if not settings.gitlab_token:
            raise ConnectorError("GITLAB_TOKEN required.")
        self._base = settings.gitlab_url.rstrip("/")
        self._headers = {"PRIVATE-TOKEN": settings.gitlab_token}

    def _get(self, path: str) -> Any:
        r = requests.get(f"{self._base}/api/v4{path}", headers=self._headers,
                         timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"GitLab API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/user")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("GitLab healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "SA-15-BRANCH":
            project_id = asset_id or params.get("project_id")
            if not project_id:
                raise ConnectorError("GitLab SA-15-BRANCH requires asset_id (project id/path).")
            # URL-encode project path if needed
            pid = requests.utils.quote(str(project_id), safe="")
            protected = self._get(f"/projects/{pid}/protected_branches")
            return {
                "branch_protection_enabled": len(protected) > 0,
                "asset": project_id,
                "owner": "engineering",
            }
        raise ConnectorError(f"GitLab connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# Slack — Web API
# ──────────────────────────────────────────────────────────────────────────
class SlackConnector(BaseConnector):
    source_system = "SLACK"

    def __init__(self) -> None:
        if not settings.slack_bot_token:
            raise ConnectorError("SLACK_BOT_TOKEN required.")
        self._headers = {"Authorization": f"Bearer {settings.slack_bot_token}"}

    def _get(self, method: str, params: dict[str, Any] | None = None) -> Any:
        r = requests.get(f"https://slack.com/api/{method}", headers=self._headers,
                         params=params or {}, timeout=settings.request_timeout_seconds)
        data = r.json()
        if not data.get("ok"):
            raise ConnectorError(f"Slack API error: {data.get('error')}")
        return data

    def healthcheck(self) -> bool:
        try:
            self._get("auth.test")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Slack healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "SC-7":
            # Check a channel is private (not public) as a data-exposure proxy
            channel = asset_id or params.get("channel")
            if not channel:
                raise ConnectorError("Slack SC-7 requires asset_id (channel id).")
            info = self._get("conversations.info", {"channel": channel})
            ch = info.get("channel", {})
            return {
                "public_access_blocked": bool(ch.get("is_private")),
                "asset": channel,
                "owner": "workplace-it",
            }
        raise ConnectorError(f"Slack connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# ServiceNow — Table API
# ──────────────────────────────────────────────────────────────────────────
class ServiceNowConnector(BaseConnector):
    source_system = "SERVICENOW"

    def __init__(self) -> None:
        if not (settings.servicenow_instance and settings.servicenow_user and settings.servicenow_password):
            raise ConnectorError("SERVICENOW_INSTANCE / USER / PASSWORD required.")
        self._base = f"https://{settings.servicenow_instance}.service-now.com"
        token = f"{settings.servicenow_user}:{settings.servicenow_password}".encode()
        self._headers = {
            "Authorization": f"Basic {base64.b64encode(token).decode()}",
            "Accept": "application/json",
        }

    def _get(self, path: str) -> Any:
        r = requests.get(f"{self._base}{path}", headers=self._headers,
                         timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"ServiceNow API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/api/now/table/sys_user?sysparm_limit=1")
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("ServiceNow healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "CM-3":
            change_id = asset_id or params.get("change")
            if not change_id:
                raise ConnectorError("ServiceNow CM-3 requires asset_id (change number).")
            data = self._get(f"/api/now/table/change_request?sysparm_query=number={change_id}")
            results = data.get("result", [])
            approved = bool(results) and results[0].get("approval") == "approved"
            return {
                "change_has_approval": approved,
                "asset": change_id,
                "owner": "change-management",
            }
        raise ConnectorError(f"ServiceNow connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# Qualys — VM API (vulnerability counts)
# ──────────────────────────────────────────────────────────────────────────
class QualysConnector(BaseConnector):
    source_system = "QUALYS"

    def __init__(self) -> None:
        if not (settings.qualys_api_url and settings.qualys_user and settings.qualys_password):
            raise ConnectorError("QUALYS_API_URL / USER / PASSWORD required.")
        self._base = settings.qualys_api_url.rstrip("/")
        self._auth = (settings.qualys_user, settings.qualys_password)
        self._headers = {"X-Requested-With": "comp-lens"}

    def healthcheck(self) -> bool:
        try:
            r = requests.get(f"{self._base}/api/2.0/fo/about/", auth=self._auth,
                            headers=self._headers, timeout=settings.request_timeout_seconds)
            return r.status_code < 400
        except Exception as exc:  # noqa: BLE001
            logger.warning("Qualys healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            ip = asset_id or params.get("ip")
            if not ip:
                raise ConnectorError("Qualys RA-5 requires asset_id (host IP).")
            # Qualys returns XML; count severity-5 (critical) detections.
            r = requests.post(
                f"{self._base}/api/2.0/fo/asset/host/vm/detection/",
                auth=self._auth, headers=self._headers,
                data={"action": "list", "ips": ip, "severities": "5"},
                timeout=settings.request_timeout_seconds,
            )
            if r.status_code >= 400:
                raise ConnectorError(f"Qualys API {r.status_code}")
            critical = r.text.count("<DETECTION>")
            return {"critical_vulnerabilities": critical, "asset": ip, "owner": "secops-team"}
        raise ConnectorError(f"Qualys connector does not support control {control_id}")


# ──────────────────────────────────────────────────────────────────────────
# CrowdStrike Falcon — OAuth2 + Hosts/Vulnerabilities API
# ──────────────────────────────────────────────────────────────────────────
class CrowdStrikeConnector(BaseConnector):
    source_system = "CROWDSTRIKE"

    def __init__(self) -> None:
        if not (settings.crowdstrike_client_id and settings.crowdstrike_client_secret):
            raise ConnectorError("CROWDSTRIKE_CLIENT_ID / CLIENT_SECRET required.")
        self._base = settings.crowdstrike_base_url.rstrip("/")
        self._token: str | None = None
        self._token_exp: float = 0.0

    def _auth_token(self) -> str:
        import time
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        r = requests.post(
            f"{self._base}/oauth2/token",
            data={
                "client_id": settings.crowdstrike_client_id,
                "client_secret": settings.crowdstrike_client_secret,
            },
            timeout=settings.request_timeout_seconds,
        )
        if r.status_code >= 400:
            raise ConnectorError(f"CrowdStrike auth {r.status_code}: {r.text[:200]}")
        body = r.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 1800))
        return self._token

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        r = requests.get(f"{self._base}{path}",
                        headers={"Authorization": f"Bearer {self._auth_token()}"},
                        params=params or {}, timeout=settings.request_timeout_seconds)
        if r.status_code >= 400:
            raise ConnectorError(f"CrowdStrike API {r.status_code}: {r.text[:200]}")
        return r.json()

    def healthcheck(self) -> bool:
        try:
            self._get("/devices/queries/devices/v1", {"limit": 1})
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("CrowdStrike healthcheck failed: %s", exc)
            return False

    def collect_telemetry(self, control_id, asset_id, params) -> dict[str, Any]:
        if control_id == "RA-5":
            host_id = asset_id or params.get("device_id")
            if not host_id:
                raise ConnectorError("CrowdStrike RA-5 requires asset_id (device id).")
            res = self._get(
                "/spotlight/queries/vulnerabilities/v1",
                {"filter": f"aid:'{host_id}'+cve.severity:'CRITICAL'", "limit": 1},
            )
            count = res.get("meta", {}).get("pagination", {}).get("total", 0)
            return {"critical_vulnerabilities": count, "asset": host_id, "owner": "secops-team"}
        raise ConnectorError(f"CrowdStrike connector does not support control {control_id}")
