"""ProxySG 存取紀錄(main 格式)與 Google Cloud 稽核紀錄(Admin Activity)。

規則條件會用到的欄位要能指定;驅動欄位切換時,衍生欄位要跟著一致。
"""
from __future__ import annotations

import json
import shlex
from datetime import datetime, timezone

import pytest

from cyberrange import find_spec, load_spec, render_one

SG = load_spec(find_spec("broadcom", "proxysg", "7.x", "proxy.access_log.main"))
GCP = load_spec(find_spec("google", "cloud-audit", "v1", "cloud_audit.admin_activity"))

# ProxySG 7.3 文件列出的 main 格式欄位順序
MAIN_FIELDS = [
    "date", "time", "time-taken", "c-ip", "sc-status", "s-action", "sc-bytes", "cs-bytes",
    "cs-method", "cs-uri-scheme", "cs-host", "cs-uri-port", "cs-uri-path", "cs-uri-query",
    "cs-username", "cs-auth-group", "s-supplier-name", "rs(Content-Type)", "cs(Referer)",
    "cs(User-Agent)", "sc-filter-result", "cs-categories", "x-virus-id", "s-ip"]

# operation -> (serviceName, methodName, resource.type, permission)
GCP_OPERATIONS = {
    "set_iam_policy": ("cloudresourcemanager.googleapis.com", "SetIamPolicy", "project",
                       "resourcemanager.projects.setIamPolicy"),
    "create_sa_key": ("iam.googleapis.com", "google.iam.admin.v1.CreateServiceAccountKey",
                      "service_account", "iam.serviceAccountKeys.create"),
    "firewall_insert": ("compute.googleapis.com", "v1.compute.firewalls.insert",
                        "gce_firewall_rule", "compute.firewalls.create"),
    "firewall_patch": ("compute.googleapis.com", "v1.compute.firewalls.patch",
                       "gce_firewall_rule", "compute.firewalls.update"),
    "vm_insert": ("compute.googleapis.com", "v1.compute.instances.insert", "gce_instance",
                  "compute.instances.create"),
    "vm_delete": ("compute.googleapis.com", "v1.compute.instances.delete", "gce_instance",
                  "compute.instances.delete"),
    "gke_create_cluster": ("container.googleapis.com",
                           "google.container.v1.ClusterManager.CreateCluster", "gke_cluster",
                           "container.clusters.create"),
    "gke_delete_cluster": ("container.googleapis.com",
                           "google.container.v1.ClusterManager.DeleteCluster", "gke_cluster",
                           "container.clusters.delete"),
}


def _sg(params: dict | None = None, at: datetime | None = None) -> dict[str, str]:
    line = render_one(SG, params, at=at)
    tokens = shlex.split(line)  # 空白分隔,含空白的欄位以雙引號包住
    assert len(tokens) == len(MAIN_FIELDS), line
    return dict(zip(MAIN_FIELDS, tokens))


def _gcp(params: dict | None = None, at: datetime | None = None) -> dict:
    line = render_one(GCP, params, at=at)
    assert "\n" not in line
    return json.loads(line)


# ───────────────────────── ProxySG ─────────────────────────


def test_proxysg_line_has_the_24_main_fields_and_no_syslog_prefix() -> None:
    for _ in range(100):
        f = _sg()
        assert f["sc-status"].isdigit() and f["time-taken"].isdigit()
        assert f["sc-bytes"].isdigit() and f["cs-bytes"].isdigit()
    line = render_one(SG)
    assert not line.startswith("<") and line[:4].isdigit()


def test_proxysg_user_agent_and_categories_are_quoted() -> None:
    line = render_one(SG, {"verdict": "denied", "user_agent_pool": "Example Agent/1.0",
                           "denied_category": "Malicious Sources/Malnets"})
    assert ' "Example Agent/1.0" DENIED "Malicious Sources/Malnets" - ' in line


def test_proxysg_denied_fields_stay_consistent() -> None:
    for _ in range(60):
        f = _sg({"verdict": "denied"})
        assert (f["sc-filter-result"], f["sc-status"], f["s-action"]) == (
            "DENIED", "403", "TCP_DENIED")
        assert (f["s-supplier-name"], f["rs(Content-Type)"]) == ("-", "-")
        assert f["cs-categories"] in SG.default_params()["denied_category_pool"]


def test_proxysg_allowed_fields_stay_consistent() -> None:
    defaults = SG.default_params()
    for _ in range(60):
        f = _sg({"verdict": "allowed"})
        assert f["sc-filter-result"] == "OBSERVED"
        assert f["sc-status"] in defaults["allowed_status_weights"]
        assert f["s-action"] in defaults["allowed_action_weights"]
        # 快取命中沒有上游連線;304 沒有本文
        assert f["s-supplier-name"] == ("-" if f["s-action"] == "TCP_HIT" else f["cs-host"])
        if f["sc-status"] == "304":
            assert f["rs(Content-Type)"] == "-"
        else:
            assert f["rs(Content-Type)"] in defaults["content_type_weights"]
        assert f["cs-categories"] in defaults["allowed_category_pool"]


def test_proxysg_cache_and_size_couplings() -> None:
    for _ in range(300):
        f = _sg({})
        # POST 不會由快取回應
        assert not (f["cs-method"] == "POST" and f["s-action"] == "TCP_HIT")
        size = int(f["sc-bytes"])
        if f["sc-status"] in ("302", "304"):
            assert size < 600
        if f["sc-status"] == "403":
            assert size < 2500


def test_proxysg_port_follows_scheme() -> None:
    assert _sg({"cs_uri_scheme": "https"})["cs-uri-port"] == "443"
    assert _sg({"cs_uri_scheme": "http"})["cs-uri-port"] == "80"


def test_proxysg_rule_conditions_can_be_pinned() -> None:
    f = _sg({"verdict": "denied", "client_pool": "198.51.100.5", "user_pool": "mallory",
             "host_pool": "c2.example.net", "cs_uri_path": "/gate.php", "cs_uri_query": "?id=7",
             "cs_method": "POST", "cs_categories": "Command and Control",
             "user_agent_pool": "python-requests/2.31.0", "proxy_ip": "192.0.2.99"})
    assert (f["c-ip"], f["cs-username"], f["cs-host"], f["cs-uri-path"], f["cs-uri-query"]) == (
        "198.51.100.5", "mallory", "c2.example.net", "/gate.php", "?id=7")
    assert (f["cs-method"], f["cs-categories"], f["cs(User-Agent)"], f["s-ip"]) == (
        "POST", "Command and Control", "python-requests/2.31.0", "192.0.2.99")
    assert (f["sc-filter-result"], f["sc-status"], f["s-action"]) == (
        "DENIED", "403", "TCP_DENIED")


def test_proxysg_date_and_time_are_gmt() -> None:
    at = datetime(2026, 3, 9, 23, 5, 7, tzinfo=timezone.utc)
    f = _sg(at=at)
    assert (f["date"], f["time"]) == ("2026-03-09", "23:05:07")


# ───────────────────────── Google Cloud ─────────────────────────


def test_gcp_every_entry_is_single_line_valid_json() -> None:
    for _ in range(300):
        _gcp()
    for operation in GCP_OPERATIONS:
        for outcome in ("success", "denied"):
            _gcp({"operation": operation, "outcome": outcome})


def test_gcp_envelope_is_an_admin_activity_audit_log_entry() -> None:
    d = _gcp({"project_id": "example-project-999"})
    assert d["protoPayload"]["@type"] == "type.googleapis.com/google.cloud.audit.AuditLog"
    assert d["logName"] == (
        "projects/example-project-999/logs/cloudaudit.googleapis.com%2Factivity")
    assert d["resource"]["labels"]["project_id"] == "example-project-999"
    assert {"insertId", "timestamp", "severity", "resource"} <= set(d)


@pytest.mark.parametrize("operation", sorted(GCP_OPERATIONS))
def test_gcp_service_method_resource_and_permission_follow_operation(operation: str) -> None:
    service, method, resource_type, permission = GCP_OPERATIONS[operation]
    for _ in range(10):
        d = _gcp({"operation": operation})
        pp = d["protoPayload"]
        assert (pp["serviceName"], pp["methodName"], d["resource"]["type"]) == (
            service, method, resource_type)
        authz = pp["authorizationInfo"][0]
        assert authz["permission"] == permission
        assert authz["resource"] == pp["resourceName"]


def test_gcp_resource_name_matches_the_named_object() -> None:
    common = {"project_id": "example-project-999", "zone": "europe-west1-b",
              "location": "europe-west1"}
    cases = {
        "set_iam_policy": "projects/example-project-999",
        "firewall_insert": "projects/example-project-999/global/firewalls/fw-x",
        "firewall_patch": "projects/example-project-999/global/firewalls/fw-x",
        "vm_insert": "projects/example-project-999/zones/europe-west1-b/instances/vm-x",
        "vm_delete": "projects/example-project-999/zones/europe-west1-b/instances/vm-x",
        "gke_create_cluster":
            "projects/example-project-999/locations/europe-west1/clusters/gke-x",
        "gke_delete_cluster":
            "projects/example-project-999/locations/europe-west1/clusters/gke-x",
    }
    for operation, expected in cases.items():
        d = _gcp({**common, "operation": operation, "firewall_pool": "fw-x",
                  "instance_pool": "vm-x", "cluster_pool": "gke-x"})
        assert d["protoPayload"]["resourceName"] == expected

    labels = _gcp({**common, "operation": "vm_delete"})["resource"]["labels"]
    assert labels["zone"] == "europe-west1-b" and labels["instance_id"].isdigit()
    labels = _gcp({**common, "operation": "gke_delete_cluster",
                   "cluster_pool": "gke-x"})["resource"]["labels"]
    assert (labels["cluster_name"], labels["location"]) == ("gke-x", "europe-west1")


def test_gcp_service_account_key_names_the_target_account() -> None:
    d = _gcp({"operation": "create_sa_key", "project_id": "example-project-999",
              "target_sa_name": "deployer"})
    email = "deployer@example-project-999.iam.gserviceaccount.com"
    labels = d["resource"]["labels"]
    assert labels["email_id"] == email
    assert d["protoPayload"]["request"]["name"] == f"projects/-/serviceAccounts/{email}"
    assert d["protoPayload"]["resourceName"] == (
        f"projects/-/serviceAccounts/{labels['unique_id']}")
    assert len(labels["unique_id"]) == 21 and labels["unique_id"].isdigit()


def test_gcp_outcome_drives_status_granted_and_severity() -> None:
    for operation in GCP_OPERATIONS:
        ok = _gcp({"operation": operation, "outcome": "success"})
        assert ok["protoPayload"]["status"] == {}
        assert ok["protoPayload"]["authorizationInfo"][0]["granted"] is True
        assert ok["severity"] == "NOTICE"

        no = _gcp({"operation": operation, "outcome": "denied"})
        status = no["protoPayload"]["status"]
        assert status["code"] == 7
        assert GCP_OPERATIONS[operation][3] in status["message"]
        assert no["protoPayload"]["resourceName"] in status["message"]
        assert no["protoPayload"]["authorizationInfo"][0]["granted"] is False
        assert no["severity"] == "ERROR"


def test_gcp_long_running_operations_carry_the_first_entry_marker() -> None:
    for operation, (service, *_rest) in GCP_OPERATIONS.items():
        ok = _gcp({"operation": operation, "outcome": "success"})
        if service in ("compute.googleapis.com", "container.googleapis.com"):
            assert ok["operation"]["first"] is True
            assert ok["operation"]["producer"] == service
        else:
            assert "operation" not in ok
        assert "operation" not in _gcp({"operation": operation, "outcome": "denied"})


def test_gcp_iam_binding_is_selectable_and_delta_only_on_success() -> None:
    params = {"operation": "set_iam_policy", "iam_role": "roles/editor",
              "iam_member": "serviceAccount:x@example-project-123.iam.gserviceaccount.com"}
    ok = _gcp({**params, "outcome": "success"})["protoPayload"]
    binding = ok["request"]["policy"]["bindings"][0]
    assert (binding["role"], binding["members"]) == ("roles/editor", [params["iam_member"]])
    delta = ok["serviceData"]["policyDelta"]["bindingDeltas"][0]
    assert (delta["action"], delta["role"], delta["member"]) == (
        "ADD", "roles/editor", params["iam_member"])
    assert "serviceData" not in _gcp({**params, "outcome": "denied"})["protoPayload"]


def test_gcp_firewall_rule_content_is_selectable() -> None:
    for operation in ("firewall_insert", "firewall_patch"):
        req = _gcp({"operation": operation, "fw_source_range": "203.0.113.0/24",
                    "fw_port": "3389", "firewall_pool": "fw-x"})["protoPayload"]["request"]
        assert req["name"] == "fw-x"
        assert req["sourceRanges"] == ["203.0.113.0/24"]
        assert req["alloweds"] == [{"IPProtocol": "tcp", "ports": ["3389"]}]


def test_gcp_actor_and_source_can_be_pinned() -> None:
    d = _gcp({"principal_pool": "ci-deployer@example-project-123.iam.gserviceaccount.com",
              "src_pool": "198.51.100.5", "user_agent_pool": "example-agent/1.0"})
    pp = d["protoPayload"]
    assert pp["authenticationInfo"] == {
        "principalEmail": "ci-deployer@example-project-123.iam.gserviceaccount.com",
        "principalSubject":
            "serviceAccount:ci-deployer@example-project-123.iam.gserviceaccount.com"}
    assert pp["requestMetadata"]["callerIp"] == "198.51.100.5"
    assert pp["requestMetadata"]["callerSuppliedUserAgent"] == "example-agent/1.0"

    user = _gcp({"principal_email": "alice@example.com"})["protoPayload"]["authenticationInfo"]
    assert user["principalSubject"] == "user:alice@example.com"


def test_gcp_timestamps_are_utc() -> None:
    at = datetime(2026, 3, 9, 23, 5, 7, 123456, tzinfo=timezone.utc)
    d = _gcp(at=at)
    assert d["timestamp"] == "2026-03-09T23:05:07.123456Z"
    assert d["receiveTimestamp"] == "2026-03-09T23:05:07.123456Z"
    assert d["protoPayload"]["requestMetadata"]["requestAttributes"]["time"] == d["timestamp"]
