"""Regression tests against unsafe deployment modes and forged PASS claims."""
import unittest
from security.imperial_eye.deployment_guard import inspect_deployment

NOW = "2026-11-10T09:30:00Z"


def sample(**values):
    source = {"deployment_id": "fixture-eu", "public_network": True,
              "server_mode": "vite_dev", "edge_auth_verified": False,
              "signed_owner_approval_verified": False,
              "publisher_rights_verified": False, "provider_quota_verified": False,
              "oom_failures_24h": 5, "memory_limit_mib": 512,
              "dependency_reviewed": False, "recorded_at": "2026-11-10T09:25:00Z"}
    source.update(values)
    return source


class TestDeploymentGuard(unittest.TestCase):
    def test_exposed_dev_server_denied(self):
        result = inspect_deployment(sample(), now=NOW)
        self.assertIn("PUBLIC_DEVELOPMENT_OR_PREVIEW_SERVER", result["reasons"])
        self.assertIn("REPEATED_OOM", result["reasons"])
        self.assertFalse(result["production_verified"])
        self.assertFalse(result["action_authorized"])

    def test_preview_is_not_production(self):
        result = inspect_deployment(sample(server_mode="vite_preview"), now=NOW)
        self.assertIn("PUBLIC_DEVELOPMENT_OR_PREVIEW_SERVER", result["reasons"])

    def test_safe_looking_input_requires_independent_review(self):
        result = inspect_deployment(sample(server_mode="static_site", edge_auth_verified=True,
                       signed_owner_approval_verified=True, publisher_rights_verified=True,
                       provider_quota_verified=True, oom_failures_24h=0,
                       dependency_reviewed=True), now=NOW)
        self.assertEqual(result["decision"], "INDEPENDENT_REVIEW_REQUIRED")
        self.assertFalse(result["production_verified"])
        self.assertFalse(result["action_authorized"])

    def test_unverified_public_access_is_flagged(self):
        result = inspect_deployment(sample(server_mode="static_site", oom_failures_24h=0), now=NOW)
        self.assertIn("PUBLIC_EDGE_AUTH_NOT_VERIFIED", result["reasons"])

    def test_expired_evidence_fails_closed(self):
        result = inspect_deployment(sample(recorded_at="2026-11-09T08:00:00Z"), now=NOW)
        self.assertIn("STALE_OBSERVATION", result["reasons"])

    def test_missing_schema_denied(self):
        result = inspect_deployment({"password": "do_not_store"}, now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertNotIn("password", str(result))

    def test_boolean_as_oom_count_denied(self):
        result = inspect_deployment(sample(oom_failures_24h=True), now=NOW)
        self.assertEqual(result["decision"], "DENY")

    def test_invalid_future_observation(self):
        result = inspect_deployment(sample(recorded_at="2026-11-11T00:00:00Z"), now=NOW)
        self.assertIn("FUTURE_OBSERVATION", result["reasons"])

    def test_unreviewed_upstream_flagged(self):
        result = inspect_deployment(sample(server_mode="hardened_server",
                      dependency_reviewed=False), now=NOW)
        self.assertIn("DEPENDENCIES_NOT_REVIEWED", result["reasons"])

    def test_zero_quota_not_assumed_safe(self):
        result = inspect_deployment(sample(provider_quota_verified=False), now=NOW)
        self.assertIn("PROVIDER_QUOTA_NOT_VERIFIED", result["reasons"])


if __name__ == "__main__":
    unittest.main()
