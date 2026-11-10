"""Adversarial offline regression tests for evidence-fusion boundaries."""
from __future__ import annotations

import copy
import gzip
import hashlib
import unittest

from security.imperial_eye.evidence_fusion import (
    FusionDenied, fuse_system_events, validate_system_event
)
from security.imperial_eye.digitraffic import decompress_limited, FeedDenied

NOW = "2026-11-10T10:00:00Z"
HASH = hashlib.sha256(b"synthetic provider evidence").hexdigest()


def event(identifier="evt-001", *, kind="render_oom", component="render_service",
          tenant="tenant-alpha", orch="security-orch", asset="render-api",
          when="2026-11-10T09:50:00Z"):
    return {
        "schema": "imperial.eye.system-event.v1",
        "event_id": identifier,
        "tenant_id": tenant,
        "orchestrator_id": orch,
        "component_id": asset,
        "component_kind": component,
        "kind": kind,
        "occurred_at": when,
        "evidence_sha256": HASH
    }


def fuse(records, **changes):
    return fuse_system_events(records, tenant_id="tenant-alpha", now=NOW, **changes)


class EvidenceFusionSecurityTests(unittest.TestCase):
    def test_repeat_oom_stays_critical_and_without_automatic_recovery(self):
        records = [event("evt-001"), event("evt-002", when="2026-11-10T09:55:00Z")]
        r = fuse(records, kill_switch=False)
        self.assertEqual(r["incident_count"], 1)
        self.assertEqual(r["incidents"][0]["event_count"], 2)
        self.assertTrue(r["incidents"][0]["repeated_oom"])
        self.assertEqual(r["incidents"][0]["severity"], "CRITICAL")
        self.assertFalse(r["execution_authorized"])
        self.assertFalse(r["source_authenticity_verified"])
        self.assertFalse(r["production_monitoring_verified"])

    def test_deterministic_across_event_order(self):
        a, b = event("evt-010"), event("evt-011")
        first = fuse([a, b])
        second = fuse([b, a])
        self.assertEqual(first["batch_sha256"], second["batch_sha256"])
        self.assertEqual(first["incidents"], second["incidents"])

    def test_idempotent_exact_replay(self):
        x = event()
        result = fuse([x, copy.deepcopy(x)])
        self.assertEqual(result["input_count"], 2)
        self.assertEqual(result["deduplicated_count"], 1)

    def test_conflicting_replay_denied(self):
        x = event()
        y = copy.deepcopy(x)
        y["evidence_sha256"] = "f" * 64
        with self.assertRaisesRegex(FusionDenied, "CONFLICTING_EVENT_REPLAY_DENIED"):
            fuse([x, y])

    def test_cross_tenant_event_denied(self):
        with self.assertRaisesRegex(FusionDenied, "CROSS_TENANT_EVENT_DENIED"):
            fuse([event(tenant="tenant-other")])

    def test_cross_tenant_orchestrator_metadata_cannot_be_injected(self):
        x = event()
        x["target_tenant"] = "other-tenant"
        with self.assertRaisesRegex(FusionDenied, "EVENT_SCHEMA_DENIED"):
            fuse([x])

    def test_identifying_person_search_forbidden(self):
        x = event()
        x["kind"] = "face_lookup"
        with self.assertRaisesRegex(FusionDenied, "EVENT_CAPABILITY_DENIED"):
            fuse([x])
        x = event()
        x["phone"] = "+123456789"
        with self.assertRaisesRegex(FusionDenied, "EVENT_SCHEMA_DENIED"):
            fuse([x])

    def test_no_arbitrary_camera_identifiers_or_streams(self):
        x = event()
        x["component_kind"] = "rtsp_camera"
        with self.assertRaisesRegex(FusionDenied, "EVENT_CAPABILITY_DENIED"):
            fuse([x])

    def test_mismatched_component_kind_denied(self):
        x = event()
        x["kind"] = "model_worker_absent"
        with self.assertRaisesRegex(FusionDenied, "EVENT_CAPABILITY_DENIED"):
            fuse([x])

    def test_same_component_id_not_different_types(self):
        x = event()
        y = event("evt-002", kind="model_worker_absent", component="nca_worker")
        with self.assertRaisesRegex(FusionDenied, "CONFLICTING_COMPONENT_IDENTITY_DENIED"):
            fuse([x, y])

    def test_stale_and_future_denied(self):
        with self.assertRaisesRegex(FusionDenied, "STALE_EVENT_DENIED"):
            fuse([event(when="2026-11-09T00:00:00Z")])
        with self.assertRaisesRegex(FusionDenied, "FUTURE_EVENT_DENIED"):
            fuse([event(when="2026-11-11T00:00:00Z")])

    def test_naive_time_denied(self):
        with self.assertRaisesRegex(FusionDenied, "TIMEZONE_REQUIRED"):
            fuse([event(when="2026-11-10T09:00:00")])

    def test_wrong_hash_denied(self):
        x = event()
        x["evidence_sha256"] = "redacted"
        with self.assertRaisesRegex(FusionDenied, "INVALID_EVIDENCE_HASH"):
            fuse([x])

    def test_empty_events_not_monitoring_pass(self):
        r = fuse([], kill_switch=False)
        self.assertEqual(r["incident_count"], 0)
        self.assertFalse(r["production_monitoring_verified"])
        self.assertFalse(r["independent_qa_verified"])
        self.assertFalse(r["execution_authorized"])

    def test_bool_kill_switch_is_required(self):
        with self.assertRaisesRegex(FusionDenied, "INVALID_KILL_SWITCH"):
            fuse([], kill_switch=0)

    def test_bounded_input_event_count(self):
        with self.assertRaisesRegex(FusionDenied, "INVALID_EVENT_BATCH"):
            fuse([event("evt-001")] * 201)

    def test_batch_cannot_include_freeform_secrets(self):
        x = event()
        x["details"] = {"cookie": "private"}
        with self.assertRaisesRegex(FusionDenied, "EVENT_SCHEMA_DENIED"):
            fuse([x])

    def test_mixed_components_have_different_scoped_incidents(self):
        x = event()
        y = event("evt-002", kind="model_worker_absent", component="nca_worker",
                  asset="nca-worker", orch="operations-orch")
        r = fuse([x,y])
        self.assertEqual(r["incident_count"],2)
        self.assertEqual({v["orchestrator_id"] for v in r["incidents"]},
                         {"security-orch", "operations-orch"})


class DigitrafficEnvelopeTests(unittest.TestCase):
    def test_padded_gzip_trailing_bytes_denied(self):
        raw = gzip.compress(b'{"type":"FeatureCollection","features":[]}') + b"junk"
        with self.assertRaisesRegex(FeedDenied, "DECOMPRESSED_RESPONSE_TOO_LARGE_OR_TRUNCATED"):
            decompress_limited(raw, "gzip")

    def test_concatenated_gzip_member_denied(self):
        raw = gzip.compress(b'{"a":1}') + gzip.compress(b'{"malicious":"payload"}')
        with self.assertRaisesRegex(FeedDenied, "DECOMPRESSED_RESPONSE_TOO_LARGE_OR_TRUNCATED"):
            decompress_limited(raw,"gzip")

    def test_unmodified_gzip_still_decodes(self):
        content = b'{"official":true}'
        self.assertEqual(decompress_limited(gzip.compress(content),"gzip"),content)

    def test_empty_gzip_member_rejected_if_trailing(self):
        raw = gzip.compress(b'{"legitimate":true}') + gzip.compress(b"")
        with self.assertRaises(FeedDenied):
            decompress_limited(raw,"gzip")


if __name__ == "__main__":
    unittest.main()
