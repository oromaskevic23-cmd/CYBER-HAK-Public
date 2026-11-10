"""Synthetic-only event tests; no real cameras or identities in fixtures."""
import copy
import unittest
from security.imperial_eye.synthetic_incident import (
    SyntheticEventDenied, summarize_synthetic_events
)

NOW = "2026-11-10T09:30:00Z"


def event(name="event-001", kind="camera_offline"):
    return {"tenant_id": "tenant-001", "source_id": "synthetic-a",
            "event_id": name, "event_type": kind,
            "occurred_at": "2026-11-10T09:25:00Z", "source_mode": "SYNTHETIC"}


class TestSyntheticEvent(unittest.TestCase):
    def test_simple_incident(self):
        out = summarize_synthetic_events([event()], tenant_id="tenant-001", now=NOW)
        self.assertEqual(out["event_counts"], {"camera_offline": 1})
        self.assertEqual(out["accepted_unique_events"], 1)
        self.assertEqual(out["camera_connections"], 0)
        self.assertFalse(out["production_authorized"])
        self.assertFalse(out["individual_tracking"])

    def test_duplicate_deduplicated(self):
        out = summarize_synthetic_events([event(), event()], tenant_id="tenant-001", now=NOW)
        self.assertEqual(out["accepted_unique_events"], 1)
        self.assertEqual(out["deduplicated"], 1)

    def test_conflicting_duplicate_rejected(self):
        with self.assertRaisesRegex(SyntheticEventDenied, "CONFLICTING_EVENT_ID"):
            summarize_synthetic_events([event(),event(kind="camera_tamper")],
                                       tenant_id="tenant-001", now=NOW)

    def test_cross_tenant_rejected(self):
        e = event()
        e["tenant_id"] = "other-tenant"
        with self.assertRaisesRegex(SyntheticEventDenied, "CROSS_TENANT_EVENT"):
            summarize_synthetic_events([e], tenant_id="tenant-001", now=NOW)

    def test_real_video_rejected(self):
        e = event()
        e["source_mode"] = "RTSP_LIVE"
        with self.assertRaisesRegex(SyntheticEventDenied, "NO_PRODUCTION_VIDEO_OR_REAL_SENSORS"):
            summarize_synthetic_events([e], tenant_id="tenant-001", now=NOW)

    def test_face_search_rejected(self):
        with self.assertRaisesRegex(SyntheticEventDenied, "UNAPPROVED_EVENT_CLASS"):
            summarize_synthetic_events([event(kind="face_search")],
                                       tenant_id="tenant-001", now=NOW)

    def test_user_image_and_ip_fields_rejected(self):
        e = event()
        e["camera_url"] = "rtsp://camera-secret/"
        with self.assertRaisesRegex(SyntheticEventDenied, "INVALID_EVENT_SCHEMA"):
            summarize_synthetic_events([e], tenant_id="tenant-001", now=NOW)

    def test_future_and_old_timestamps_rejected(self):
        for ts in ("2026-11-10T09:31:00Z", "2026-11-10T07:00:00Z"):
            e = event()
            e["occurred_at"] = ts
            with self.assertRaisesRegex(SyntheticEventDenied, "STALE_OR_FUTURE_EVENT"):
                summarize_synthetic_events([e], tenant_id="tenant-001", now=NOW)

    def test_large_batch_rejected(self):
        with self.assertRaisesRegex(SyntheticEventDenied, "EVENT_BATCH_EXCEEDS_LIMIT"):
            summarize_synthetic_events([event()] * 257,tenant_id="tenant-001",now=NOW)

    def test_deterministic_sha_independent_of_order(self):
        a = event("event-001", "camera_offline")
        b = event("event-002", "camera_tamper")
        r1 = summarize_synthetic_events([a,b],tenant_id="tenant-001",now=NOW)
        r2 = summarize_synthetic_events([b,a],tenant_id="tenant-001",now=NOW)
        self.assertEqual(r1["evidence_sha256"],r2["evidence_sha256"])
        self.assertEqual(r1["event_counts"], {"camera_offline": 1, "camera_tamper": 1})

    def test_empty_safe(self):
        out = summarize_synthetic_events([],tenant_id="tenant-001",now=NOW)
        self.assertEqual(out["accepted_unique_events"],0)
        self.assertEqual(out["camera_connections"],0)

    def test_no_individual_identifiers_in_response(self):
        out = summarize_synthetic_events([event()],tenant_id="tenant-001",now=NOW)
        self.assertNotIn("tenant-001",str(out))
        self.assertNotIn("synthetic-a",str(out))


if __name__ == "__main__":
    unittest.main()
