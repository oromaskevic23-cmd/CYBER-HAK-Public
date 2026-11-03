"""Tests for a permission-scoped camera information index."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from security.imperial_eye.catalog import CatalogDenied, load_catalog, validate_record

FIXTURE = Path("security/imperial_eye/data/sources.json")


class PublicSourceTests(unittest.TestCase):
    def test_official_portals_only(self):
        records = load_catalog(FIXTURE)
        self.assertEqual(len(records), 2)
        self.assertEqual({x["id"] for x in records},
                         {"fi-fintraffic-official", "ny-511-official"})
        self.assertTrue(all(x["record_kind"]=="official_publisher_portal" for x in records))

    def test_no_camera_credentials_or_video_streams(self):
        for value in load_catalog(FIXTURE):
            self.assertNotIn("password", value)
            self.assertNotIn("stream", value)
            self.assertNotIn("rtsp", value)
            self.assertNotIn("face", value)
            self.assertEqual(value["permission_basis"],"official_public_portal_link")

    def test_rejects_direct_ip_camera(self):
        item=copy.deepcopy(load_catalog(FIXTURE)[0])
        item["portal_url"]="http://192.168.0.1:554/live"
        with self.assertRaises(CatalogDenied):
            validate_record(item)

    def test_rejects_external_portal_and_redirector(self):
        item=copy.deepcopy(load_catalog(FIXTURE)[0])
        item["portal_url"]="https://bad.example.com/redirect"
        with self.assertRaisesRegex(CatalogDenied,"PUBLISHER_HOST_MISMATCH"):
            validate_record(item)

    def test_rejects_embedded_credentials_and_localhost(self):
        item=copy.deepcopy(load_catalog(FIXTURE)[0])
        item["portal_url"]="https://admin:secret@511ny.org/live"
        with self.assertRaises(CatalogDenied):
            validate_record(item)
        item["portal_url"]="https://localhost/camera"
        with self.assertRaises(CatalogDenied):
            validate_record(item)

    def test_no_direct_cctv_feed_entries(self):
        item=copy.deepcopy(load_catalog(FIXTURE)[0])
        item["record_kind"]="direct_rtsp_stream"
        with self.assertRaisesRegex(CatalogDenied,"NO_DIRECT_CAMERA_OR_STREAM_COLLECTION"):
            validate_record(item)

    def test_rejects_unapproved_authorization_basis(self):
        item=copy.deepcopy(load_catalog(FIXTURE)[0])
        item["permission_basis"]="exposed_default_password"
        with self.assertRaises(CatalogDenied):
            validate_record(item)

    def test_rejects_unknown_fields_and_user_photos(self):
        item=copy.deepcopy(load_catalog(FIXTURE)[0])
        item["face_template"]="sensitive"
        with self.assertRaisesRegex(CatalogDenied,"INVALID_RECORD_SCHEMA"):
            validate_record(item)

    def test_rejects_privacy_policy_drift(self):
        data=json.loads(FIXTURE.read_text())
        data["capabilities"]["face_search"]=True
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"bad.json"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(CatalogDenied,"PROHIBITED_SURVEILLANCE_CAPABILITIES"):
                load_catalog(path)

    def test_rejects_duplicate_source(self):
        data=json.loads(FIXTURE.read_text())
        data["sources"].append(copy.deepcopy(data["sources"][0]))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"dup.json"
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(CatalogDenied,"DUPLICATE_SOURCE_ID"):
                load_catalog(path)


if __name__ == "__main__":
    unittest.main()
