"""Fintraffic metadata schema, transport and privacy-negative regression tests."""
from __future__ import annotations

import gzip
import hashlib
import json
import unittest
from unittest.mock import patch

from security.imperial_eye.digitraffic import (
    API, HOST, PATH, FeedDenied, decompress_limited, normalize, fetch_once
)


def example(station="C12345", preset="C1234501", collection=True):
    return {
        "type":"FeatureCollection",
        "features":[{
            "type":"Feature",
            "geometry":{"type":"Point","coordinates":[24.8,60.2]},
            "properties":{
                "id":station,"name":"Public road weather camera",
                "state":"ACTIVE","collectionStatus":"GATHERING",
                "presets":[{"id":preset,"inCollection":collection}]
            }
        }]
    }


class FakeResponse:
    def __init__(self, data=None, status=200, encoding="gzip"):
        self.status=status
        self.encoding=encoding
        payload=json.dumps(data if data is not None else example()).encode()
        self.data=gzip.compress(payload) if encoding=="gzip" else payload

    def getheader(self, name):
        return self.encoding if name=="Content-Encoding" else None

    def read(self, max_count):
        return self.data[:max_count]


class FakeConnection:
    calls=[]
    response=FakeResponse()
    def __init__(self, host, port, *, timeout, context):
        self.calls.append(("connect",host,port,timeout))
    def request(self, method, path, *, headers):
        self.calls.append(("request",method,path,dict(headers)))
    def getresponse(self): return self.response
    def close(self): self.calls.append(("close",))


class DigitrafficTests(unittest.TestCase):
    def setUp(self):
        FakeConnection.calls=[]
        FakeConnection.response=FakeResponse()

    def fetch(self, **options):
        return fetch_once(live=True,transport=FakeConnection,**options)

    def test_offline_by_default_no_network(self):
        with self.assertRaisesRegex(FeedDenied,"EXPLICIT_PUBLIC_METADATA"):
            fetch_once()
        self.assertEqual(FakeConnection.calls,[])

    def test_fixed_host_and_http_get(self):
        result=self.fetch(limit=2)
        self.assertEqual(FakeConnection.calls[0][1:3],(HOST,443))
        self.assertEqual(FakeConnection.calls[1][1:3],("GET",PATH))
        self.assertEqual(result["api"],API)
        self.assertEqual(result["sample_size"],1)
        self.assertEqual(result["station_samples"][0]["published_image_url"],
                         "https://weathercam.digitraffic.fi/C1234501.jpg")
        self.assertEqual(result["license"],"CC BY 4.0")
        self.assertFalse(result["individual_image_freshness_verified"])

    def test_proper_service_headers_without_personal_data(self):
        self.fetch()
        headers=FakeConnection.calls[1][3]
        self.assertEqual(headers["Accept-Encoding"],"gzip")
        self.assertIn("IMPERIALCore",headers["Digitraffic-User"])
        self.assertNotIn("Authorization",headers)
        self.assertNotIn("Cookie",headers)
        self.assertNotIn("@",headers["Digitraffic-User"])

    def test_unknown_source_redirect_denied_not_followed(self):
        FakeConnection.response=FakeResponse(status=301)
        with self.assertRaisesRegex(FeedDenied,"OFFICIAL_API_HTTP_301"):
            self.fetch()
        self.assertEqual(sum(1 for x in FakeConnection.calls if x[0]=="connect"),1)

    def test_not_found_and_throttling_fail_closed(self):
        for code in (404,429,503):
            FakeConnection.response=FakeResponse(status=code)
            with self.assertRaises(FeedDenied):
                self.fetch()

    def test_invalid_gzip_and_bomb_denied(self):
        with self.assertRaisesRegex(FeedDenied,"INVALID_GZIP"):
            decompress_limited(b"not-gzip","gzip")
        with self.assertRaises(FeedDenied):
            decompress_limited(gzip.compress(b"x"*31_000_000),"gzip")
        with self.assertRaises(FeedDenied):
            decompress_limited(b"something","br")

    def test_no_image_for_uncollected_presets(self):
        result=normalize(example(collection=False),fetched_at="2026-11-03T08:00:00Z",
                         source_sha256=hashlib.sha256(b"example").hexdigest())
        self.assertIsNone(result["station_samples"][0]["published_image_url"])

    def test_private_ip_or_nonfinite_location_rejected(self):
        payload=example()
        payload["features"][0]["geometry"]["coordinates"]=[192.168,99]
        with self.assertRaisesRegex(FeedDenied,"NO_VALID_OFFICIAL"):
            normalize(payload,fetched_at="2026-11-03T08:00:00Z",source_sha256="e"*64)

    def test_person_search_fields_not_retained(self):
        payload=example()
        payload["features"][0]["properties"]["face_embedding"]=[0.1,0.2]
        payload["features"][0]["properties"]["person_id"]="secret-person"
        result=normalize(payload,fetched_at="2026-11-03T08:00:00Z",source_sha256="e"*64)
        string=json.dumps(result)
        self.assertNotIn("face_embedding",string)
        self.assertNotIn("person_id",string)

    def test_invalid_schema_rejected(self):
        with self.assertRaisesRegex(FeedDenied,"UNRECOGNIZED_GEOJSON_FORMAT"):
            normalize({"stations":[]},fetched_at="2026-11-03T08:00:00Z",source_sha256="e"*64)

    def test_deduplicate_and_limit(self):
        payload=example()
        payload["features"].append(payload["features"][0])
        result=normalize(payload,fetched_at="2026-11-03T08:00:00Z",source_sha256="e"*64,limit=1)
        self.assertEqual(result["sample_size"],1)
        self.assertEqual(result["total_valid_stations_in_response"],1)

    def test_unsupported_preset_never_constructs_image_url(self):
        payload=example(preset="https://evil.test/img")
        result=normalize(payload,fetched_at="2026-11-03T08:00:00Z",source_sha256="e"*64)
        self.assertIsNone(result["station_samples"][0]["published_image_url"])

    def test_missing_location_rejected(self):
        payload=example()
        payload["features"][0]["geometry"]={"type":"Point","coordinates":[]}
        with self.assertRaises(FeedDenied):
            normalize(payload,fetched_at="2026-11-03T08:00:00Z",source_sha256="e"*64)

    def test_live_only_exact_boolean_and_bounded_timeout(self):
        with self.assertRaises(FeedDenied):
            fetch_once(live=1,transport=FakeConnection)
        with self.assertRaises(FeedDenied):
            self.fetch(timeout=30)

    def test_public_metadata_not_live_video(self):
        result=self.fetch()
        self.assertFalse(result["realtime_video"])
        self.assertFalse(result["facial_recognition"])
        self.assertFalse(result["owner_biometrics_collected"])
        self.assertTrue(result["sample_is_not_complete_catalog"])


if __name__=="__main__":
    unittest.main()
