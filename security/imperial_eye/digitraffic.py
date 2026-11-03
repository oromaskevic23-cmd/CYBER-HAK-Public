"""IMPERIAL EYE — one bounded, fixed-host, public Fintraffic API read.

No password, camera probing, image downloads, private feeds or face tracking.
The station inventory is metadata, NOT a claim of live video availability.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import http.client
import json
import re
import ssl
import zlib

HOST = "tie.digitraffic.fi"
PATH = "/api/weathercam/v1/stations"
API = f"https://{HOST}{PATH}"
DOCUMENTATION = "https://www.digitraffic.fi/en/road-traffic/"
ATTRIBUTION = "Source: Fintraffic / Digitraffic (CC BY 4.0)"
MAX_COMPRESSED = 8_000_000
MAX_JSON = 30_000_000
STATION_ID = re.compile(r"[A-Za-z0-9_-]{1,45}\Z")
PRESET_ID = re.compile(r"C[0-9]{5,12}\Z")


class FeedDenied(ValueError):
    """Reject an unsupported or untrusted weather-camera response."""


def decompress_limited(raw: bytes, encoding: str) -> bytes:
    if type(raw) is not bytes or len(raw) > MAX_COMPRESSED:
        raise FeedDenied("COMPRESSED_RESPONSE_TOO_LARGE")
    if encoding == "identity":
        if len(raw) > MAX_JSON:
            raise FeedDenied("RESPONSE_TOO_LARGE")
        return raw
    if encoding != "gzip":
        raise FeedDenied("UNKNOWN_ENCODING")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = decoder.decompress(raw, MAX_JSON + 1)
    except zlib.error:
        raise FeedDenied("INVALID_GZIP") from None
    if len(data) > MAX_JSON or decoder.unconsumed_tail or not decoder.eof:
        raise FeedDenied("DECOMPRESSED_RESPONSE_TOO_LARGE_OR_TRUNCATED")
    return data


def parse_station(feature: object) -> dict | None:
    if type(feature) is not dict:
        return None
    geom, props = feature.get("geometry"), feature.get("properties")
    if type(props) is not dict or type(geom) is not dict or geom.get("type") != "Point":
        return None
    point = geom.get("coordinates")
    if type(point) is not list or len(point) < 2:
        return None
    lon, lat = point[:2]
    if (type(lat) not in (int,float) or type(lon) not in (int,float)
            or not 59 <= lat <= 71 or not 19 <= lon <= 33):
        return None
    station_id = props.get("id") or feature.get("id")
    if type(station_id) is not str or not STATION_ID.fullmatch(station_id):
        return None
    name = props.get("name")
    if type(name) is not str or not 2 <= len(name) <= 110 or "<" in name or ">" in name:
        name = f"Road weather camera {station_id}"
    presets = props.get("presets", [])
    if type(presets) is not list:
        presets = []
    public_preset = None
    for item in presets:
        if type(item) is not dict or item.get("inCollection") is not True:
            continue
        identifier = item.get("id")
        if type(identifier) is str and PRESET_ID.fullmatch(identifier):
            public_preset = identifier
            break
    state, collection = props.get("state"), props.get("collectionStatus")
    return {
        "station_id":station_id,"label":name,
        "lat":round(float(lat),5),"lon":round(float(lon),5),
        "state":state[:60] if type(state) is str else "UNKNOWN",
        "collection_status":collection[:60] if type(collection) is str else "UNKNOWN",
        "published_image_url":f"https://weathercam.digitraffic.fi/{public_preset}.jpg" if public_preset else None,
        "image_is_live_verified":False,"record_kind":"official_public_weathercam_metadata"
    }


def normalize(payload: object, *, fetched_at: str, source_sha256: str, limit: int=20) -> dict:
    if type(payload) is not dict or type(limit) is not int or not 1 <= limit <= 50:
        raise FeedDenied("INVALID_PAYLOAD_OR_LIMIT")
    features = payload.get("features")
    if payload.get("type") != "FeatureCollection" or type(features) is not list:
        raise FeedDenied("UNRECOGNIZED_GEOJSON_FORMAT")
    if len(features) > 100_000:
        raise FeedDenied("EXCESS_STATION_COUNT")
    seen, samples = set(), []
    for entry in features:
        parsed = parse_station(entry)
        if parsed is None or parsed["station_id"] in seen:
            continue
        seen.add(parsed["station_id"])
        samples.append(parsed)
    if not samples:
        raise FeedDenied("NO_VALID_OFFICIAL_WEATHERCAM_STATIONS")
    samples.sort(key=lambda s:s["station_id"])
    try:
        if datetime.fromisoformat(fetched_at.replace("Z","+00:00")).tzinfo is None:
            raise ValueError("timezone required")
    except ValueError:
        raise FeedDenied("INVALID_FETCH_TIME") from None
    return {
        "schema_version":1,"dataset":"digitraffic_weathercam_official_metadata_sample",
        "publisher":"Fintraffic / Digitraffic","api":API,
        "source_documentation":DOCUMENTATION,"license":"CC BY 4.0",
        "attribution":ATTRIBUTION,"fetched_at":fetched_at,
        "source_sha256":source_sha256,"total_valid_stations_in_response":len(samples),
        "sample_size":min(len(samples),limit),"sample_is_not_complete_catalog":True,
        "realtime_video":False,"individual_image_freshness_verified":False,
        "facial_recognition":False,"owner_biometrics_collected":False,
        "station_samples":samples[:limit]
    }


def fetch_once(*, live: bool=False, timeout: int=12, limit: int=20, transport=None) -> dict:
    if live is not True:
        raise FeedDenied("EXPLICIT_PUBLIC_METADATA_OPT_IN_REQUIRED")
    if type(timeout) is not int or not 1 <= timeout <= 20:
        raise FeedDenied("INVALID_TIMEOUT")
    factory = transport if transport is not None else http.client.HTTPSConnection
    conn = factory(HOST,443,timeout=timeout,context=ssl.create_default_context())
    try:
        conn.request("GET",PATH,headers={
            "Accept":"application/geo+json, application/json",
            "Accept-Encoding":"gzip","Digitraffic-User":"IMPERIALCore/ImperialEye-v0.2",
            "User-Agent":"IMPERIAL-EYE/0.2 (+attribution; no PII)"
        })
        response = conn.getresponse()
        if response.status != 200:
            raise FeedDenied(f"OFFICIAL_API_HTTP_{response.status}")
        raw = response.read(MAX_COMPRESSED+1)
        data = decompress_limited(raw,(response.getheader("Content-Encoding") or "identity").lower())
        try:
            payload = json.loads(data)
        except (ValueError,UnicodeDecodeError):
            raise FeedDenied("INVALID_OFFICIAL_JSON") from None
        observed = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
        return normalize(payload,fetched_at=observed,
                         source_sha256=hashlib.sha256(data).hexdigest(),limit=limit)
    except (OSError,ssl.SSLError,http.client.HTTPException) as exc:
        raise FeedDenied("OFFICIAL_API_UNAVAILABLE") from exc
    finally:
        conn.close()


def main():
    import argparse
    parser=argparse.ArgumentParser(description="Read one fixed official Digitraffic weather-camera metadata response")
    parser.add_argument("--live",action="store_true")
    parser.add_argument("--limit",type=int,default=12)
    args=parser.parse_args()
    if not args.live:
        parser.error("Explicit --live is required")
    print(json.dumps(fetch_once(live=True,limit=args.limit),sort_keys=True,indent=2))


if __name__=="__main__":
    main()
