"""IMPERIAL EYE: curated official public-source catalog, no camera discovery.

Input is an explicit owner-reviewed dataset; never probes IP cameras,
searches face identities, handles biometric templates, or retrieves private
footage. This catalog returns links to *publisher portals*, not live feeds.
"""
from __future__ import annotations

from datetime import date
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

FIELDS = frozenset({
    "id", "publisher", "publisher_host", "portal_url", "label", "region",
    "region_center_lat", "region_center_lon", "category",
    "permission_basis", "source_documentation_url", "last_reviewed",
    "status", "record_kind"
})
IDENTIFIER = re.compile(r"[a-z][a-z0-9-]{2,60}\Z")
HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
CATEGORIES = frozenset({"traffic", "weather", "public_environment"})
ALLOWED_BASIS = frozenset({"official_public_portal_link"})
SOURCE_STATUS = frozenset({"PUBLISHER_PORTAL_VERIFIED", "STALE_NEEDS_REVIEW"})


class CatalogDenied(ValueError):
    pass


def _official_url(value, domain):
    if type(value) is not str or len(value)>800:
        raise CatalogDenied("INVALID_URL")
    try:
        p=urlsplit(value)
        port=p.port
    except ValueError:
        raise CatalogDenied("INVALID_URL") from None
    if (p.scheme!="https" or not p.hostname or p.username or p.password
            or p.fragment or port not in (None,443)):
        raise CatalogDenied("HTTPS_PUBLISHER_PORTAL_ONLY")
    if not HOST.fullmatch(p.hostname):
        raise CatalogDenied("PUBLIC_DNS_PUBLISHER_REQUIRED")
    try:
        ipaddress.ip_address(p.hostname)
        raise CatalogDenied("IP_CAMERA_TARGET_FORBIDDEN")
    except ValueError:
        pass
    if p.hostname != domain and not p.hostname.endswith("."+domain):
        raise CatalogDenied("PUBLISHER_HOST_MISMATCH")
    return value


def validate_record(item):
    if type(item) is not dict or set(item)!=FIELDS:
        raise CatalogDenied("INVALID_RECORD_SCHEMA")
    if type(item["id"]) is not str or not IDENTIFIER.fullmatch(item["id"]):
        raise CatalogDenied("INVALID_SOURCE_ID")
    if item["record_kind"]!="official_publisher_portal":
        raise CatalogDenied("NO_DIRECT_CAMERA_OR_STREAM_COLLECTION")
    if item["permission_basis"] not in ALLOWED_BASIS or item["category"] not in CATEGORIES:
        raise CatalogDenied("SOURCE_PERMISSION_OR_CATEGORY_DENIED")
    if item["status"] not in SOURCE_STATUS:
        raise CatalogDenied("SOURCE_STATUS_UNSUPPORTED")
    host=item["publisher_host"]
    if type(host) is not str or not HOST.fullmatch(host) or host.lower()!=host:
        raise CatalogDenied("INVALID_PUBLISHER_HOST")
    _official_url(item["portal_url"],host)
    _official_url(item["source_documentation_url"],host)
    for field in ("publisher","label","region"):
        value=item[field]
        if type(value) is not str or not 2<=len(value)<=120 or "<" in value:
            raise CatalogDenied("INVALID_SOURCE_TEXT")
    lat,lon=item["region_center_lat"],item["region_center_lon"]
    if (type(lat) not in (int,float) or type(lon) not in (int,float)
            or not -90<=lat<=90 or not -180<=lon<=180):
        raise CatalogDenied("INVALID_REGION_COORDINATES")
    if type(item["last_reviewed"]) is not str:
        raise CatalogDenied("INVALID_REVIEW_DATE")
    try:
        reviewed=date.fromisoformat(item["last_reviewed"])
    except ValueError:
        raise CatalogDenied("INVALID_REVIEW_DATE") from None
    if reviewed > date.today():
        raise CatalogDenied("FUTURE_REVIEW_DATE")
    return dict(item)


def load_catalog(path):
    path=Path(path)
    if path.is_symlink():
        raise CatalogDenied("SYMLINK_CATALOG_FORBIDDEN")
    if path.stat().st_size>128000:
        raise CatalogDenied("CATALOG_TOO_LARGE")
    document=json.loads(path.read_text(encoding="utf-8"))
    if (type(document) is not dict or
            set(document)!={"schema_version","sources","capabilities"} or
            document["schema_version"]!=1 or
            type(document["sources"]) is not list or
            type(document["capabilities"]) is not dict):
        raise CatalogDenied("INVALID_CATALOG_SCHEMA")
    if document["capabilities"]!={"identity_tracking":False,
                                  "face_search":False,
                                  "private_camera_access":False,
                                  "public_portal_links_only":True}:
        raise CatalogDenied("PROHIBITED_SURVEILLANCE_CAPABILITIES")
    result=[validate_record(item) for item in document["sources"]]
    if len({s["id"] for s in result})!=len(result):
        raise CatalogDenied("DUPLICATE_SOURCE_ID")
    return result
