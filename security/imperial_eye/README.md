# IMPERIAL EYE — Global Public Observation & Owner Identity Gate (v0.1)

**Program:** IMPERIAL Core × CYBER HAK × Nano Core Agents  
**Author / Final Architectural Decision Authority:** Alexander Nikolaevich Romaskevich (RomaskevicH), Founder • Owner • CEO.  
**Date:** 2026-11-03 · **Budget:** FREE_ONLY.  
**Current maturity:** functioning offline-servable source atlas and policy/unit CI, NOT a global live video surveillance platform, running face-recognition server or deployed authenticated Owner login.

## Motivation and original design

Several public projects branded "God's Eye" visualize published public data and agency traffic cameras on a world map. Their GitHub descriptions make quantitative claims; we have **not** independently verified the claimed global camera counts, licensing of individual feeds or their availability. In addition, the Telegram service "Glaz Boga" is a different personal-information lookup product. Do not confuse the two.

Reference studies, no code or artwork copied:
- [Phaviwylera/godseye](https://github.com/Phaviwylera/godseye): global map of agency-published camera feeds (self-described).
- [javigarciacom/gods-eye-view](https://github.com/javigarciacom/gods-eye-view): world map and public situational-intelligence layers (self-described).

**No service establishes lawful, comprehensive access to every camera on Earth.** IMPERIAL EYE's scope is deliberate: a catalog of agency-authorized public publishers and, in a separate future PRIVATE module, cameras explicitly enrolled by their operators and permitted by contract.

## Implemented components

`catalog.py`: strict source schema with a manually reviewed official publisher/host, HTTPS-only publisher link, source documentation, jurisdiction/region, timestamp, publisher attribution and explicit status. Rejects direct IP/RTSP cameras, private feeds, credential fields, privacy-surveillance capabilities, malformed URLs and unauthorized host redirection. It deliberately does not probe websites, scrape devices, replay images, or collect identifiers about people.

`data/sources.json`: **2** official agency publisher portal links at time of review:
- **511NY**, official New York State transportation/traffic camera map: https://511ny.org/map · official FAQ: https://511ny.org/faq. Link access is not permission to rehost every feed.
- **Fintraffic**, official road conditions and camera information: https://www.fintraffic.fi/en/digitalservices/traffic-situation. Fintraffic/Digitraffic published datasets are generally CC BY 4.0 with attribution conditions: https://www.fintraffic.fi/en/fintraffic/terms-use. This catalog publishes a LINK, not copies of images or the licensed data. Any future data ingester must retain dataset-specific credit, source links, terms and refresh limits.

`web/index.html` + `web/assets/eye.css` + `web/assets/eye.js`: original mobile-responsive source atlas. Clicking an approved source opens its official publisher portal. Pins represent **approximate region centers, not camera coordinates**. The land silhouettes are decorative, not authoritative cartography. No automatic external video play, archived footage, network scanning or camera stream interception. Catalog is fetched from the same origin and validated client-side as a second defensive check.

**Local run (no dependencies):**

```bash
python3 -m http.server 8000 --directory security/imperial_eye
# Open http://127.0.0.1:8000/web/
```

The local UI uses static curated JSON and works only over an HTTP static server or another proper static host. GitHub Pages publication is **not** implied by committing HTML.

`tests/test_catalog.py` + `tests/test_web_ui.py` and [CI workflow](../../.github/workflows/imperial-eye.yml) validate security boundaries, reject private cameras, and syntax-check the WebAuthn client.

## Verified executable evidence — 3 November 2026

- [Source catalog and no-biometric policy gate](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41595285470): **18/18 PASS per Python version (3.11 and 3.12)**.
- [Real Chromium UI smoke](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41595313923): **PASS**; two public source cards, functional filter, no video/image feeds opened, no requests to external domains during the test, and Owner login refused without a trusted server.
- [Evidence JSON with source commit, test statuses and screenshot SHA-256](evidence/2026-11-03-local-browser-pass.json).
- Real Chromium engine reported: **156.0.8078.4**; screenshot SHA-256: `1b8831ab0c3b0aa9e32887eb1fb5df89095c32790a65c273aa29d84f4e51917d`.
- The browser workflow was switched to manual dispatch after the verified run to preserve FREE_ONLY constraints. The lightweight policy workflow remains available on changes.

**No real camera feeds, biometric templates or production Owner sessions were tested or implemented.** Official portal entries are not individual camera locations. These tests demonstrate the source navigator and a fail-closed auth UI, not production surveillance or WebAuthn assertion verification.

## Sprint 019 — verified official camera stations and protected passkey verifier (3 November 2026)

**Official public station API: real result, not a simulated response.** [Fintraffic read CI](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41596732548) read the fixed HTTPS endpoint `https://tie.digitraffic.fi/api/weathercam/v1/stations` without authentication. It received and validated **816 public station metadata records** in that response, then saved an explicitly **limited sample of 12 stations** with camera station IDs, publisher coordinates, source links, condition collection metadata and `fetched_at=2026-11-03T07:30:20Z`. Each available image URL points to the official `weathercam.digitraffic.fi` host. No photos or video have been copied or automatically downloaded.

- [Open-source metadata adapter](digitraffic.py) — only one hardcoded TLS destination, gzip bounds, `Digitraffic-User` non-PII header, no redirects, no credentials; fails closed on schema/host errors.
- [12 authentic dated station records](data/digitraffic_sample.json) — Fintraffic / Digitraffic attribution under CC BY 4.0, exact source SHA-256, actual source observation time, and distinction between **metadata collection** and **image liveness**.
- [Full-screen atlas with station metadata cards](web/index.html) — map dots from published coordinates, labels, links to official still images shown only for snapshots less than 24 hours old, and publisher licensing.
- [Real Chromium screenshot/UI proof](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41597277505) — 12 station cards, 2 publisher portals, filter active, zero external requests or auto-streamed images, Owner login denied in absence of trusted server.
- [Structured evidence, hash and limits](evidence/2026-11-03-sprint019-official-api-webauthn.json).

**Important freshness limit:** a checked-in static snapshot does NOT update automatically. After 24 hours the UI displays STALE and withholds direct image links. A fresh official API read, independent validation and a new reviewed snapshot are required before those links reappear. The **816** count is the number of unique valid station metadata records observed in this particular source response; it is NOT 816 independently verified live feeds and not access to all cameras in the world.

**WebAuthn server verification core (LOCAL LAB):** [owner_webauthn.py](owner_webauthn.py) now uses the pinned open-source **py_webauthn 3.0.1** library to validate a **real** cryptographic ES256 device assertion against a separately provided trust record. Challenges are random, one-use, limited to 90 seconds and stored persistently in SQLite. Exact RP hostname/origin, required user verification (UV), credential ID and signature plus sign counters are checked; invalid signatures also burn challenges. The module returns `owner_authority_session:false` and `production_authorized:false` EVEN ON SUCCESS because an actual Owner identity has not enrolled its credential. No plaintext biometric sample or Face ID template is handled.

- [WebAuthn synthetic cryptographic tests](tests/test_owner_webauthn.py) (not a mocked-only verifier).
- [48/48 complete security tests](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41597973689) on Python 3.11 and 3.12. Includes tampered signatures, changed origin, wrong key, missing UV, stale challenge, counter replay, no enrollment and false public camera data.
- **Not deployed:** HTTP endpoints `/api/imperial-eye/owner/challenge` and `/api/imperial-eye/owner/assertion` remain unimplemented. This is the **verification engine** to be integrated behind a protected TLS origin. No live Face ID owner session is claimed.

**Technical scope:** work stays within CYBER HAK and does not bypass HANTER's Federated Multi-Orchestrator Architecture, NCA AI Passport, Guardian Core, Approval Gateway, Audit Ledger, Zero Trust or CRYPTO IMPERIAL Ecosystem Boundary.

## Face scanner / Owner login: use device WebAuthn, NOT central face recognition

**Owner Device Gate design:** user-initiated WebAuthn / passkey challenge with `userVerification: required` and relying-party (RP) origin binding. On an eligible Apple device, the platform can use Face ID; other authenticators may use Touch ID, fingerprint or device PIN. **The relying-party server cannot require Face ID specifically just by setting userVerification=required**, and must never claim a face scan occurred without device-specific proof. FIDO documents that biometric matching is local to the authenticator and the biometric template is not disclosed to the relying party.

The client provides two distinct actions: `Check device support` and `Authenticate with passkey`. Authentication attempts call same-origin protected routes:

`POST /api/imperial-eye/owner/challenge` → exact RP ID / origin / one-time random challenge / allowlisted credential IDs / maximum expiry from protected server.

`navigator.credentials.get({publicKey:{challenge, rpId, allowCredentials, userVerification:"required"}})` → signed authenticator assertion. The browser cannot grant any Owner authority.

`POST /api/imperial-eye/owner/assertion` → **production backend must verify** signed authenticator data, exact challenge, RP ID hash, browser origin, UV flag, allowlisted registered credential, counter/replay, credential revocation, and protected server session; combine with Owner Authority Guard, Guardian Core and Approval Gateway for sensitive actions.

**Current limit:** authentication backend and actual Owner credential enrollment are **NOT DEPLOYED**. Static GitHub code never captures camera images or biometric templates. If the backend routes are absent or reject a request, it fails closed. A client-visible `user_verified` flag alone must NEVER authorize a privileged server operation.

Reference: https://www.w3.org/TR/2026/CR-webauthn-3-20260113/ and https://fidoalliance.org/passkeys/.

## Architecture and data governance

`Architect → HANTER Command Center → federated public-data / security / cloud orchestrators → trained NCA → allowed source connectors`, with ORION research, VELION model router (MAX is a mode), LEGION examinations, CYBER HAK security, AI Passport, Enterprise Skills, Guardian Core, Approval Gateway, Audit Ledger, ProofGraph, Owner Kill Switch and Zero Trust.

**Public/Private Boundary:** public-source portal index never contains private camera IPs, tokens, home cameras, faces, identifiers or account data. Operator-owned private camera integrations, if later explicitly requested, require tenant-specific consent and independent authenticated private storage, access lists and lawful retention. No automatic publishing from private resources. Preserve the separate CRYPTO IMPERIAL Ecosystem Boundary.

### Long-term permissioned observation layers (not implemented)

- Official road and weather cameras under publisher rights/terms, with source citation, freshness, liveness and rate-limit evidence.
- Licensed weather, hazard, wildfire, maritime and aviation aggregate layers where permitted and safe; distinguish historical, delayed, modeled and live data.
- Signed source manifest, rights/license registry, provenance and review timestamp per record.
- A source-specific viewer for explicitly permitted cameras, not a scanning utility. Source payloads may be rendered under publisher constraints; forbid unauthorized archives.
- Independent QA and anomaly detection on **non-personal sensor events** only; do not run face indexing or follow named individuals across cameras.
- WebAuthn protected Owner identity; never export or store raw facial images, hashes, templates or biometric embeddings.

## Acceptance, safety and limitations

**Implemented and testable:** original static source navigator, finite list of validated publisher links, no-cookie client, owner device support probe, WebAuthn client *request contract*, Python source guard and offline security tests.

**Not implemented:** thousands of camera feeds, livestream playback, 3D globe, authorized camera account management, source-data API ingestion, server-side passkey verification, Face ID owner enrollment, full owner session, independent security assessment, remote worker control, Google/OSINT personal-info aggregation, global people detection or cloud deployment.

The architecture intentionally does not implement indiscriminate worldwide camera access, unauthorized surveillance, covert account lookup, geolocation of private persons, or facial identification from external cameras. Publishing an official traffic-map link is not a license to extract, store or redistribute surveillance footage.

### Production gates

1. Protected WebAuthn RP backend, owner-enrolled passkey credentials, phishing-resistant challenge binding and audited recovery, with verified Owner Authority Guard integration.
2. Evidence that the owner consented to each camera/account connector and the publisher grants the appropriate rights for each playback or ingestion use.
3. Verified public feed liveness, freshness, license, change tracking, rate limits, and data corrections.
4. Local security testing + independent threat assessment of WebAuthn, SSRF, cross-tenant data and public/private separation.
5. A released UI behind real hosting and TLS; public deployment alone grants no private or Owner credentials.
6. Limited one-agent read-only task, qualified LEGION output QA and verifiable Audit Ledger; only then expand to NCA squads.

**Build software. Verify everything.**
