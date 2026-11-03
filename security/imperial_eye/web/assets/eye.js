"use strict";
/* IMPERIAL EYE — public source navigator. No live video, face or person indexing. */
(() => {
  const SVG_NS = "http://www.w3.org/2000/svg";
  const $ = id => document.getElementById(id);
  const catalog = [];
  const approvedHosts = new Set(["511ny.org", "fintraffic.fi"]);

  function publisherLink(value) {
    if (typeof value !== "string") return null;
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" || url.username || url.password || url.port && url.port !== "443") return null;
      const allowed = [...approvedHosts].some(host => url.hostname === host || url.hostname.endsWith("." + host));
      return allowed ? url.href : null;
    } catch (_error) { return null; }
  }

  function element(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined) item.textContent = text;
    return item;
  }

  function render(items) {
    const box = $("source-list");
    const pins = $("markers");
    box.replaceChildren();
    pins.replaceChildren();
    if (!items.length) {
      box.append(element("p", "muted", "No reviewed public publishers match your filter."));
      return;
    }
    for (const entry of items) {
      if (!entry || entry.record_kind !== "official_publisher_portal" ||
          entry.permission_basis !== "official_public_portal_link") continue;
      const link = publisherLink(entry.portal_url);
      if (!link) continue;
      const card = element("article", "source-card");
      card.append(element("span", "tag", "PUBLISHER PORTAL · NOT LIVE STREAM"));
      card.append(element("h3", "", entry.publisher));
      card.append(element("p", "", entry.label + " — " + entry.region));
      const a = element("a", "", "Open official publisher");
      a.href = link;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      card.append(a);
      card.append(element("div", "meta", "Reviewed: " + entry.last_reviewed + " · Source links only"));
      box.append(card);

      if (Number.isFinite(entry.region_center_lat) && Number.isFinite(entry.region_center_lon)) {
        const x = (entry.region_center_lon + 180) / 360 * 1000;
        const y = (90 - entry.region_center_lat) / 180 * 500;
        const halo = document.createElementNS(SVG_NS, "circle");
        halo.setAttribute("cx", String(x)); halo.setAttribute("cy", String(y));
        halo.setAttribute("r", "14"); halo.setAttribute("class", "pin-halo");
        pins.append(halo);
        const dot = document.createElementNS(SVG_NS, "circle");
        dot.setAttribute("cx", String(x)); dot.setAttribute("cy", String(y));
        dot.setAttribute("r", "6"); dot.setAttribute("class", "pin");
        pins.append(dot);
        const title = document.createElementNS(SVG_NS, "title");
        title.textContent = entry.region + ": regional center, not camera coordinates";
        dot.append(title);
      }
    }
  }

  async function load() {
    try {
      const response = await fetch("../data/sources.json", {credentials:"omit", cache:"no-store"});
      if (!response.ok) throw new Error("Official catalog unavailable");
      const data = await response.json();
      const flags = data && data.capabilities;
      if (data.schema_version !== 1 || !Array.isArray(data.sources) ||
          !flags || flags.identity_tracking !== false ||
          flags.face_search !== false || flags.private_camera_access !== false ||
          flags.public_portal_links_only !== true) {
        throw new Error("Catalog safety schema was rejected");
      }
      catalog.push(...data.sources.filter(entry =>
        entry && entry.record_kind === "official_publisher_portal" &&
        entry.permission_basis === "official_public_portal_link" &&
        publisherLink(entry.portal_url)));
      $("count").textContent = String(catalog.length);
      render(catalog);
    } catch (_error) {
      $("count").textContent = "0";
      $("source-list").replaceChildren(element("p","muted",
        "Catalog unavailable or failed validation. No unverified source is displayed."));
    }
  }

  $("source-filter").addEventListener("input", function() {
    const term = this.value.trim().toLowerCase().slice(0, 80);
    render(catalog.filter(entry =>
      [entry.publisher, entry.label, entry.region].some(v =>
        typeof v === "string" && v.toLowerCase().includes(term))));
  });

  $("owner-check").addEventListener("click", async () => {
    const status = $("passkey-status");
    if (!window.isSecureContext || typeof PublicKeyCredential === "undefined") {
      status.textContent = "Device passkeys unavailable in this context. No access granted.";
      return;
    }
    try {
      const available = typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function"
        ? await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() : false;
      status.textContent = available
        ? "Device authenticator available. Protected server challenge and Owner enrollment NOT configured. Access denied."
        : "No local platform authenticator confirmed. Access denied.";
    } catch (_error) {
      status.textContent = "Could not inspect device capability. Access denied.";
    }
  });
  function bytesFromBase64Url(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error("Invalid authentication challenge format");
    }
    const binary = atob(value.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(value.length/4)*4,"="));
    return Uint8Array.from(binary, c => c.charCodeAt(0));
  }
  function base64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  }

  $("owner-auth").addEventListener("click", async () => {
    const status = $("passkey-status");
    const button = $("owner-auth");
    if (!window.isSecureContext || !navigator.credentials ||
        typeof navigator.credentials.get !== "function") {
      status.textContent = "Secure passkey authentication unavailable. Access denied.";
      return;
    }
    button.disabled = true;
    try {
      // This MUST be an authenticated, same-origin private server. GitHub
      // Pages is static: these routes are not deployed and fail closed.
      const challengeResponse = await fetch("/api/imperial-eye/owner/challenge", {
        method:"POST", credentials:"same-origin", redirect:"error",
        headers:{"Accept":"application/json"}
      });
      if (!challengeResponse.ok) throw new Error("Protected challenge issuer unavailable");
      const challenge = await challengeResponse.json();
      if (!challenge || challenge.schema_version !== 1 ||
          challenge.rp_id !== location.hostname ||
          typeof challenge.challenge !== "string" ||
          !Array.isArray(challenge.allow_credentials) || !challenge.allow_credentials.length) {
        throw new Error("Server challenge rejected");
      }
      const credential = await navigator.credentials.get({
        publicKey:{
          challenge:bytesFromBase64Url(challenge.challenge),
          rpId:challenge.rp_id,
          allowCredentials:challenge.allow_credentials.map(x => ({
            type:"public-key",id:bytesFromBase64Url(x.id)
          })),
          timeout:60000,
          userVerification:"required"
        }
      });
      if (!credential || credential.type !== "public-key") {
        throw new Error("Authenticator verification unsuccessful");
      }
      const response = credential.response;
      const proof = {
        schema_version:1,
        challenge_id:challenge.challenge_id,
        id:credential.id,
        raw_id:base64Url(credential.rawId),
        type:credential.type,
        response:{
          authenticator_data:base64Url(response.authenticatorData),
          client_data_json:base64Url(response.clientDataJSON),
          signature:base64Url(response.signature),
          user_handle:response.userHandle ? base64Url(response.userHandle) : null
        }
      };
      const verifyResponse = await fetch("/api/imperial-eye/owner/assertion", {
        method:"POST",credentials:"same-origin",redirect:"error",
        headers:{"Content-Type":"application/json","Accept":"application/json"},
        body:JSON.stringify(proof)
      });
      if (!verifyResponse.ok) throw new Error("Server assertion verification refused");
      const decision = await verifyResponse.json();
      // UI state is informative only. Actual privileged commands require
      // their own server-side Guardian + Approval Gateway checks.
      status.textContent = decision && decision.schema_version === 1 &&
        decision.user_verified === true && decision.owner_authority_session === true
        ? "Device verified by private server. Every privileged action still requires Owner Authority Guard and Approval Gateway."
        : "Server did not grant Owner verification. Access denied.";
    } catch (_error) {
      status.textContent = "No verified Owner session: protected backend absent, expired, or declined. Access denied.";
    } finally {
      button.disabled = false;
    }
  });
  /* Camera metadata is a stored, dated sample of an official API response.
     It contains no private camera credentials, frames, face scans or AI results. */
  const cameraHost = "weathercam.digitraffic.fi";
  function verifiedPublisherStill(value) {
    if (value === null) return null;
    if (typeof value !== "string") return null;
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" || url.hostname !== cameraHost ||
          url.username || url.password || url.search || url.hash || url.port ||
          !/^\/C[0-9]{5,12}\.jpg$/.test(url.pathname)) return null;
      return url.href;
    } catch (_error) {
      return null;
    }
  }

  async function loadWeathercams() {
    const list = $("camera-list");
    try {
      const response = await fetch("../data/digitraffic_sample.json", {
        credentials:"omit", cache:"no-store", redirect:"error"
      });
      if (!response.ok) throw new Error("official source sample unavailable");
      const data = await response.json();
      if (!data || data.schema_version !== 1 ||
          data.dataset !== "digitraffic_weathercam_official_metadata_sample" ||
          data.publisher !== "Fintraffic / Digitraffic" ||
          data.api !== "https://tie.digitraffic.fi/api/weathercam/v1/stations" ||
          data.license !== "CC BY 4.0" ||
          data.attribution !== "Source: Fintraffic / Digitraffic (CC BY 4.0)" ||
          data.realtime_video !== false ||
          data.individual_image_freshness_verified !== false ||
          data.facial_recognition !== false ||
          data.owner_biometrics_collected !== false ||
          data.sample_is_not_complete_catalog !== true ||
          !/^[0-9a-f]{64}$/.test(data.source_sha256 || "") ||
          !Array.isArray(data.station_samples) ||
          data.station_samples.length !== data.sample_size ||
          data.station_samples.length > 50 ||
          !Number.isSafeInteger(data.total_valid_stations_in_response) ||
          data.total_valid_stations_in_response < data.sample_size) {
        throw new Error("source evidence policy failure");
      }
      const when = Date.parse(data.fetched_at);
      const elapsed = Date.now() - when;
      if (!Number.isFinite(when) || elapsed < -60*60*1000) {
        throw new Error("untrusted source observation time");
      }
      const fresh = elapsed >= 0 && elapsed <= 24 * 60 * 60 * 1000;
      const encountered = new Set();
      const valid = [];
      for (const station of data.station_samples) {
        if (!station || station.record_kind !== "official_public_weathercam_metadata" ||
            station.image_is_live_verified !== false ||
            typeof station.station_id !== "string" ||
            !/^C[0-9]{5,12}$/.test(station.station_id) ||
            encountered.has(station.station_id) ||
            typeof station.label !== "string" || station.label.length > 110 ||
            !Number.isFinite(station.lat) || !Number.isFinite(station.lon) ||
            station.lat < 59 || station.lat > 71 ||
            station.lon < 19 || station.lon > 33) {
          throw new Error("untrusted source station");
        }
        if (station.published_image_url !== null && !verifiedPublisherStill(station.published_image_url)) {
          throw new Error("untrusted image host or station URL");
        }
        encountered.add(station.station_id);
        valid.push(station);
      }
      $("camera-count").textContent = String(valid.length);
      $("station-total").textContent =
        "SAMPLE " + valid.length + " / " + data.total_valid_stations_in_response + " VALID STATIONS IN API";
      $("camera-freshness").textContent = "Source snapshot: " +
        new Date(when).toISOString().replace(".000Z","Z") +
        (fresh ? " · OBSERVATION WITHIN 24H" : " · STALE — RECHECK REQUIRED");
      list.replaceChildren();
      const markers = $("weathercam-markers");
      markers.replaceChildren();
      for (const station of valid) {
        const card = element("article","camera-card");
        card.append(element("span","cam-label",station.station_id));
        card.append(element("h3","",station.label));
        card.append(element("div","cam-location",
          station.lat.toFixed(4) + "° N · " + station.lon.toFixed(4) + "° E · Finland"));
        card.append(element("div","cam-status",
          "Provider metadata: " + String(station.collection_status || "UNKNOWN").slice(0,40)));
        const still = verifiedPublisherStill(station.published_image_url);
        if (still && fresh) {
          const link = element("a","", "Open publisher's still image");
          link.href = still;
          link.target = "_blank";
          link.rel = "noopener noreferrer";
          card.append(link);
        } else {
          card.append(element("div","cam-note",
            fresh ? "No public image preset in this record." : "Snapshot expired. Image link withheld until revalidation."));
        }
        card.append(element("div","cam-note","Image availability and timestamp NOT independently verified."));
        list.append(card);
        const x = (station.lon + 180) / 360 * 1000;
        const y = (90 - station.lat) / 180 * 500;
        const marker = document.createElementNS(SVG_NS,"circle");
        marker.setAttribute("cx",String(x)); marker.setAttribute("cy",String(y));
        marker.setAttribute("r","3.5"); marker.setAttribute("class","weathercam-station");
        const label = document.createElementNS(SVG_NS,"title");
        label.textContent = station.station_id + " — official source location (metadata only)";
        marker.append(label);
        markers.append(marker);
      }
    } catch (_error) {
      $("camera-count").textContent = "0";
      $("station-total").textContent = "UNVERIFIED / BLOCKED";
      $("camera-freshness").textContent = "No usable, source-validated weathercam snapshot";
      list.replaceChildren(element("p","muted",
        "Camera records are unavailable or failed validation. No untrusted camera URLs are shown."));
      $("weathercam-markers").replaceChildren();
    }
  }

  load();
  loadWeathercams();
})();