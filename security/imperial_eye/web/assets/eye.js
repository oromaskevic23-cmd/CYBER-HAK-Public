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
    return btoa(binary).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"");
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
  load();
})();