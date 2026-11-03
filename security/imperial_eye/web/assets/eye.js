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
  load();
})();