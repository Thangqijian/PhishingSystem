(function (root) {
  const INTERACTION_WINDOW_MS = 8000;
  const MULTI_PART_PUBLIC_SUFFIXES = new Set([
    "co.uk", "org.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "com.my", "net.my", "org.my",
    "co.nz", "co.jp", "com.sg",
  ]);

  function parseWebUrl(value) {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return null;
      }
      return parsed;
    } catch (error) {
      return null;
    }
  }

  function normalizeHostname(value) {
    return String(value || "")
      .trim()
      .toLowerCase()
      .replace(/^www\./, "");
  }

  function getSiteKey(hostname) {
    const normalized = normalizeHostname(hostname);
    if (!normalized || normalized === "localhost" || /^\d+(\.\d+){3}$/.test(normalized)) {
      return normalized;
    }

    const labels = normalized.split(".");
    if (labels.length <= 2) return normalized;

    const suffix = labels.slice(-2).join(".");
    return MULTI_PART_PUBLIC_SUFFIXES.has(suffix)
      ? labels.slice(-3).join(".")
      : suffix;
  }

  function isSameSite(firstUrl, secondUrl) {
    const first = parseWebUrl(firstUrl);
    const second = parseWebUrl(secondUrl);
    if (!first || !second) return false;

    return getSiteKey(first.hostname) === getSiteKey(second.hostname);
  }

  function hasDeceptiveAdSignals(value) {
    const parsed = parseWebUrl(value);
    if (!parsed) return false;

    const decoded = decodeURIComponent(parsed.href).toLowerCase();
    const adTerms = [
      "propellerads",
      "proppop",
      "popunder",
      "pop-under",
      "popads",
      "adsterra",
      "clickadu",
      "onclicka",
    ];
    if (adTerms.some((term) => decoded.includes(term))) return true;

    const parameterNames = new Set(
      Array.from(parsed.searchParams.keys(), (name) => name.toLowerCase())
    );
    const campaignSignals = [
      "clickid",
      "click_id",
      "offer",
      "campaign",
      "utm_source",
      "utm_medium",
      "utm_campaign",
    ].filter((name) => parameterNames.has(name)).length;
    const medium = (parsed.searchParams.get("utm_medium") || "").toLowerCase();

    return campaignSignals >= 3 && /^(cpc|cpm|pop|paid)$/.test(medium);
  }

  function createInteraction({
    sourceUrl = "",
    intendedUrl = "",
    occurredAt = Date.now(),
  } = {}) {
    const source = parseWebUrl(sourceUrl);
    const intended = parseWebUrl(intendedUrl);
    const timestamp = Number(occurredAt);

    return {
      sourceUrl: source?.href || "",
      intendedUrl: intended?.href || "",
      occurredAt: Number.isFinite(timestamp) ? timestamp : Date.now(),
    };
  }

  function isUnexpectedCrossDomainTab({
    interaction,
    targetUrl = "",
    now = Date.now(),
    interactionWindowMs = INTERACTION_WINDOW_MS,
  } = {}) {
    const target = parseWebUrl(targetUrl);
    if (!interaction || !target) return false;

    const elapsed = Number(now) - Number(interaction.occurredAt);
    if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > interactionWindowMs) {
      return false;
    }

    if (isSameSite(interaction.sourceUrl, target.href)) return false;

    if (
      interaction.intendedUrl &&
      isSameSite(interaction.intendedUrl, target.href) &&
      !hasDeceptiveAdSignals(target.href)
    ) {
      return false;
    }

    return true;
  }

  function findUnexpectedInteraction({
    interactions = [],
    targetUrl = "",
    now = Date.now(),
    interactionWindowMs = INTERACTION_WINDOW_MS,
  } = {}) {
    if (!Array.isArray(interactions)) return null;

    for (let index = interactions.length - 1; index >= 0; index -= 1) {
      const interaction = interactions[index];
      if (
        isUnexpectedCrossDomainTab({
          interaction,
          targetUrl,
          now,
          interactionWindowMs,
        })
      ) {
        return interaction;
      }
    }

    return null;
  }

  const api = {
    INTERACTION_WINDOW_MS,
    createInteraction,
    findUnexpectedInteraction,
    hasDeceptiveAdSignals,
    isUnexpectedCrossDomainTab,
  };

  root.PhishShieldNavigationGuard = api;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
