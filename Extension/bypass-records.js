(function (root) {
  function normalizeHostname(value) {
    return String(value || "")
      .trim()
      .toLowerCase()
      .replace(/^www\./, "");
  }

  function normalizeRiskScore(value) {
    if (value === null || value === undefined || value === "") return null;

    const score = Number(value);
    if (!Number.isFinite(score)) return null;
    return Math.max(0, Math.min(score, 100));
  }

  function getBypassHostname(entry) {
    if (typeof entry === "string") return normalizeHostname(entry);
    return normalizeHostname(entry?.hostname);
  }

  function normalizeBypassRecord(entry) {
    const hostname = getBypassHostname(entry);
    if (!hostname) return null;

    if (typeof entry === "string") {
      return {
        hostname,
        riskScore: null,
        bypassedAt: null,
      };
    }

    const bypassedAt = Number(entry?.bypassedAt);
    return {
      hostname,
      riskScore: normalizeRiskScore(entry?.riskScore),
      bypassedAt: Number.isFinite(bypassedAt) ? bypassedAt : null,
    };
  }

  function findBypassRecord(entries, hostname) {
    const target = normalizeHostname(hostname);
    if (!target || !Array.isArray(entries)) return null;

    for (const entry of entries) {
      const record = normalizeBypassRecord(entry);
      if (record?.hostname === target) return record;
    }

    return null;
  }

  function upsertBypassRecord(entries, record) {
    const normalized = normalizeBypassRecord(record);
    const current = Array.isArray(entries) ? entries : [];
    if (!normalized) return [...current];

    return [
      ...current.filter(
        (entry) => getBypassHostname(entry) !== normalized.hostname
      ),
      normalized,
    ];
  }

  function removeHostnameEntries(entries, hostname) {
    const target = normalizeHostname(hostname);
    const current = Array.isArray(entries) ? entries : [];
    if (!target) return [...current];

    return current.filter(
      (entry) => getBypassHostname(entry) !== target
    );
  }

  const api = {
    findBypassRecord,
    getBypassHostname,
    removeHostnameEntries,
    upsertBypassRecord,
  };

  root.PhishShieldBypassRecords = api;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
