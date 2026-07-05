(function (root) {
  function normalizeDownloadUrl(value) {
    if (!value || typeof value !== "string") return "";

    try {
      const url = new URL(value);
      url.hash = "";
      return url.href;
    } catch (error) {
      return "";
    }
  }

  function createDownloadAllowanceStore({
    ttlMs = 30000,
    now = () => Date.now(),
  } = {}) {
    const allowances = new Map();

    function removeExpired() {
      const currentTime = now();
      allowances.forEach((expiresAt, url) => {
        if (expiresAt <= currentTime) {
          allowances.delete(url);
        }
      });
    }

    function allow(url) {
      const normalized = normalizeDownloadUrl(url);
      if (!normalized) return false;

      removeExpired();
      allowances.set(normalized, now() + ttlMs);
      return true;
    }

    function consume(urlCandidates) {
      removeExpired();

      for (const candidate of urlCandidates || []) {
        const normalized = normalizeDownloadUrl(candidate);
        if (!normalized || !allowances.has(normalized)) continue;

        allowances.delete(normalized);
        return true;
      }

      return false;
    }

    return { allow, consume };
  }

  function shouldRememberBlockedHost(result) {
    if (result?.status !== "phishing") return false;
    if (result.urlhausHit) return true;
    return result.download?.is_malicious !== true;
  }

  const downloadAllowances = {
    createDownloadAllowanceStore,
    normalizeDownloadUrl,
    shouldRememberBlockedHost,
  };

  root.PhishShieldDownloadAllowances = downloadAllowances;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = downloadAllowances;
  }
})(typeof globalThis !== "undefined" ? globalThis : self);
