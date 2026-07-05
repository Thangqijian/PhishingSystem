(function (root) {
  function isUsableUrl(value) {
    if (!value || typeof value !== "string") return false;

    try {
      const parsed = new URL(value);
      return parsed.protocol === "http:" || parsed.protocol === "https:";
    } catch (error) {
      return false;
    }
  }

  function chooseScanUrl({ documentUrl = "", navigationUrl = "" } = {}) {
    if (isUsableUrl(navigationUrl)) return navigationUrl;
    return documentUrl;
  }

  function shouldBlockPageForStatus(status) {
    return status !== "safe";
  }

  function clampRiskScore(score) {
    return Math.max(0, Math.min(Number(score) || 0, 100));
  }

  function getRiskAnimationState(score) {
    return {
      startScore: 0,
      endScore: clampRiskScore(score),
    };
  }

  function shouldRunProtection(protectionEnabled) {
    return protectionEnabled !== false;
  }

  function isInterceptedDownload({ pendingUrl = "" } = {}) {
    return isUsableUrl(pendingUrl);
  }

  function shouldEnforceChildLock(
    childLockEnabled,
    status,
    isInterceptedDownload = false
  ) {
    return childLockEnabled === true &&
      !isInterceptedDownload &&
      (status === "suspicious" || status === "phishing");
  }

  function getChildLockCountdownMessage(seconds) {
    const remaining = Math.max(0, Math.floor(Number(seconds) || 0));
    const unit = remaining === 1 ? "second" : "seconds";
    return `Child Lock is active. Returning to safety in ${remaining} ${unit}.`;
  }

  const helpers = {
    chooseScanUrl,
    getChildLockCountdownMessage,
    isInterceptedDownload,
    shouldBlockPageForStatus,
    shouldEnforceChildLock,
    getRiskAnimationState,
    clampRiskScore,
    shouldRunProtection,
  };

  root.PhishShieldHelpers = helpers;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = helpers;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
