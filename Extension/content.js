(function () {
  const helpers = globalThis.PhishShieldHelpers || {
    chooseScanUrl: ({ documentUrl = "", navigationUrl = "" } = {}) => navigationUrl || documentUrl,
    shouldBlockPageForStatus: (status) => status !== "safe",
    getRiskAnimationState: (score) => ({
      startScore: 0,
      endScore: Math.max(0, Math.min(Number(score) || 0, 100)),
    }),
    clampRiskScore: (score) => Math.max(0, Math.min(Number(score) || 0, 100)),
    shouldRunProtection: (protectionEnabled) => protectionEnabled !== false,
    isInterceptedDownload: ({ pendingUrl = "" } = {}) => {
      try {
        const parsed = new URL(pendingUrl);
        return parsed.protocol === "http:" || parsed.protocol === "https:";
      } catch (error) {
        return false;
      }
    },
    shouldEnforceChildLock: (
      childLockEnabled,
      status,
      isInterceptedDownload = false
    ) =>
      childLockEnabled === true &&
      !isInterceptedDownload &&
      (status === "suspicious" || status === "phishing"),
    getChildLockCountdownMessage: (seconds) => {
      const remaining = Math.max(0, Math.floor(Number(seconds) || 0));
      return `Child Lock is active. Returning to safety in ${remaining} ${remaining === 1 ? "second" : "seconds"}.`;
    },
  };
  let isProcessing = false;
  let lastUrl = "";
  let scanSequence = 0;
  const CHILD_LOCK_RETURN_SECONDS = 5;

  const DOWNLOAD_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
    ".scr", ".jar", ".dll", ".pif", ".com", ".hta",
    ".wsf", ".cpl", ".reg", ".iso", ".img", ".apk",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".dmg", ".pkg", ".deb", ".rpm",
  ];

  function shouldSkipScan(url) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase().replace("www.", "");
      const referenceSkipDomains = [
        "safebrowsing.google.com",
        "consumer.ftc.gov",
        "urlhaus.abuse.ch",
      ];

      return (
        !url ||
        url.includes("google.com/search/warmup.html") ||
        url.startsWith("chrome://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:") ||
        url.startsWith("chrome-extension://") ||
        referenceSkipDomains.some((domain) =>
          hostname === domain || hostname.endsWith("." + domain)
        )
      );
    } catch (e) {
      return true;
    }
  }

  function getHostname(url) {
    try {
      return new URL(url).hostname.toLowerCase().replace("www.", "");
    } catch (e) {
      return "unknown";
    }
  }

  function isLikelyDownloadLink(anchor, url) {
    if (anchor?.hasAttribute("download")) return true;

    try {
      const path = new URL(url).pathname.toLowerCase();
      return DOWNLOAD_EXTENSIONS.some((ext) => path.endsWith(ext));
    } catch (e) {
      return false;
    }
  }

  async function runCheck(rawUrl, options = {}) {
    const url = helpers.chooseScanUrl({
      documentUrl: window.location.href,
      navigationUrl: rawUrl,
    });

    if (shouldSkipScan(url)) {
      removeHidingStyle();
      return;
    }

    const settings = await chrome.storage.local.get(["protectionEnabled"]);
    if (!helpers.shouldRunProtection(settings.protectionEnabled)) {
      removeHidingStyle();
      if (options.pendingUrl) {
        window.location.href = options.pendingUrl;
      }
      return;
    }

    if (isProcessing && lastUrl === url && !options.forceScan) return;
    if (lastUrl && lastUrl !== url) {
      removeOverlay(document.getElementById("security-block-root")?.shadowRoot);
    }

    isProcessing = true;
    lastUrl = url;
    const scanId = ++scanSequence;

    InjectPageBlockStyle();

    let shadowRoot;

    try {
      shadowRoot = await createOverlay({
        hostname: getHostname(url),
        riskScore: 0,
        status: "loading",
      }, true);

      chrome.runtime.sendMessage(
        {
          action: "checkUrl",
          url,
          filename: options.filename || "",
          forceScan: options.forceScan || false,
          unexpectedRedirect: options.unexpectedRedirect === true,
          referrerUrl: options.referrerUrl || document.referrer || "",
        },
        (response) => {
          if (scanId !== scanSequence || lastUrl !== url) {
            return;
          }

          isProcessing = false;

          if (!response) {
            removeOverlay(shadowRoot);
            return;
          }

          const effectiveOptions = {
            ...options,
            unexpectedRedirect:
              options.unexpectedRedirect === true ||
              response.unexpectedRedirect === true,
            closeTabOnSafety: response.closeTabOnSafety === true,
          };

          if (options.pendingUrl && response.status === "safe") {
            removeOverlay(shadowRoot);
            window.location.href = options.pendingUrl;
            return;
          }

          if (
            response.status === "safe" &&
            response.showSafeNotification === false &&
            !effectiveOptions.unexpectedRedirect
          ) {
            if (hasDashboardOpen(shadowRoot)) {
              keepDashboardOpenOnly(shadowRoot);
              return;
            }
            removeOverlay(shadowRoot);
            return;
          }

          bindPopupEvents(shadowRoot, response, effectiveOptions);
        }
      );
    } catch (error) {
      console.error("PhishShield scan failed:", error);
      if (scanId === scanSequence) {
        isProcessing = false;
      }
      removeHidingStyle();
    }
  }

  runCheck(window.location.href);

  function removeHidingStyle() {
    document.getElementById("phishshield-page-block")?.remove();
  }

  function InjectPageBlockStyle() {
    if (document.getElementById("phishshield-page-block")) return;

    const blockStyle = document.createElement("style");
    blockStyle.id = "phishshield-page-block";
    blockStyle.textContent = `
      body {
        overflow:hidden !important;
      }

      body > :not(#security-block-root) {
        pointer-events:none !important;
        filter:blur(5px) !important;
        opacity:0.15 !important;
      }
    `;

    (document.head || document.documentElement).appendChild(blockStyle);
  }

  function removeOverlay(shadowRoot) {
    const root = shadowRoot?.host || document.getElementById("security-block-root");
    root?.remove();
    removeHidingStyle();
  }

  function hasDashboardOpen(shadowRoot) {
    return Boolean(shadowRoot?.getElementById("dashboard-wrapper"));
  }

  function keepDashboardOpenOnly(shadowRoot) {
    removeHidingStyle();
    const widget = shadowRoot.getElementById("ps-widget");
    const wrapper = shadowRoot.getElementById("dashboard-wrapper");

    widget?.classList.remove("show", "is-loading", "show-details");
    if (widget) {
      widget.style.display = "none";
    }
    if (wrapper) {
      wrapper.dataset.removeOverlayOnClose = "true";
    }
    shadowRoot.host.style.pointerEvents = "auto";
  }

  function setOverlayInteraction(shadowRoot, status) {
    const root = shadowRoot?.host;
    const widget = shadowRoot?.getElementById("ps-widget");
    if (!root) return;

    const shouldBlock = helpers.shouldBlockPageForStatus(status);
    root.style.pointerEvents = shouldBlock ? "auto" : "none";
    if (widget) {
      widget.style.pointerEvents = "auto";
    }
  }

  async function createOverlay(data, showLoading = false) {
    const existing = document.getElementById("security-block-root");
    if (existing?.shadowRoot) {
      return existing.shadowRoot;
    }

    const root = document.createElement("div");
    root.id = "security-block-root";
    root.style.position = "fixed";
    root.style.inset = "0";
    root.style.zIndex = "2147483647";
    root.style.pointerEvents = "auto";

    document.documentElement.appendChild(root);

    const shadowRoot = root.attachShadow({ mode: "open" });
    const response = await fetch(chrome.runtime.getURL("popup.html"));
    const htmlString = await response.text();
    const template = document.createElement("template");
    template.innerHTML = htmlString;

    shadowRoot.appendChild(template.content.cloneNode(true));

    const widget = shadowRoot.getElementById("ps-widget");
    const domainText = shadowRoot.getElementById("ps-domain-text");
    const loadingSettingsBtn = shadowRoot.getElementById("ps-btn-settings-loading");

    if (domainText) {
      domainText.textContent = data.hostname || "unknown";
    }

    bindSettingsButton(shadowRoot, loadingSettingsBtn, widget);

    if (showLoading && widget) {
      widget.classList.add("show", "is-loading");
    }

    return shadowRoot;
  }

  function setText(shadowRoot, id, value) {
    const element = shadowRoot.getElementById(id);
    if (element) element.textContent = value ?? "--";
  }

  function addFinding(container, title, message, color = "red") {
    const card = document.createElement("div");
    card.className = "ps-indicator-card";

    const dot = document.createElement("div");
    dot.className = `ps-indicator-dot ${color}`;

    const text = document.createElement("div");
    text.className = "ps-indicator-text";

    const heading = document.createElement("h4");
    heading.textContent = title;

    const copy = document.createElement("p");
    copy.textContent = message;

    text.append(heading, copy);
    card.append(dot, text);
    container.appendChild(card);
  }

  function getSummary(
    data,
    isInterceptedDownload = false,
    isUnexpectedRedirect = false
  ) {
    const riskScore = Number(data.riskScore || 0);

    if (data.previouslyAllowed) {
      return "You previously chose to allow this website. This is the saved risk score from that decision; the website was not rescanned.";
    }

    if (isUnexpectedRedirect) {
      return "This page tried to open an unrelated website in a new tab. PhishShield blocked that tab and checked its destination for malicious indicators.";
    }

    if (isInterceptedDownload || data.download?.is_malicious) {
      return "PhishShield blocked this download because the file type can run or modify software on your device. Continue only if you trust this website and expected this file.";
    }

    if (riskScore <= 30) {
      return "No significant phishing indicators were detected. The website appears legitimate based on the current machine learning and heuristic analysis.";
    }

    if (riskScore <= 70) {
      return "Several suspicious indicators were detected. Be careful before entering passwords, payment details, or personal information.";
    }

    return "Multiple high-confidence phishing indicators were detected. This website may be linked to credential theft, impersonation, redirection abuse, or malicious content.";
  }

  function getDownloadText(download, pendingUrl = "", isInterceptedDownload = false) {
    if (download?.is_malicious) return `High-risk file type (${download.extension || "unknown"})`;
    if (download?.is_suspicious) return `Suspicious archive (${download.extension || "unknown"})`;
    if (isInterceptedDownload) {
      try {
        const filename = new URL(pendingUrl).pathname.split("/").pop() || "";
        const extension = filename.toLowerCase().match(/\.[a-z0-9]+$/)?.[0];
        return extension
          ? `High-risk download request (${extension})`
          : "High-risk download request";
      } catch (error) {
        return "High-risk download request";
      }
    }
    return "None";
  }

  function getThreatSources(data) {
    let count = 0;
    if (Number(data.mlConfidence || 0) >= 70) count += 1;
    if (Number(data.heuristicRisk || 0) >= 40) count += 1;
    if (data.urlhausHit) count += 1;
    if (data.download?.is_malicious || data.download?.is_suspicious) count += 1;
    return `${count} triggered`;
  }

  function bindPopupEvents(shadowRoot, data, options = {}) {
    const widget = shadowRoot.getElementById("ps-widget");
    const btnDetails = shadowRoot.getElementById("ps-btn-details");
    const btnSafe = shadowRoot.getElementById("ps-btn-safe");
    const btnContinue = shadowRoot.getElementById("ps-btn-continue");
    const btnBack = shadowRoot.getElementById("back-btn");
    const btnSettings = shadowRoot.getElementById("ps-btn-settings");
    const container = shadowRoot.getElementById("detection-results");
    const findings = Array.isArray(data.flags) ? [...data.flags] : [];
    const isInterceptedDownload = helpers.isInterceptedDownload(options);
    const isUnexpectedRedirect = options.unexpectedRedirect === true;
    if (isUnexpectedRedirect) {
      findings.unshift(
        "This page opened an unrelated website without a matching link click"
      );
    }

    if (data.status !== "safe") {
      if (btnContinue) btnContinue.disabled = true;
      if (btnSettings) btnSettings.disabled = true;
    }

    widget?.classList.remove("is-loading", "hide");
    widget?.classList.remove("ps-state-safe", "ps-state-suspicious", "ps-state-phishing");
    widget?.classList.add(`ps-state-${data.status || "safe"}`);
    widget?.classList.add("show");
    setOverlayInteraction(shadowRoot, data.status || "safe");

    updateRiskUI(shadowRoot, Number(data.riskScore || 0), data.status);
    updateHeaderUI(shadowRoot, data, {
      isInterceptedDownload,
      isUnexpectedRedirect,
    });

    if (isInterceptedDownload || data.download?.is_malicious) {
      setText(shadowRoot, "risk-title", "High-Risk Download Detected");
    } else if (isUnexpectedRedirect) {
      setText(
        shadowRoot,
        "risk-title",
        data.status === "phishing"
          ? "Malicious Redirect Blocked"
          : "Unexpected Redirect Blocked"
      );
    } else if (data.previouslyAllowed) {
      setText(shadowRoot, "risk-title", "Previously Allowed");
    }

    if (container) {
      container.innerHTML = "";

      if (findings.length === 0) {
        addFinding(
          container,
          "No Major Findings",
          "No detailed heuristic indicators were returned for this scan.",
          "yellow"
        );
      } else {
        findings.forEach((flag) => {
          addFinding(container, "Security Finding", String(flag), "red");
        });
      }
    }

    setText(shadowRoot, "ps-domain-text", data.hostname || "unknown");
    const scoreLabel = shadowRoot.getElementById("risk-score-label");
    if (scoreLabel) {
      scoreLabel.textContent = data.previouslyAllowed
        ? "PREVIOUS RISK SCORE"
        : "MALICIOUS RISK";
    }
    if (data.previouslyAllowed && !data.previousRiskScoreAvailable) {
      setText(shadowRoot, "risk-score-text", "--");
    }

    setText(
      shadowRoot,
      "threat-summary-text",
      getSummary(data, isInterceptedDownload, isUnexpectedRedirect)
    );
    setText(shadowRoot, "ml-confidence", `${Math.round(Number(data.mlConfidence || 0))}%`);
    setText(shadowRoot, "heuristic-risk", `${Math.round(Number(data.heuristicRisk || 0))}%`);
    setText(shadowRoot, "risk-level", data.riskLevel || (data.status || "safe").toUpperCase());
    setText(shadowRoot, "redirect-count", data.redirectCount || 0);
    setText(shadowRoot, "threat-sources", getThreatSources(data));
    setText(shadowRoot, "resolved-url", data.resolvedUrl || window.location.href);
    setText(shadowRoot, "cross-domain-status", data.crossDomain ? "Yes" : "No");
    setText(shadowRoot, "urlhaus-status", data.urlhausHit ? "Detected" : "No hit");
    setText(
      shadowRoot,
      "download-status",
      getDownloadText(data.download || {}, options.pendingUrl, isInterceptedDownload)
    );
    setText(shadowRoot, "model-used", data.modelUsed || "Local model");
    setText(
      shadowRoot,
      "scan-footer",
      data.previouslyAllowed
        ? "Bypass status: PREVIOUSLY ALLOWED"
        : isUnexpectedRedirect
          ? "Redirect status: BLOCKED"
          : isInterceptedDownload || data.download?.is_malicious
        ? "Download status: BLOCKED"
        : `Scan result: ${(data.status || "safe").toUpperCase()}`
    );

    const message = shadowRoot.querySelector(".ps-message");
    if (message) {
      message.textContent = "";
      const introText = data.previouslyAllowed
        ? "You previously allowed "
        : isUnexpectedRedirect
          ? "PhishShield blocked an unexpected tab opening "
          : "PhishShield AI has analyzed ";
      const intro = document.createTextNode(introText);
      const domain = document.createElement("strong");
      domain.className = "ps-domain";
      domain.textContent = data.hostname || "this site";
      const outroText = data.previouslyAllowed
        ? ". This saved score is from the earlier warning; the site was not rescanned."
        : isUnexpectedRedirect
          ? " after a click on this page."
          : isInterceptedDownload || data.download?.is_malicious
        ? " and paused a high-risk download request for your review."
        : data.status === "safe"
          ? " and found no major signs of phishing."
          : " and found indicators that require caution.";
      const outro = document.createTextNode(outroText);
      message.append(intro, domain, outro);
    }

    if (isInterceptedDownload) {
      if (btnSafe) btnSafe.textContent = "Back to Safety";
      if (btnContinue) btnContinue.textContent = "Download Anyway";
    } else if (isUnexpectedRedirect) {
      if (btnSafe) btnSafe.textContent = "Stay on This Page";
      if (btnContinue) btnContinue.style.display = "none";
    }

    if (data.status === "safe") {
      removeHidingStyle();
      if (btnSafe) btnSafe.style.display = "none";
      if (btnContinue) btnContinue.style.display = "none";
      if (btnDetails) {
        btnDetails.textContent = data.previouslyAllowed
          ? "Why was this allowed?"
          : isUnexpectedRedirect
            ? "Why was this blocked?"
            : "Why is this safe?";
      }
      if (widget) widget.dataset.safePopup = "true";
      startSafeDismiss(shadowRoot, widget);
    }

    btnDetails?.addEventListener("click", () => {
      widget?.classList.add("show-details");
    });

    btnBack?.addEventListener("click", () => {
      widget?.classList.remove("show-details");
    });

    bindSettingsButton(shadowRoot, btnSettings, widget);

    btnSafe?.addEventListener("click", () => {
      returnToSafety(shadowRoot, options);
    });

    btnContinue?.addEventListener("click", async () => {
      if (isInterceptedDownload) {
        const approved = await approveInterceptedDownload(
          shadowRoot,
          options.pendingUrl
        );
        if (!approved) return;

        closeWithAnimation(shadowRoot, () => {
          removeHidingStyle();
          window.location.href = options.pendingUrl;
        });
        return;
      }

      const confirmContinue = confirm("Proceeding to this website is not recommended. Continue?");
      if (!confirmContinue) return;

      chrome.runtime.sendMessage({
        action: "rememberBypass",
        hostname: data.hostname,
        url: options.pendingUrl || window.location.href,
        riskScore: data.riskScore,
      });

      closeWithAnimation(shadowRoot, () => {
        removeHidingStyle();
        if (options.pendingUrl) {
          window.location.href = options.pendingUrl;
        }
      });
    });

    startChildLockReturnCountdown(shadowRoot, data, options, {
      btnContinue,
      btnSettings,
    });
  }

  async function startChildLockReturnCountdown(
    shadowRoot,
    data,
    options,
    { btnContinue, btnSettings }
  ) {
    if (data.status === "safe") return;

    const widget = shadowRoot.getElementById("ps-widget");
    const notice = shadowRoot.getElementById("ps-child-lock-notice");
    const countdown = shadowRoot.getElementById("ps-child-lock-countdown");

    try {
      const settings = await chrome.storage.local.get(["childLockEnabled"]);
      if (!widget?.isConnected) return;

      const isInterceptedDownload = helpers.isInterceptedDownload(options);
      if (!helpers.shouldEnforceChildLock(
        settings.childLockEnabled,
        data.status,
        isInterceptedDownload
      )) {
        if (btnContinue) btnContinue.disabled = false;
        if (btnSettings) btnSettings.disabled = false;
        return;
      }

      if (btnContinue) btnContinue.style.display = "none";
      if (btnSettings) btnSettings.style.display = "none";
      if (notice) notice.hidden = false;

      let remaining = CHILD_LOCK_RETURN_SECONDS;
      updateChildLockCountdown(notice, countdown, remaining);
      clearChildLockCountdown(widget);

      widget.__childLockInterval = setInterval(() => {
        if (!widget.isConnected) {
          clearChildLockCountdown(widget);
          return;
        }

        remaining -= 1;
        updateChildLockCountdown(notice, countdown, remaining);

        if (remaining <= 0) {
          clearChildLockCountdown(widget);
          returnToSafety(shadowRoot, options);
        }
      }, 1000);
    } catch (error) {
      console.error("Child Lock safety check failed:", error);
      if (btnContinue) btnContinue.disabled = false;
      if (btnSettings) btnSettings.disabled = false;
    }
  }

  function updateChildLockCountdown(notice, countdown, seconds) {
    if (countdown) countdown.textContent = String(Math.max(0, seconds));
    if (notice) {
      notice.setAttribute(
        "aria-label",
        helpers.getChildLockCountdownMessage(seconds)
      );
    }
  }

  function clearChildLockCountdown(widget) {
    if (!widget?.__childLockInterval) return;
    clearInterval(widget.__childLockInterval);
    widget.__childLockInterval = null;
  }

  function returnToSafety(shadowRoot, options = {}) {
    const widget = shadowRoot.getElementById("ps-widget");
    if (widget?.dataset.returningToSafety === "true") return;
    if (widget) widget.dataset.returningToSafety = "true";

    clearChildLockCountdown(widget);

    if (options.closeTabOnSafety) {
      chrome.runtime.sendMessage({ action: "closeCurrentTab" }, () => {
        if (!chrome.runtime.lastError) return;
        closeWithAnimation(shadowRoot, removeHidingStyle);
      });
      return;
    }

    closeWithAnimation(shadowRoot, () => {
      removeHidingStyle();
      if (options.pendingUrl || options.unexpectedRedirect) return;

      if (document.referrer) {
        window.history.back();
      } else {
        window.location.href = "https://www.google.com";
      }
    });
  }

  async function approveInterceptedDownload(shadowRoot, url) {
    try {
      const settings = await chrome.storage.local.get(["childLockEnabled"]);
      return showDownloadApprovalDialog(shadowRoot, {
        requireParentPassword: settings.childLockEnabled === true,
        onApprove: async () => {
          const response = await sendRuntimeMessage({
            action: "allowDownloadOnce",
            url,
          });
          return response?.ok
            ? ""
            : "The one-time download approval could not be saved.";
        },
      });
    } catch (error) {
      console.error("Download approval failed:", error);
      return false;
    }
  }

  function showDownloadApprovalDialog(
    shadowRoot,
    { requireParentPassword, onApprove }
  ) {
    const dialog = shadowRoot.getElementById("ps-download-approval-dialog");
    const form = shadowRoot.getElementById("ps-download-approval-form");
    const title = shadowRoot.getElementById("ps-download-approval-title");
    const message = shadowRoot.getElementById("ps-download-approval-message");
    const parentField = shadowRoot.getElementById("ps-download-parent-field");
    const passwordInput = shadowRoot.getElementById("ps-download-parent-password");
    const errorBox = shadowRoot.getElementById("ps-download-approval-error");
    const cancelButton = shadowRoot.getElementById("ps-download-approval-cancel");
    const submitButton = shadowRoot.getElementById("ps-download-approval-submit");

    if (!dialog || !form || dialog.dataset.open === "true") {
      return Promise.resolve(false);
    }

    title.textContent = requireParentPassword
      ? "Parent approval required"
      : "Confirm high-risk download";
    message.textContent = requireParentPassword
      ? "Child Lock is active. Enter the parent password to approve this download once."
      : "Continue only if you trust this website and expected this file.";
    parentField.hidden = !requireParentPassword;
    passwordInput.value = "";
    errorBox.textContent = "";
    submitButton.disabled = false;
    cancelButton.disabled = false;
    dialog.hidden = false;
    dialog.setAttribute("aria-hidden", "false");
    dialog.dataset.open = "true";

    setTimeout(() => {
      if (requireParentPassword) {
        passwordInput.focus();
      } else {
        submitButton.focus();
      }
    }, 0);

    return new Promise((resolve) => {
      const finish = (approved) => {
        dialog.hidden = true;
        dialog.setAttribute("aria-hidden", "true");
        dialog.dataset.open = "false";
        form.removeEventListener("submit", handleSubmit);
        cancelButton.removeEventListener("click", handleCancel);
        dialog.removeEventListener("keydown", handleKeyDown);
        resolve(approved);
      };

      const handleCancel = () => finish(false);
      const handleKeyDown = (event) => {
        if (event.key === "Escape" && !submitButton.disabled) {
          event.preventDefault();
          finish(false);
        }
      };
      const handleSubmit = async (event) => {
        event.preventDefault();
        if (submitButton.disabled) return;

        errorBox.textContent = "";
        submitButton.disabled = true;
        cancelButton.disabled = true;

        try {
          if (requireParentPassword) {
            const verified = await verifyParentPassword(passwordInput.value);
            if (!verified) {
              errorBox.textContent = "Incorrect parent password.";
              submitButton.disabled = false;
              cancelButton.disabled = false;
              passwordInput.focus();
              return;
            }
          }

          const approvalError = await onApprove();
          if (approvalError) {
            errorBox.textContent = approvalError;
            submitButton.disabled = false;
            cancelButton.disabled = false;
            return;
          }

          finish(true);
        } catch (error) {
          errorBox.textContent =
            error.message || "The download could not be approved.";
          submitButton.disabled = false;
          cancelButton.disabled = false;
        }
      };

      form.addEventListener("submit", handleSubmit);
      cancelButton.addEventListener("click", handleCancel);
      dialog.addEventListener("keydown", handleKeyDown);
    });
  }

  async function verifyParentPassword(password) {
    const childLock = globalThis.PhishShieldChildLock;
    if (!childLock || typeof password !== "string") return false;

    const data = await chrome.storage.local.get([
      "childPasswordRecord",
      "childPassword",
    ]);

    if (childLock.isPasswordRecord(data.childPasswordRecord)) {
      return childLock.verifyPassword(password, data.childPasswordRecord);
    }

    if (
      typeof data.childPassword !== "string" ||
      password !== data.childPassword
    ) {
      return false;
    }

    const record = await childLock.createPasswordRecord(password);
    await chrome.storage.local.set({ childPasswordRecord: record });
    await chrome.storage.local.remove("childPassword");
    return true;
  }

  function sendRuntimeMessage(message) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response);
      });
    });
  }

  function updateHeaderUI(shadowRoot, data, options = {}) {
    const headerTitle = shadowRoot.querySelector(".ps-header .ps-title");
    const subtitle = shadowRoot.querySelector(".ps-subtitle");
    const statusPill = shadowRoot.getElementById("ps-status-pill");
    const status = data.status;
    const download = data.download || {};
    const isInterceptedDownload = options.isInterceptedDownload === true;
    const isUnexpectedRedirect = options.isUnexpectedRedirect === true;

    if (!headerTitle || !subtitle) return;

    if (data.previouslyAllowed) {
      headerTitle.textContent = "Previously Allowed";
      subtitle.textContent = "Bypass Reminder";
      if (statusPill) statusPill.textContent = "Allowed";
    } else if (isUnexpectedRedirect) {
      headerTitle.textContent = status === "phishing"
        ? "Malicious Redirect Blocked"
        : "Unexpected Redirect Blocked";
      subtitle.textContent = "Cross-Domain Popup Protection";
      if (statusPill) statusPill.textContent = "Blocked";
    } else if (isInterceptedDownload || download?.is_malicious) {
      headerTitle.textContent = "High-Risk Download Detected";
      subtitle.textContent = "Download Protection";
      if (statusPill) statusPill.textContent = "Blocked";
    } else if (status === "safe") {
      headerTitle.textContent = "Website Appears Safe";
      subtitle.textContent = "PhishShield AI Scan";
      if (statusPill) statusPill.textContent = "Low Risk";
    } else if (status === "suspicious") {
      headerTitle.textContent = "Suspicious Website";
      subtitle.textContent = "Caution Recommended";
      if (statusPill) statusPill.textContent = "Review Needed";
    } else {
      headerTitle.textContent = "Deceptive Site Ahead";
      subtitle.textContent = "PhishShield AI Flag";
      if (statusPill) statusPill.textContent = "High Risk";
    }
  }

  function closeWithAnimation(shadowRoot, callback) {
    const widget = shadowRoot.getElementById("ps-widget");
    widget?.classList.remove("show");
    widget?.classList.add("hide");

    setTimeout(() => {
      const root = shadowRoot.host;
      root?.remove();
      callback?.();
    }, 700);
  }

  function startSafeDismiss(shadowRoot, widget) {
    if (!widget || widget.dataset.safePopup !== "true") return;

    clearTimeout(widget.__safeDismissTimer);

    const start = () => {
      if (shadowRoot.getElementById("dashboard-wrapper")) return;

      widget.__safeDismissTimer = setTimeout(() => {
        closeWithAnimation(shadowRoot);
      }, 5000);
    };

    start();

    if (!widget.__safeDismissBound) {
      widget.__safeDismissBound = true;
      widget.addEventListener("mouseenter", () => pauseSafeDismiss(widget));
      widget.addEventListener("mouseleave", () => {
        pauseSafeDismiss(widget);
        start();
      });
    }
  }

  function pauseSafeDismiss(widget) {
    if (!widget) return;
    clearTimeout(widget.__safeDismissTimer);
    widget.__safeDismissTimer = null;
  }

  function bindSettingsButton(shadowRoot, button, widget) {
    if (!button || button.dataset.settingsBound === "true") return;

    button.dataset.settingsBound = "true";
    button.addEventListener("click", () => {
      pauseSafeDismiss(widget);
      openDashboard(shadowRoot, widget);
    });
  }

  function updateRiskUI(shadowRoot, riskScore, status) {
    const progress = shadowRoot.getElementById("risk-progress");
    const scoreText = shadowRoot.getElementById("risk-score-text");
    const title = shadowRoot.getElementById("risk-title");

    if (!progress || !scoreText || !title) return;

    const animationState = helpers.getRiskAnimationState(riskScore);
    const safeScore = animationState.endScore;
    const radius = 60;
    const circumference = 2 * Math.PI * radius;
    const targetOffset = circumference - ((safeScore / 100) * circumference);

    progress.style.strokeDasharray = `${circumference}`;
    progress.style.transition = "none";
    progress.style.strokeDashoffset = `${circumference}`;
    scoreText.textContent = `${animationState.startScore}%`;

    if (status === "safe" || safeScore <= 30) {
      progress.style.stroke = "#00ff88";
      title.textContent = "Website Appears Safe";
    } else if (status === "suspicious" || safeScore <= 70) {
      progress.style.stroke = "#ffb300";
      title.textContent = "Suspicious Website";
    } else {
      progress.style.stroke = "#ff3366";
      title.textContent = "Phishing Detected";
    }

    progress.getBoundingClientRect();
    progress.style.transition = "stroke-dashoffset 1.2s ease, stroke 1s ease";

    requestAnimationFrame(() => {
      progress.style.strokeDashoffset = `${targetOffset}`;
    });

    animateScoreText(scoreText, animationState.startScore, safeScore);
  }

  function animateScoreText(element, startScore, endScore) {
    const duration = 1200;
    const startTime = performance.now();

    if (element.__riskAnimationFrame) {
      cancelAnimationFrame(element.__riskAnimationFrame);
    }

    const tick = (now) => {
      const progress = Math.min((now - startTime) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const value = startScore + ((endScore - startScore) * eased);

      element.textContent = `${Math.round(value)}%`;

      if (progress < 1) {
        element.__riskAnimationFrame = requestAnimationFrame(tick);
      }
    };

    element.__riskAnimationFrame = requestAnimationFrame(tick);
  }

  async function openDashboard(shadowRoot, widget, options = {}) {
    if (shadowRoot.getElementById("dashboard-wrapper")) return;

    try {
      shadowRoot.host.style.pointerEvents = "auto";

      const response = await fetch(chrome.runtime.getURL("Dashboard/dashboard.html"));
      const htmlString = await response.text();
      const wrapper = document.createElement("div");

      wrapper.id = "dashboard-wrapper";
      wrapper.innerHTML = htmlString;
      wrapper.style.position = "fixed";
      wrapper.style.inset = "0";
      wrapper.style.zIndex = "2147483647";
      wrapper.style.pointerEvents = "auto";
      wrapper.dataset.standalone = options.standalone ? "true" : "false";

      shadowRoot.appendChild(wrapper);

      const module = await import(chrome.runtime.getURL("Dashboard/dashboard.js"));
      module.bindDashboardEvents(shadowRoot, wrapper);

      const closeBtn = wrapper.querySelector("#dashboard-close");
      closeBtn?.addEventListener("click", () => {
        setTimeout(() => {
          if (wrapper.dataset.removeOverlayOnClose === "true") {
            removeOverlay(shadowRoot);
            return;
          }

          if (wrapper.dataset.standalone === "true" && !widget?.classList.contains("show")) {
            removeOverlay(shadowRoot);
            return;
          }

          if (widget?.isConnected && widget.dataset.safePopup === "true") {
            setOverlayInteraction(shadowRoot, "safe");
            startSafeDismiss(shadowRoot, widget);
          }
        }, 50);
      }, { once: true });
    } catch (error) {
      console.error("Dashboard load failed:", error);
    }
  }

  async function openStandaloneDashboard() {
    try {
      const shadowRoot = await createOverlay({
        hostname: getHostname(window.location.href),
        riskScore: 0,
        status: "safe",
      }, false);
      const widget = shadowRoot.getElementById("ps-widget");
      openDashboard(shadowRoot, widget, { standalone: true });
    } catch (error) {
      console.error("Dashboard overlay failed:", error);
    }
  }

  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.button !== 0) return;

    const eventPath = typeof event.composedPath === "function"
      ? event.composedPath()
      : [];
    if (eventPath.some((node) => node?.id === "security-block-root")) return;

    const target = event.target instanceof Element ? event.target : null;
    const anchor = target?.closest("a[href]");
    let intendedUrl = "";

    if (anchor) {
      try {
        const candidate = new URL(
          anchor.getAttribute("href"),
          window.location.href
        );
        if (candidate.protocol === "http:" || candidate.protocol === "https:") {
          intendedUrl = candidate.href;
        }
      } catch (error) {
        intendedUrl = "";
      }
    }

    chrome.runtime.sendMessage({
      action: "recordPageInteraction",
      sourceUrl: window.location.href,
      intendedUrl,
      occurredAt: Date.now(),
    }).catch(() => {});

    if (!anchor || !intendedUrl) return;

    const url = intendedUrl;
    if (!isLikelyDownloadLink(anchor, url) || shouldSkipScan(url)) return;

    event.preventDefault();
    event.stopPropagation();

    runCheck(url, {
      forceScan: true,
      filename: anchor.getAttribute("download") || "",
      pendingUrl: url,
    });
  }, true);

  chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "urlChanged") {
      runCheck(message.url || window.location.href);
    }

    if (message.action === "openDashboardOverlay") {
      openStandaloneDashboard();
    }

    if (message.action === "unexpectedRedirectBlocked" && message.url) {
      runCheck(message.url, {
        forceScan: true,
        unexpectedRedirect: true,
      });
    }
  });
})();
