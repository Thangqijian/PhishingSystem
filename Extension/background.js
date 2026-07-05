importScripts("download-allowance.js");
importScripts("bypass-records.js", "navigation-guard.js");

const API_URL = "http://localhost:5000/analyze";
const downloadAllowanceHelpers = globalThis.PhishShieldDownloadAllowances;
const bypassRecordHelpers = globalThis.PhishShieldBypassRecords;
const navigationGuard = globalThis.PhishShieldNavigationGuard;
const downloadAllowanceStore =
  downloadAllowanceHelpers.createDownloadAllowanceStore();

const REFERENCE_SKIP_DOMAINS = [
  "safebrowsing.google.com",
  "consumer.ftc.gov",
  "urlhaus.abuse.ch",
];

const DANGEROUS_DOWNLOAD_EXTENSIONS = [
  ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
  ".scr", ".jar", ".dll", ".pif", ".com", ".hta",
  ".wsf", ".cpl", ".reg", ".iso", ".img", ".apk",
];

chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get([
    "protectionEnabled",
    "showSafeNotifications",
    "rememberBypass",
    "childLockEnabled",
    "scannedCount",
    "blockedCount",
    "downloadBlockedCount",
    "blockedList",
    "bypassedList",
  ], (result) => {
    const defaults = {};

    if (result.protectionEnabled === undefined) defaults.protectionEnabled = true;
    if (result.showSafeNotifications === undefined) defaults.showSafeNotifications = true;
    if (result.rememberBypass === undefined) defaults.rememberBypass = true;
    if (result.childLockEnabled === undefined) defaults.childLockEnabled = false;
    if (result.scannedCount === undefined) defaults.scannedCount = 0;
    if (result.blockedCount === undefined) defaults.blockedCount = 0;
    if (result.downloadBlockedCount === undefined) defaults.downloadBlockedCount = 0;
    if (result.blockedList === undefined) defaults.blockedList = [];
    if (result.bypassedList === undefined) defaults.bypassedList = [];

    if (Object.keys(defaults).length > 0) {
      chrome.storage.local.set(defaults);
    }
  });
});

function openDashboardTab() {
  chrome.tabs.create({
    url: chrome.runtime.getURL("Dashboard/dashboard.html"),
  });
}

chrome.action.onClicked.addListener((tab) => {
  if (!tab?.id || !/^https?:\/\//i.test(tab.url || "")) {
    openDashboardTab();
    return;
  }

  chrome.tabs.sendMessage(tab.id, { action: "openDashboardOverlay" })
    .catch(() => {
      openDashboardTab();
    });
});

const tabCache = {};
const lastUrlPerTab = {};
const recentInteractionsByTab = {};
const recentGlobalInteractions = [];
const pendingCreatedTabs = {};
const handledCreatedTabs = new Set();
const MAX_RECENT_GLOBAL_INTERACTIONS = 12;

function markCreatedTabHandled(tabId) {
  handledCreatedTabs.add(tabId);
  setTimeout(() => handledCreatedTabs.delete(tabId), 5000);
}

function trackCreatedTab(tabId, openerTabId, targetUrl = "") {
  if (!tabId || !openerTabId || handledCreatedTabs.has(tabId)) return;

  const existing = pendingCreatedTabs[tabId];
  if (existing) {
    existing.openerTabId = openerTabId;
    existing.interaction =
      existing.interaction || recentInteractionsByTab[openerTabId] || null;
    existing.targetUrl = targetUrl || existing.targetUrl;
  } else {
    pendingCreatedTabs[tabId] = {
      openerTabId,
      interaction: recentInteractionsByTab[openerTabId] || null,
      targetUrl,
      createdAt: Date.now(),
      timer: null,
    };
  }

  scheduleCreatedTabCheck(tabId);
}

function rememberGlobalInteraction(interaction) {
  if (!interaction) return;

  recentGlobalInteractions.push(interaction);
  while (recentGlobalInteractions.length > MAX_RECENT_GLOBAL_INTERACTIONS) {
    recentGlobalInteractions.shift();
  }
}

function pruneRecentGlobalInteractions(now = Date.now()) {
  const maxAge = navigationGuard.INTERACTION_WINDOW_MS + 1000;

  for (let index = recentGlobalInteractions.length - 1; index >= 0; index -= 1) {
    const occurredAt = Number(recentGlobalInteractions[index]?.occurredAt);
    if (!Number.isFinite(occurredAt) || now - occurredAt > maxAge) {
      recentGlobalInteractions.splice(index, 1);
    }
  }
}

function getUnexpectedInteractionForUrl(url, now = Date.now()) {
  pruneRecentGlobalInteractions(now);
  return navigationGuard.findUnexpectedInteraction({
    interactions: recentGlobalInteractions,
    targetUrl: url,
    now,
  });
}

function scheduleCreatedTabCheck(tabId, delay = 75) {
  const pending = pendingCreatedTabs[tabId];
  if (!pending) return;

  clearTimeout(pending.timer);
  pending.timer = setTimeout(() => {
    evaluateCreatedTab(tabId);
  }, delay);
}

async function evaluateCreatedTab(tabId) {
  const pending = pendingCreatedTabs[tabId];
  if (!pending) return;

  pending.timer = null;
  const now = Date.now();
  const interaction =
    pending.interaction ||
    recentInteractionsByTab[pending.openerTabId] ||
    getUnexpectedInteractionForUrl(targetUrl, now);
  const targetUrl = pending.targetUrl || "";

  if (
    now - pending.createdAt >
    navigationGuard.INTERACTION_WINDOW_MS + 500
  ) {
    delete pendingCreatedTabs[tabId];
    markCreatedTabHandled(tabId);
    return;
  }

  if (!interaction || !/^https?:\/\//i.test(targetUrl)) {
    if (!/^https?:\/\//i.test(targetUrl)) {
      scheduleCreatedTabCheck(tabId, 100);
      return;
    }

    if (!navigationGuard.hasDeceptiveAdSignals(targetUrl)) {
      scheduleCreatedTabCheck(tabId, 100);
      return;
    }
  }

  delete pendingCreatedTabs[tabId];
  markCreatedTabHandled(tabId);

  const settings = await chrome.storage.local.get(["protectionEnabled"]);
  if (settings.protectionEnabled === false) return;

  const isUnexpected =
    navigationGuard.hasDeceptiveAdSignals(targetUrl) ||
    navigationGuard.isUnexpectedCrossDomainTab({
      interaction,
      targetUrl,
      now,
    });
  if (!isUnexpected) return;

  chrome.tabs.remove(tabId, () => void chrome.runtime.lastError);
  chrome.tabs.sendMessage(pending.openerTabId, {
    action: "unexpectedRedirectBlocked",
    url: targetUrl,
  }).catch(() => {});
}

function getHostName(urlStr) {
  try {
    return new URL(urlStr).hostname.toLowerCase().replace("www.", "");
  } catch (e) {
    return "";
  }
}

function shouldSkipReferenceDomain(hostname) {
  return REFERENCE_SKIP_DOMAINS.some((domain) =>
    hostname === domain || hostname.endsWith("." + domain)
  );
}

function hasDangerousDownloadExtension(url = "", filename = "") {
  const candidates = [url, filename]
    .filter(Boolean)
    .map((value) => String(value).toLowerCase().split(/[?#]/)[0]);

  return DANGEROUS_DOWNLOAD_EXTENSIONS.some((ext) =>
    candidates.some((candidate) => candidate.endsWith(ext))
  );
}

async function analyzeURL(url, filename = "", unexpectedRedirect = false) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url,
      filename,
      unexpected_redirect: unexpectedRedirect,
    }),
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return response.json();
}

function addBlockedHost(hostname) {
  if (!hostname) return;

  chrome.storage.local.get(["blockedList", "blockedCount"], (data) => {
    const blockedList = Array.isArray(data.blockedList) ? data.blockedList : [];

    chrome.storage.local.set({
      blockedList: blockedList.includes(hostname)
        ? blockedList
        : [...blockedList, hostname],
      blockedCount: Number(data.blockedCount || 0) + 1,
    });
  });
}

function rememberBypass(hostname, riskScore) {
  if (!hostname) return;

  chrome.storage.local.get(
    ["rememberBypass", "bypassedList", "blockedList"],
    (data) => {
      if (data.rememberBypass === false) return;

      const bypassedList = Array.isArray(data.bypassedList)
        ? data.bypassedList
        : [];
      const blockedList = Array.isArray(data.blockedList)
        ? data.blockedList
        : [];
      chrome.storage.local.set({
        bypassedList: bypassRecordHelpers.upsertBypassRecord(bypassedList, {
          hostname,
          riskScore,
          bypassedAt: Date.now(),
        }),
        blockedList: bypassRecordHelpers.removeHostnameEntries(
          blockedList,
          hostname
        ),
      });
    }
  );
}

function formatResult(url, result, settings) {
  const hostname = getHostName(url);
  const download = result.download || {};
  let riskScore = Number(result.risk_score ?? 0);
  let status = result.status || (result.is_phishing ? "phishing" : "safe");

  if (download.is_malicious) {
    riskScore = Math.max(riskScore, 95);
    status = "phishing";
  } else if (download.is_suspicious && status === "safe") {
    riskScore = Math.max(riskScore, 45);
    status = "suspicious";
  }

  return {
    status,
    hostname,
    riskScore,
    riskLevel: result.risk_level,
    mlConfidence: result.ml_confidence,
    heuristicRisk: result.heuristic_risk,
    flags: result.flags || [],
    redirectCount: result.redirect_count || 0,
    crossDomain: result.cross_domain || false,
    resolvedUrl: result.resolved_url || url,
    urlhausHit: result.urlhaus_hit || false,
    download,
    modelUsed: result.model_used || "",
    recommendedAction: result.recommended_action || "allow",
    showSafeNotification: settings.showSafeNotifications !== false,
  };
}

async function handleCheckUrl(url, options = {}) {
  const hostname = getHostName(url);
  const unexpectedFromRecentClick = getUnexpectedInteractionForUrl(url);
  const unexpectedRedirect =
    options.unexpectedRedirect === true || Boolean(unexpectedFromRecentClick);
  const currentTabHostname = getHostName(options.currentTabUrl || "");
  const closeTabOnSafety = Boolean(
    unexpectedFromRecentClick &&
    currentTabHostname &&
    currentTabHostname === hostname
  );

  if (!hostname || shouldSkipReferenceDomain(hostname)) {
    return { status: "safe", riskScore: 0, hostname, showSafeNotification: false };
  }

  const data = await chrome.storage.local.get([
    "protectionEnabled",
    "showSafeNotifications",
    "rememberBypass",
    "scannedCount",
    "blockedCount",
    "blockedList",
    "bypassedList",
  ]);

  chrome.storage.local.set({ scannedCount: Number(data.scannedCount || 0) + 1 });

  if (data.protectionEnabled === false) {
    return {
      status: "safe",
      riskScore: 0,
      hostname,
      flags: ["Protection is currently disabled"],
      showSafeNotification: false,
    };
  }

  const blockedList = Array.isArray(data.blockedList) ? data.blockedList : [];
  if (blockedList.includes(hostname)) {
    return {
      status: "phishing",
      riskScore: 100,
      hostname,
      riskLevel: "HIGH",
      flags: ["Previously blocked domain"],
      showSafeNotification: true,
      unexpectedRedirect,
      closeTabOnSafety,
    };
  }

  const bypassedList = Array.isArray(data.bypassedList) ? data.bypassedList : [];
  const bypassRecord = bypassRecordHelpers.findBypassRecord(
    bypassedList,
    hostname
  );
  if (
    !unexpectedRedirect &&
    (data.rememberBypass ?? true) &&
    bypassRecord
  ) {
    const previousRiskScoreAvailable = bypassRecord.riskScore !== null;
    return {
      status: "safe",
      riskScore: previousRiskScoreAvailable ? bypassRecord.riskScore : null,
      hostname,
      flags: ["Site was previously allowed by the user"],
      previouslyAllowed: true,
      previousRiskScoreAvailable,
      bypassedAt: bypassRecord.bypassedAt,
      showSafeNotification: true,
      unexpectedRedirect,
      closeTabOnSafety,
    };
  }

  try {
    const result = await analyzeURL(
      url,
      options.filename || "",
      unexpectedRedirect
    );
    const formatted = formatResult(url, result, data);
    formatted.unexpectedRedirect = unexpectedRedirect;
    formatted.closeTabOnSafety = closeTabOnSafety;

    if (downloadAllowanceHelpers.shouldRememberBlockedHost(formatted)) {
      addBlockedHost(hostname);
    }

    return formatted;
  } catch (error) {
    console.error("Backend scan failed:", error);

    if (unexpectedRedirect) {
      return {
        status: "phishing",
        hostname,
        riskScore: 85,
        riskLevel: "HIGH",
        flags: [
          "Unexpected cross-domain tab was opened after a page click",
          "Backend service is unavailable, so the destination could not be fully scanned",
        ],
        showSafeNotification: true,
        unexpectedRedirect: true,
        closeTabOnSafety,
      };
    }

    if (hasDangerousDownloadExtension(url, options.filename)) {
      return {
        status: "phishing",
        hostname,
        riskScore: 95,
        riskLevel: "HIGH",
        flags: ["Dangerous download file type detected"],
        download: {
          is_malicious: true,
          is_suspicious: false,
          message: "Dangerous download file type detected",
        },
        showSafeNotification: true,
      };
    }

    return {
      status: "suspicious",
      hostname,
      riskScore: 50,
      riskLevel: "MEDIUM",
      flags: ["Backend service is not available, so this URL could not be fully scanned"],
      showSafeNotification: true,
    };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "recordPageInteraction") {
    const tabId = sender.tab?.id;
    if (tabId) {
      const interaction = navigationGuard.createInteraction({
        sourceUrl: sender.tab?.url || message.sourceUrl || "",
        intendedUrl: message.intendedUrl || "",
        occurredAt: message.occurredAt,
      });
      recentInteractionsByTab[tabId] = interaction;
      rememberGlobalInteraction(interaction);

      Object.entries(pendingCreatedTabs).forEach(([createdTabId, pending]) => {
        if (pending.openerTabId !== tabId) return;
        pending.interaction = interaction;
        scheduleCreatedTabCheck(Number(createdTabId), 0);
      });
    }

    sendResponse({ ok: Boolean(tabId) });
    return true;
  }

  if (message.action === "allowDownloadOnce") {
    const allowed = downloadAllowanceStore.allow(message.url);
    sendResponse({ ok: allowed });
    return true;
  }

  if (message.action === "closeCurrentTab") {
    const tabId = sender.tab?.id;
    if (!tabId) {
      sendResponse({ ok: false });
      return true;
    }

    chrome.tabs.remove(tabId, () => {
      sendResponse({ ok: !chrome.runtime.lastError });
    });
    return true;
  }

  if (message.action === "checkUrl") {
    const tabId = sender.tab?.id;
    const url = message.url;

    if (tabId && tabCache[tabId]?.url === url && !message.forceScan) {
      sendResponse(tabCache[tabId].result);
      return true;
    }

    (async () => {
      const result = await handleCheckUrl(url, {
        filename: message.filename || "",
        unexpectedRedirect: message.unexpectedRedirect === true,
        currentTabUrl: sender.tab?.url || "",
      });

      if (tabId) {
        tabCache[tabId] = { url, result };
      }

      sendResponse(result);
    })();

    return true;
  }

  if (message.action === "rememberBypass") {
    rememberBypass(
      message.hostname || getHostName(message.url),
      message.riskScore
    );
    sendResponse({ ok: true });
    return true;
  }

  if (message.action === "openDashboard") {
    openDashboardTab();
    sendResponse({ ok: true });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabCache[tabId];
  delete lastUrlPerTab[tabId];
  delete recentInteractionsByTab[tabId];

  const pending = pendingCreatedTabs[tabId];
  if (pending?.timer) clearTimeout(pending.timer);
  delete pendingCreatedTabs[tabId];
});

chrome.tabs.onCreated.addListener((tab) => {
  if (!tab.id || !tab.openerTabId) return;

  trackCreatedTab(
    tab.id,
    tab.openerTabId,
    tab.pendingUrl || tab.url || ""
  );
});

chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
  trackCreatedTab(details.tabId, details.sourceTabId, details.url);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!changeInfo.url) return;

  if (pendingCreatedTabs[tabId]) {
    pendingCreatedTabs[tabId].targetUrl =
      changeInfo.url || tab?.pendingUrl || tab?.url || "";
    scheduleCreatedTabCheck(tabId, 0);
    return;
  }

  if (lastUrlPerTab[tabId] === changeInfo.url) return;

  lastUrlPerTab[tabId] = changeInfo.url;

  chrome.tabs.sendMessage(tabId, {
    action: "urlChanged",
    url: changeInfo.url,
  }).catch(() => {});
});

chrome.downloads.onCreated.addListener((downloadItem) => {
  (async () => {
    const url = downloadItem.finalUrl || downloadItem.url || downloadItem.referrer || "";
    const filename = downloadItem.filename || "";

    if (downloadAllowanceStore.consume([downloadItem.finalUrl, downloadItem.url])) {
      return;
    }

    const settings = await chrome.storage.local.get(["protectionEnabled", "downloadBlockedCount"]);
    if (settings.protectionEnabled === false) return;

    let shouldCancel = hasDangerousDownloadExtension(url, filename);

    try {
      const result = await handleCheckUrl(url, { filename });
      shouldCancel =
        shouldCancel ||
        result.download?.is_malicious ||
        result.recommendedAction === "block_download";
    } catch (error) {
      console.error("Download scan failed:", error);
    }

    if (!shouldCancel) return;

    chrome.downloads.cancel(downloadItem.id, () => {
      chrome.downloads.erase({ id: downloadItem.id });
    });

    chrome.storage.local.set({
      downloadBlockedCount: Number(settings.downloadBlockedCount || 0) + 1,
    });

    chrome.notifications?.create({
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "PhishGuard blocked a high-risk download",
      message: "The file type can run or modify software. Download only from a source you trust.",
    });
  })();
});
