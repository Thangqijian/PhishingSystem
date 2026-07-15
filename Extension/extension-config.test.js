const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = __dirname;

function test(name, fn) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (error) {
    console.error(`FAIL ${name}`);
    console.error(error.message);
    process.exitCode = 1;
  }
}

test("toolbar action is reserved for opening the dashboard", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

  assert.strictEqual(manifest.action.default_popup, undefined);
  assert.strictEqual(manifest.action.default_title, "Open PhishShield Dashboard");
});

test("extension details page exposes dashboard as options page", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

  assert.deepStrictEqual(manifest.options_ui, {
    page: "Dashboard/dashboard.html",
    open_in_tab: true,
  });
});

test("content helper loads before content script", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const scripts = manifest.content_scripts[0].js;

  assert.ok(scripts.indexOf("content-helpers.js") < scripts.indexOf("content.js"));
});

test("child lock helper loads before content script", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const scripts = manifest.content_scripts[0].js;

  assert.deepStrictEqual(scripts.slice(0, 3), [
    "content-helpers.js",
    "child-lock.js",
    "bypass-records.js",
  ]);
  assert.ok(scripts.indexOf("bypass-records.js") < scripts.indexOf("content.js"));
});

test("dashboard uses a child lock dialog and reset control", () => {
  const dashboardHtml = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.html"),
    "utf8"
  );

  assert.ok(dashboardHtml.includes('id="child-lock-dialog"'));
  assert.ok(dashboardHtml.includes('id="child-lock-form"'));
  assert.ok(dashboardHtml.includes('id="child-lock-dialog-error"'));
  assert.ok(dashboardHtml.includes('id="reset-child-password-btn"'));
  assert.ok(dashboardHtml.includes("Reset password"));
  assert.strictEqual(dashboardHtml.includes('id="child-password"'), false);
  assert.strictEqual(dashboardHtml.includes('id="save-password-btn"'), false);
});

test("dashboard and content script avoid native password prompts", () => {
  const dashboardHtml = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.html"),
    "utf8"
  );
  const contentJs = fs.readFileSync(path.join(root, "content.js"), "utf8");

  assert.ok(dashboardHtml.includes('<script src="../child-lock.js"></script>'));
  assert.strictEqual(contentJs.includes("prompt("), false);
  assert.strictEqual(contentJs.includes("verifyChildLock"), false);
});

test("dashboard URLHaus controls use clear wording", () => {
  const dashboardHtml = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.html"),
    "utf8"
  );
  const dashboardJs = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.js"),
    "utf8"
  );

  assert.ok(dashboardHtml.includes("Check status"));
  assert.ok(dashboardHtml.includes("Update URLHaus now"));
  assert.ok(dashboardJs.includes("Needs URLHaus key"));
});

test("dashboard explains how to reopen settings when protection is off", () => {
  const dashboardHtml = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.html"),
    "utf8"
  );

  assert.ok(dashboardHtml.includes("Click the extension icon"));
});

test("dashboard close button has restrained hover feedback", () => {
  const dashboardHtml = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.html"),
    "utf8"
  );

  assert.ok(dashboardHtml.includes(".icon-btn:hover"));
  assert.ok(dashboardHtml.includes("background: #fef2f2"));
  assert.ok(dashboardHtml.includes("transform: translateY(-1px)"));
});

test("warning popup includes the child lock countdown notice", () => {
  const popupHtml = fs.readFileSync(path.join(root, "popup.html"), "utf8");

  assert.ok(popupHtml.includes('id="ps-child-lock-notice"'));
  assert.ok(popupHtml.includes('id="ps-child-lock-countdown"'));
  assert.ok(popupHtml.includes("Child Lock is active"));
});

test("content script wires the five second child lock safety return", () => {
  const contentJs = fs.readFileSync(path.join(root, "content.js"), "utf8");

  assert.ok(contentJs.includes("CHILD_LOCK_RETURN_SECONDS = 5"));
  assert.ok(contentJs.includes("startChildLockReturnCountdown"));
  assert.ok(contentJs.includes("returnToSafety"));
  assert.ok(contentJs.includes('btnContinue.style.display = "none"'));
  assert.ok(contentJs.includes('btnSettings.style.display = "none"'));
});

test("download warning uses awareness wording and approval dialog", () => {
  const popupHtml = fs.readFileSync(path.join(root, "popup.html"), "utf8");
  const contentJs = fs.readFileSync(path.join(root, "content.js"), "utf8");

  assert.ok(popupHtml.includes('id="ps-download-approval-dialog"'));
  assert.ok(popupHtml.includes('id="ps-download-approval-form"'));
  assert.ok(popupHtml.includes('id="ps-download-parent-password"'));
  assert.ok(popupHtml.includes('id="ps-download-approval-error"'));
  assert.ok(contentJs.includes("High-Risk Download Detected"));
  assert.ok(contentJs.includes('btnSafe.textContent = "Back to Safety"'));
  assert.ok(contentJs.includes("Download Anyway"));
  assert.ok(contentJs.includes("Continue only if you trust this website"));
  assert.ok(contentJs.includes("helpers.isInterceptedDownload(options)"));
});

test("risk percentage clearly identifies malicious risk", () => {
  const popupHtml = fs.readFileSync(path.join(root, "popup.html"), "utf8");

  assert.ok(popupHtml.includes('id="risk-score-label"'));
  assert.ok(popupHtml.includes("MALICIOUS RISK"));
});

test("bypassed sites preserve and explain the previous risk score", () => {
  const backgroundJs = fs.readFileSync(path.join(root, "background.js"), "utf8");
  const contentJs = fs.readFileSync(path.join(root, "content.js"), "utf8");
  const dashboardHtml = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.html"),
    "utf8"
  );
  const dashboardJs = fs.readFileSync(
    path.join(root, "Dashboard", "dashboard.js"),
    "utf8"
  );

  assert.ok(backgroundJs.includes('importScripts("bypass-records.js", "navigation-guard.js")'));
  assert.ok(backgroundJs.includes("findBypassRecord"));
  assert.ok(backgroundJs.includes("removeHostnameEntries"));
  assert.ok(backgroundJs.includes("previouslyAllowed: true"));
  assert.ok(backgroundJs.includes("previousRiskScoreAvailable"));
  assert.ok(contentJs.includes("riskScore: data.riskScore"));
  assert.ok(contentJs.includes("PREVIOUS RISK SCORE"));
  assert.ok(contentJs.includes("Previously Allowed"));
  assert.ok(contentJs.includes("was not rescanned"));
  assert.ok(dashboardHtml.includes('<script src="../bypass-records.js"></script>'));
  assert.ok(dashboardJs.includes("getBypassHostname"));
});

test("unexpected cross-domain tabs are blocked and reported to the opener", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  const backgroundJs = fs.readFileSync(path.join(root, "background.js"), "utf8");
  const contentJs = fs.readFileSync(path.join(root, "content.js"), "utf8");
  const frameRecorder = manifest.content_scripts.find((entry) =>
    entry.js.includes("interaction-recorder.js")
  );

  assert.ok(frameRecorder);
  assert.strictEqual(frameRecorder.all_frames, true);
  assert.strictEqual(frameRecorder.match_about_blank, true);
  assert.ok(backgroundJs.includes('"navigation-guard.js"'));
  assert.ok(backgroundJs.includes('message.action === "recordPageInteraction"'));
  assert.ok(backgroundJs.includes("chrome.tabs.onCreated.addListener"));
  assert.ok(backgroundJs.includes("chrome.webNavigation.onCreatedNavigationTarget.addListener"));
  assert.ok(backgroundJs.includes("hasDeceptiveAdSignals(targetUrl)"));
  assert.ok(backgroundJs.includes("recentGlobalInteractions"));
  assert.ok(backgroundJs.includes("findUnexpectedInteraction"));
  assert.ok(backgroundJs.includes("isUnexpectedCrossDomainTab"));
  assert.strictEqual(backgroundJs.includes("Boolean(unexpectedFromRecentClick)"), false);
  assert.ok(backgroundJs.includes("closeTabOnSafety"));
  assert.ok(backgroundJs.includes('message.action === "returnToSafety"'));
  assert.strictEqual(backgroundJs.includes('message.action === "closeCurrentTab"'), false);
  assert.strictEqual(backgroundJs.includes("chrome.tabs.remove"), false);
  assert.ok(backgroundJs.includes("spawnedTabs"));
  assert.ok(backgroundJs.includes("rememberSpawnedTab"));
  assert.ok(backgroundJs.includes("getSpawnedTab"));
  assert.ok(backgroundJs.includes("unexpectedRedirectTabs"));
  assert.ok(backgroundJs.includes("rememberUnexpectedRedirectTab"));
  assert.ok(backgroundJs.includes("getUnexpectedRedirectTab"));
  assert.ok(backgroundJs.includes('action: "unexpectedRedirectBlocked"'));
  assert.ok(backgroundJs.includes("closeTabOnSafety: true"));
  assert.ok(backgroundJs.includes("unexpected_redirect: unexpectedRedirect"));
  assert.ok(contentJs.includes('action: "recordPageInteraction"'));
  assert.ok(contentJs.includes('message.action === "unexpectedRedirectBlocked"'));
  assert.ok(contentJs.includes("message.unexpectedRedirect === true"));
  assert.ok(contentJs.includes(
    "unexpectedRedirect: options.unexpectedRedirect === true"
  ));
  assert.ok(contentJs.includes("referrerUrl: options.referrerUrl || document.referrer || \"\""));
  assert.ok(contentJs.includes("response.closeTabOnSafety === true"));
  assert.ok(contentJs.includes("options.unexpectedRedirect && !options.closeTabOnSafety"));
  assert.ok(contentJs.includes('action: "returnToSafety"'));
  assert.strictEqual(contentJs.includes("Stay on This Page"), false);
  assert.ok(contentJs.includes("Unexpected Redirect Blocked"));
  assert.ok(contentJs.includes("Malicious Redirect Blocked"));
  assert.ok(contentJs.includes("Cross-Domain Popup Protection"));
});

test("background supports one-time approved downloads", () => {
  const backgroundJs = fs.readFileSync(path.join(root, "background.js"), "utf8");
  const contentJs = fs.readFileSync(path.join(root, "content.js"), "utf8");

  assert.ok(backgroundJs.includes('importScripts("download-allowance.js")'));
  assert.ok(backgroundJs.includes('message.action === "allowDownloadOnce"'));
  assert.ok(backgroundJs.includes("showDownloadBlockedPopup"));
  assert.ok(backgroundJs.includes("getDownloadReviewTabIds"));
  assert.ok(backgroundJs.includes('action: "downloadBlockedForReview"'));
  assert.ok(contentJs.includes('message.action === "downloadBlockedForReview"'));
  assert.ok(backgroundJs.includes("downloadAllowanceStore.consume"));
  assert.ok(backgroundJs.includes("PhishGuard blocked a high-risk download"));
});

test("extension-only download fallback does not blacklist the source host", () => {
  const backgroundJs = fs.readFileSync(path.join(root, "background.js"), "utf8");
  const fallbackStart = backgroundJs.indexOf(
    "if (hasDangerousDownloadExtension(url, options.filename))"
  );
  const fallbackEnd = backgroundJs.indexOf(
    "return {",
    backgroundJs.indexOf("showSafeNotification: true", fallbackStart)
  );
  const fallbackBlock = backgroundJs.slice(fallbackStart, fallbackEnd);

  assert.ok(fallbackStart >= 0);
  assert.strictEqual(fallbackBlock.includes("addBlockedHost(hostname)"), false);
});

test("popup card stays accessible on short browser viewports", () => {
  const popupHtml = fs.readFileSync(path.join(root, "popup.html"), "utf8");

  assert.ok(popupHtml.includes("max-height: calc(100vh - 24px)"));
  assert.ok(popupHtml.includes("overflow-y: auto"));
  assert.ok(popupHtml.includes("@media (max-height: 820px)"));
  assert.ok(popupHtml.includes('viewBox="0 0 140 140"'));
  assert.ok(popupHtml.includes(".risk-circle svg"));
  assert.ok(popupHtml.includes("width: 100%"));
  assert.ok(popupHtml.includes("height: 100%"));
  assert.strictEqual(
    popupHtml.includes(".risk-circle,\n    .risk-circle svg"),
    false
  );
});

test("manifest exposes the updated extension version", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));

  assert.strictEqual(manifest.version, "1.2.1");
});
