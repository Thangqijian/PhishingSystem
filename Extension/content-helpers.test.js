const assert = require("assert");

const {
  chooseScanUrl,
  getChildLockCountdownMessage,
  isInterceptedDownload,
  shouldBlockPageForStatus,
  shouldEnforceChildLock,
  getRiskAnimationState,
  shouldRunProtection,
} = require("./content-helpers.js");

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

test("chooseScanUrl prefers navigation URL over stale document URL", () => {
  const url = chooseScanUrl({
    documentUrl: "https://www.google.com/search?q=bank",
    navigationUrl: "https://secure-login-check.example.com/account/verify",
  });

  assert.strictEqual(url, "https://secure-login-check.example.com/account/verify");
});

test("safe result does not keep a full-page click blocker active", () => {
  assert.strictEqual(shouldBlockPageForStatus("safe"), false);
  assert.strictEqual(shouldBlockPageForStatus("suspicious"), true);
  assert.strictEqual(shouldBlockPageForStatus("phishing"), true);
  assert.strictEqual(shouldBlockPageForStatus("loading"), true);
});

test("risk animation starts from zero and ends at the scan score", () => {
  assert.deepStrictEqual(getRiskAnimationState(30), {
    startScore: 0,
    endScore: 30,
  });

  assert.deepStrictEqual(getRiskAnimationState(130), {
    startScore: 0,
    endScore: 100,
  });
});

test("protection disabled means the content script should not show scan UI", () => {
  assert.strictEqual(shouldRunProtection(false), false);
  assert.strictEqual(shouldRunProtection(true), true);
  assert.strictEqual(shouldRunProtection(undefined), true);
});

test("child lock enforces suspicious and phishing warnings only", () => {
  assert.strictEqual(shouldEnforceChildLock(true, "suspicious"), true);
  assert.strictEqual(shouldEnforceChildLock(true, "phishing"), true);
  assert.strictEqual(shouldEnforceChildLock(true, "safe"), false);
  assert.strictEqual(shouldEnforceChildLock(false, "phishing"), false);
  assert.strictEqual(shouldEnforceChildLock(undefined, "phishing"), false);
});

test("child lock leaves intercepted downloads available for parent approval", () => {
  assert.strictEqual(shouldEnforceChildLock(true, "phishing", true), false);
  assert.strictEqual(shouldEnforceChildLock(true, "phishing", false), true);
});

test("pending download URL preserves download context without backend metadata", () => {
  assert.strictEqual(
    isInterceptedDownload({ pendingUrl: "https://example.com/setup.exe" }),
    true
  );
  assert.strictEqual(isInterceptedDownload({ pendingUrl: "" }), false);
  assert.strictEqual(isInterceptedDownload(), false);
});

test("child lock countdown message uses readable seconds", () => {
  assert.strictEqual(
    getChildLockCountdownMessage(5),
    "Child Lock is active. Returning to safety in 5 seconds."
  );
  assert.strictEqual(
    getChildLockCountdownMessage(1),
    "Child Lock is active. Returning to safety in 1 second."
  );
});
