const assert = require("assert");

const {
  createDownloadAllowanceStore,
  normalizeDownloadUrl,
  shouldRememberBlockedHost,
} = require("./download-allowance.js");

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

test("download URLs are normalized without fragments", () => {
  assert.strictEqual(
    normalizeDownloadUrl("https://example.com/app.exe?build=1#download"),
    "https://example.com/app.exe?build=1"
  );
});

test("an allowance is consumed once by the exact URL", () => {
  let currentTime = 1000;
  const store = createDownloadAllowanceStore({
    ttlMs: 30000,
    now: () => currentTime,
  });

  store.allow("https://example.com/app.exe#button");

  assert.strictEqual(store.consume(["https://example.com/app.exe"]), true);
  assert.strictEqual(store.consume(["https://example.com/app.exe"]), false);
  assert.strictEqual(store.consume(["https://example.com/other.exe"]), false);
});

test("an allowance can match an original URL candidate", () => {
  const store = createDownloadAllowanceStore();
  store.allow("https://example.com/download?id=42");

  assert.strictEqual(
    store.consume([
      "https://cdn.example.com/final.exe",
      "https://example.com/download?id=42",
    ]),
    true
  );
});

test("expired allowances cannot be consumed", () => {
  let currentTime = 1000;
  const store = createDownloadAllowanceStore({
    ttlMs: 30000,
    now: () => currentTime,
  });

  store.allow("https://example.com/app.exe");
  currentTime = 31001;

  assert.strictEqual(store.consume(["https://example.com/app.exe"]), false);
});

test("download-only risk does not permanently block the whole host", () => {
  assert.strictEqual(
    shouldRememberBlockedHost({
      status: "phishing",
      download: { is_malicious: true },
      urlhausHit: false,
    }),
    false
  );
  assert.strictEqual(
    shouldRememberBlockedHost({
      status: "phishing",
      download: { is_malicious: false },
      urlhausHit: false,
    }),
    true
  );
  assert.strictEqual(
    shouldRememberBlockedHost({
      status: "phishing",
      download: { is_malicious: true },
      urlhausHit: true,
    }),
    true
  );
});
