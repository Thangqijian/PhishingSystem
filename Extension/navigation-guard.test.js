const assert = require("assert");

const {
  createInteraction,
  findUnexpectedInteraction,
  isUnexpectedCrossDomainTab,
} = require("./navigation-guard.js");

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

test("a non-link click opening another domain is unexpected", () => {
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://unknown-ad.test/landing",
      now: 1500,
    }),
    true
  );
});

test("a clicked link opening its intended destination is expected", () => {
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    intendedUrl: "https://stream-partner.test/title",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://stream-partner.test/title",
      now: 1500,
    }),
    false
  );
});

test("a disguised PropellerAds link is unexpected even when it matches the anchor", () => {
  const adUrl =
    "https://stake.ac/?c=KE2orCKI&offer=PropPopMal&utm_source=propellerads&utm_medium=cpc&utm_campaign=km_Propeller_Pop_Malaysia_mobile_pop&clickId=YUugWb4v5Z5wuwUWon2T6b";
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    intendedUrl: adUrl,
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: adUrl,
      now: 1500,
    }),
    true
  );
});

test("a new tab that differs from the clicked link is unexpected", () => {
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    intendedUrl: "https://movies.example/help",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://unknown-ad.test/landing",
      now: 1500,
    }),
    true
  );
});

test("a recent page click can identify an unexpected new tab without opener data", () => {
  const interactions = [
    createInteraction({
      sourceUrl: "https://movies.example/watch",
      occurredAt: 1000,
    }),
  ];

  assert.strictEqual(
    findUnexpectedInteraction({
      interactions,
      targetUrl: "https://unknown-ad.test/landing",
      now: 1500,
    }),
    interactions[0]
  );
});

test("a recent clicked link is not treated as unexpected without opener data", () => {
  const targetUrl = "https://stream-partner.test/title";
  const interactions = [
    createInteraction({
      sourceUrl: "https://movies.example/watch",
      intendedUrl: targetUrl,
      occurredAt: 1000,
    }),
  ];

  assert.strictEqual(
    findUnexpectedInteraction({
      interactions,
      targetUrl,
      now: 1500,
    }),
    null
  );
});

test("a Google result redirect URL is expected when it opens the embedded destination", () => {
  const targetUrl = "https://www.microsoft.com/en-my/download";
  const interaction = createInteraction({
    sourceUrl: "https://www.google.com/search?q=microsoft+download",
    intendedUrl:
      "https://www.google.com/url?sa=t&url=https%3A%2F%2Fwww.microsoft.com%2Fen-my%2Fdownload",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl,
      now: 1500,
    }),
    false
  );
});

test("a Google search result click without a readable anchor is expected", () => {
  const interaction = createInteraction({
    sourceUrl: "https://www.google.com/search?q=7zip+download",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://www.7-zip.org/",
      now: 1500,
    }),
    false
  );
});

test("a delayed popup redirect is still linked to the recent click", () => {
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://unknown-ad.test/landing",
      now: 6500,
    }),
    true
  );
});

test("same-site subdomain tabs are not blocked", () => {
  const interaction = createInteraction({
    sourceUrl: "https://watch.example.com/title",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://account.example.com/login",
      now: 1500,
    }),
    false
  );
});

test("expired click context does not block a later tab", () => {
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "https://unknown-ad.test/landing",
      now: 12000,
    }),
    false
  );
});

test("browser-internal placeholder URLs wait for a real destination", () => {
  const interaction = createInteraction({
    sourceUrl: "https://movies.example/watch",
    occurredAt: 1000,
  });

  assert.strictEqual(
    isUnexpectedCrossDomainTab({
      interaction,
      targetUrl: "about:blank",
      now: 1100,
    }),
    false
  );
});
