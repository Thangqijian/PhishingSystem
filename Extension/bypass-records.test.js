const assert = require("assert");

const {
  findBypassRecord,
  getBypassHostname,
  removeHostnameEntries,
  upsertBypassRecord,
} = require("./bypass-records.js");

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

test("legacy bypass hostnames remain valid without inventing a score", () => {
  assert.deepStrictEqual(
    findBypassRecord(["example.com"], "www.example.com"),
    {
      hostname: "example.com",
      riskScore: null,
      bypassedAt: null,
    }
  );
});

test("structured bypass records preserve their saved risk score", () => {
  assert.deepStrictEqual(
    findBypassRecord(
      [{ hostname: "warning.test", riskScore: 68.4, bypassedAt: 1234 }],
      "warning.test"
    ),
    {
      hostname: "warning.test",
      riskScore: 68.4,
      bypassedAt: 1234,
    }
  );
});

test("saving a bypass replaces older entries for the same hostname", () => {
  const updated = upsertBypassRecord(
    [
      "warning.test",
      { hostname: "other.test", riskScore: 41, bypassedAt: 100 },
    ],
    {
      hostname: "www.warning.test",
      riskScore: 72,
      bypassedAt: 200,
    }
  );

  assert.deepStrictEqual(updated, [
    { hostname: "other.test", riskScore: 41, bypassedAt: 100 },
    { hostname: "warning.test", riskScore: 72, bypassedAt: 200 },
  ]);
});

test("dashboard labels support legacy and structured bypass entries", () => {
  assert.strictEqual(getBypassHostname("legacy.test"), "legacy.test");
  assert.strictEqual(
    getBypassHostname({ hostname: "saved.test", riskScore: 55 }),
    "saved.test"
  );
});

test("an explicit bypass removes the same hostname from blocking entries", () => {
  assert.deepStrictEqual(
    removeHostnameEntries(
      ["warning.test", "other.test"],
      "www.warning.test"
    ),
    ["other.test"]
  );
});
