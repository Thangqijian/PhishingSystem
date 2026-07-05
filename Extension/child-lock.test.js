const assert = require("assert");

const {
  createPasswordRecord,
  isPasswordRecord,
  validateNewPassword,
  verifyPassword,
} = require("./child-lock.js");

const tests = [];

function test(name, fn) {
  tests.push({ name, fn });
}

test("new passwords require at least six characters", () => {
  assert.strictEqual(
    validateNewPassword("12345", "12345"),
    "Use at least 6 characters."
  );
});

test("new password confirmation must match", () => {
  assert.strictEqual(
    validateNewPassword("parent1", "parent2"),
    "Passwords do not match."
  );
  assert.strictEqual(validateNewPassword("parent1", "parent1"), "");
});

test("password records use unique salts and verify without storing plaintext", async () => {
  const first = await createPasswordRecord("parent123");
  const second = await createPasswordRecord("parent123");

  assert.strictEqual(isPasswordRecord(first), true);
  assert.notStrictEqual(first.salt, second.salt);
  assert.strictEqual(JSON.stringify(first).includes("parent123"), false);
  assert.strictEqual(await verifyPassword("parent123", first), true);
  assert.strictEqual(await verifyPassword("wrong-password", first), false);
});

test("malformed password records are rejected", async () => {
  assert.strictEqual(isPasswordRecord(null), false);
  assert.strictEqual(isPasswordRecord({ salt: "abc" }), false);
  assert.strictEqual(await verifyPassword("parent123", null), false);
});

(async () => {
  for (const { name, fn } of tests) {
    try {
      await fn();
      console.log(`PASS ${name}`);
    } catch (error) {
      console.error(`FAIL ${name}`);
      console.error(error.message);
      process.exitCode = 1;
    }
  }
})();
