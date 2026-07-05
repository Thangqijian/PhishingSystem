(function (root) {
  const PASSWORD_RECORD_VERSION = 1;
  const PASSWORD_ITERATIONS = 100000;
  const PASSWORD_ALGORITHM = "PBKDF2-SHA-256";

  function validateNewPassword(password, confirmation) {
    if (typeof password !== "string" || password.trim().length < 6) {
      return "Use at least 6 characters.";
    }

    if (password !== confirmation) {
      return "Passwords do not match.";
    }

    return "";
  }

  function isPasswordRecord(record) {
    return Boolean(
      record &&
      record.version === PASSWORD_RECORD_VERSION &&
      record.algorithm === PASSWORD_ALGORITHM &&
      Number.isInteger(record.iterations) &&
      record.iterations > 0 &&
      typeof record.salt === "string" &&
      record.salt.length > 0 &&
      typeof record.hash === "string" &&
      record.hash.length > 0
    );
  }

  function getCryptoApi() {
    const cryptoApi = root.crypto;
    if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
      throw new Error("Secure password storage is not available in this browser.");
    }
    return cryptoApi;
  }

  function bytesToBase64(bytes) {
    if (typeof root.btoa === "function") {
      let binary = "";
      bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
      });
      return root.btoa(binary);
    }

    return root.Buffer.from(bytes).toString("base64");
  }

  function base64ToBytes(value) {
    if (typeof root.atob === "function") {
      const binary = root.atob(value);
      return Uint8Array.from(binary, (character) => character.charCodeAt(0));
    }

    return Uint8Array.from(root.Buffer.from(value, "base64"));
  }

  async function derivePasswordHash(password, salt, iterations) {
    const cryptoApi = getCryptoApi();
    const encoder = new TextEncoder();
    const key = await cryptoApi.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await cryptoApi.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations,
      },
      key,
      256
    );

    return new Uint8Array(bits);
  }

  async function createPasswordRecord(password) {
    const cryptoApi = getCryptoApi();
    const salt = cryptoApi.getRandomValues(new Uint8Array(16));
    const hash = await derivePasswordHash(password, salt, PASSWORD_ITERATIONS);

    return {
      version: PASSWORD_RECORD_VERSION,
      algorithm: PASSWORD_ALGORITHM,
      iterations: PASSWORD_ITERATIONS,
      salt: bytesToBase64(salt),
      hash: bytesToBase64(hash),
    };
  }

  async function verifyPassword(password, record) {
    if (!isPasswordRecord(record) || typeof password !== "string") {
      return false;
    }

    try {
      const expected = base64ToBytes(record.hash);
      const actual = await derivePasswordHash(
        password,
        base64ToBytes(record.salt),
        record.iterations
      );

      if (actual.length !== expected.length) return false;

      let difference = 0;
      for (let index = 0; index < actual.length; index += 1) {
        difference |= actual[index] ^ expected[index];
      }
      return difference === 0;
    } catch (error) {
      return false;
    }
  }

  const childLock = {
    createPasswordRecord,
    isPasswordRecord,
    validateNewPassword,
    verifyPassword,
  };

  root.PhishShieldChildLock = childLock;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = childLock;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
