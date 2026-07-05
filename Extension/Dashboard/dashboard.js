const BACKEND_URL = "http://localhost:5000/";
const THREAT_INTEL_STATUS_URL = "http://localhost:5000/threat-intel/status";
const THREAT_INTEL_UPDATE_URL = "http://localhost:5000/threat-intel/update";

const DEMO_LINKS = {
  safe: "https://www.example.com/",
  suspicious: "http://127.0.0.1:5000/demo/suspicious-login?verify=account&brand=paypal&redirect=http://example.test",
  malicious: "http://127.0.0.1:5000/demo/malicious-download.exe"
};

const DEFAULTS = {
  protectionEnabled: true,
  showSafeNotifications: true,
  rememberBypass: true,
  childLockEnabled: false,
  blockedList: [],
  bypassedList: [],
  scannedCount: 0,
  blockedCount: 0,
  downloadBlockedCount: 0
};

const PROTECTION_OFF_NOTICE_KEY = "protectionDisabledNoticeShown";
const CHILD_LOCK_STORAGE_KEYS = [
  "childLockEnabled",
  "childPasswordRecord",
  "childPassword",
];

export function bindDashboardEvents(shadowRoot, wrapper) {
  const root = wrapper;
  const dashboardCard = root.querySelector(".dashboard-card");
  const closeBtn = root.querySelector("#dashboard-close");
  const resetBtn = root.querySelector("#reset-btn");
  const protectionToggle = root.querySelector("#protection-toggle");
  const safeNotificationToggle = root.querySelector("#safe-notification-toggle");
  const rememberBypassToggle = root.querySelector("#remember-bypass");
  const childLockToggle = root.querySelector("#child-lock-toggle");
  const resetChildPasswordBtn = root.querySelector("#reset-child-password-btn");
  const clearCacheBtn = root.querySelector("#clear-cache-btn");
  const clearBypassBtn = root.querySelector("#clear-bypass-btn");
  const refreshStatusBtn = root.querySelector("#refresh-status-btn");
  const refreshIntelBtn = root.querySelector("#refresh-intel-btn");
  const updateUrlhausBtn = root.querySelector("#update-urlhaus-btn");
  const tabButtons = Array.from(root.querySelectorAll(".tab-btn"));
  const demoButtons = Array.from(root.querySelectorAll(".open-demo-btn"));

  dashboardCard?.classList.add("auth-checking");
  bindTabs(root, tabButtons);
  initializeDashboard(root, wrapper);
  checkBackendStatus(root);
  loadThreatIntel(root);

  closeBtn?.addEventListener("click", () => {
    closeDashboard(wrapper);
  });

  protectionToggle?.addEventListener("change", () => {
    const enabled = protectionToggle.checked;
    chrome.storage.local.set({ protectionEnabled: enabled }, () => {
      if (!enabled) {
        showProtectionOffNoticeOnce(root);
      }
    });
  });

  safeNotificationToggle?.addEventListener("change", () => {
    chrome.storage.local.set({ showSafeNotifications: safeNotificationToggle.checked });
  });

  rememberBypassToggle?.addEventListener("change", () => {
    chrome.storage.local.set({ rememberBypass: rememberBypassToggle.checked });
  });

  childLockToggle?.addEventListener("change", async () => {
    await handleChildLockToggle(root, childLockToggle);
  });

  resetChildPasswordBtn?.addEventListener("click", async () => {
    const changed = await showResetPasswordDialog(root);
    if (changed) {
      await updateChildLockStatus(root);
    }
  });

  clearCacheBtn?.addEventListener("click", () => {
    chrome.storage.local.set({ blockedList: [] }, () => {
      renderList(root, "#blocked-list-container", []);
    });
  });

  clearBypassBtn?.addEventListener("click", () => {
    chrome.storage.local.set({ bypassedList: [] }, () => {
      renderList(root, "#bypassed-list-container", []);
      setText(root, "#bypassed-count", "0");
    });
  });

  resetBtn?.addEventListener("click", () => {
    chrome.storage.local.set(
      {
        scannedCount: 0,
        blockedCount: 0,
        downloadBlockedCount: 0
      },
      () => {
        setText(root, "#scanned-count", "0");
        setText(root, "#blocked-count", "0");
        setText(root, "#download-blocked-count", "0");
      }
    );
  });

  refreshStatusBtn?.addEventListener("click", () => {
    checkBackendStatus(root);
    loadThreatIntel(root);
  });

  refreshIntelBtn?.addEventListener("click", () => {
    loadThreatIntel(root);
  });

  updateUrlhausBtn?.addEventListener("click", () => {
    updateThreatIntel(root, updateUrlhausBtn);
  });

  demoButtons.forEach((button) => {
    button.addEventListener("click", () => {
      openDemoLink(button.dataset.demo);
    });
  });
}

async function initializeDashboard(root, wrapper) {
  await loadDashboard(root);

  const data = await storageGet(CHILD_LOCK_STORAGE_KEYS);
  const dashboardCard = root.querySelector(".dashboard-card");
  if (!data.childLockEnabled) {
    dashboardCard?.classList.remove("auth-checking");
    return;
  }

  const unlocked = hasStoredPassword(data)
    ? await showVerifyPasswordDialog(root, {
      title: "Unlock settings",
      message: "Enter the parent password to open PhishShield settings.",
      confirmText: "Unlock",
    })
    : await showSetPasswordDialog(root, {
      title: "Finish Child Lock setup",
      message: "Create a parent password before using protected settings.",
      confirmText: "Save password",
      storageValues: { childLockEnabled: true },
    });

  dashboardCard?.classList.remove("auth-checking");
  if (!unlocked) {
    closeDashboard(wrapper);
  }
}

function closeDashboard(wrapper) {
  if (wrapper?.id === "dashboard-wrapper") {
    wrapper.remove();
    return;
  }
  window.close();
}

async function handleChildLockToggle(root, toggle) {
  const requestedState = toggle.checked;
  const previousState = !requestedState;
  toggle.disabled = true;

  try {
    const data = await storageGet(CHILD_LOCK_STORAGE_KEYS);
    let confirmed;

    if (requestedState && !hasStoredPassword(data)) {
      confirmed = await showSetPasswordDialog(root, {
        title: "Set parent password",
        message: "Create a password before enabling Child Lock.",
        confirmText: "Enable Child Lock",
        storageValues: { childLockEnabled: true },
      });
    } else {
      confirmed = await showVerifyPasswordDialog(root, {
        title: requestedState ? "Enable Child Lock" : "Disable Child Lock",
        message: requestedState
          ? "Enter the parent password to enable Child Lock."
          : "Enter the parent password to disable Child Lock.",
        confirmText: requestedState ? "Enable" : "Disable",
        onVerified: () => storageSet({ childLockEnabled: requestedState }),
      });
    }

    if (!confirmed) {
      toggle.checked = previousState;
      return;
    }

    toggle.checked = requestedState;
    await updateChildLockStatus(root);
  } catch (error) {
    console.error("Child Lock update failed:", error);
    toggle.checked = previousState;
  } finally {
    toggle.disabled = false;
  }
}

async function showSetPasswordDialog(root, {
  title,
  message,
  confirmText,
  storageValues = {},
}) {
  return showChildLockDialog(root, {
    title,
    message,
    confirmText,
    showNewPassword: true,
    showConfirmation: true,
    onSubmit: async ({ newPassword, confirmation }) => {
      const childLock = getChildLockApi();
      const validationError = childLock.validateNewPassword(
        newPassword,
        confirmation
      );
      if (validationError) return validationError;

      await saveChildPassword(newPassword, storageValues);
      return "";
    },
  });
}

async function showVerifyPasswordDialog(root, {
  title,
  message,
  confirmText,
  onVerified,
}) {
  return showChildLockDialog(root, {
    title,
    message,
    confirmText,
    showCurrentPassword: true,
    onSubmit: async ({ currentPassword }) => {
      const data = await storageGet(CHILD_LOCK_STORAGE_KEYS);
      const verified = await verifyStoredPassword(currentPassword, data);
      if (!verified) return "Incorrect password.";

      if (onVerified) {
        await onVerified();
      }
      return "";
    },
  });
}

async function showResetPasswordDialog(root) {
  const data = await storageGet(CHILD_LOCK_STORAGE_KEYS);
  if (!hasStoredPassword(data)) return false;

  return showChildLockDialog(root, {
    title: "Reset parent password",
    message: "Confirm the current password, then choose a new one.",
    confirmText: "Update password",
    showCurrentPassword: true,
    showNewPassword: true,
    showConfirmation: true,
    onSubmit: async ({ currentPassword, newPassword, confirmation }) => {
      const currentData = await storageGet(CHILD_LOCK_STORAGE_KEYS);
      const verified = await verifyStoredPassword(currentPassword, currentData);
      if (!verified) return "Current password is incorrect.";

      const validationError = getChildLockApi().validateNewPassword(
        newPassword,
        confirmation
      );
      if (validationError) return validationError;

      await saveChildPassword(newPassword);
      return "";
    },
  });
}

function showChildLockDialog(root, {
  title,
  message,
  confirmText,
  showCurrentPassword = false,
  showNewPassword = false,
  showConfirmation = false,
  onSubmit,
}) {
  const dialog = root.querySelector("#child-lock-dialog");
  const form = root.querySelector("#child-lock-form");
  const cancelButton = root.querySelector("#child-lock-dialog-cancel");
  const submitButton = root.querySelector("#child-lock-dialog-submit");
  const errorBox = root.querySelector("#child-lock-dialog-error");
  const currentField = root.querySelector("#child-lock-current-field");
  const newField = root.querySelector("#child-lock-new-field");
  const confirmField = root.querySelector("#child-lock-confirm-field");
  const currentInput = root.querySelector("#child-lock-current-password");
  const newInput = root.querySelector("#child-lock-new-password");
  const confirmInput = root.querySelector("#child-lock-confirm-password");

  if (!dialog || !form || dialog.dataset.open === "true") {
    return Promise.resolve(false);
  }

  root.querySelector("#child-lock-dialog-title").textContent = title;
  root.querySelector("#child-lock-dialog-message").textContent = message;
  currentField.hidden = !showCurrentPassword;
  newField.hidden = !showNewPassword;
  confirmField.hidden = !showConfirmation;
  currentInput.value = "";
  newInput.value = "";
  confirmInput.value = "";
  errorBox.textContent = "";
  submitButton.textContent = confirmText;
  submitButton.disabled = false;
  cancelButton.disabled = false;
  dialog.hidden = false;
  dialog.setAttribute("aria-hidden", "false");
  dialog.dataset.open = "true";

  const firstInput = showCurrentPassword ? currentInput : newInput;
  setTimeout(() => firstInput?.focus(), 0);

  return new Promise((resolve) => {
    const finish = (result) => {
      dialog.hidden = true;
      dialog.setAttribute("aria-hidden", "true");
      dialog.dataset.open = "false";
      form.removeEventListener("submit", handleSubmit);
      cancelButton.removeEventListener("click", handleCancel);
      dialog.removeEventListener("keydown", handleKeyDown);
      resolve(result);
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
        const error = await onSubmit({
          currentPassword: currentInput.value,
          newPassword: newInput.value,
          confirmation: confirmInput.value,
        });

        if (error) {
          errorBox.textContent = error;
          submitButton.disabled = false;
          cancelButton.disabled = false;
          firstInput?.focus();
          return;
        }

        finish(true);
      } catch (error) {
        errorBox.textContent = error.message || "The password could not be saved.";
        submitButton.disabled = false;
        cancelButton.disabled = false;
      }
    };

    form.addEventListener("submit", handleSubmit);
    cancelButton.addEventListener("click", handleCancel);
    dialog.addEventListener("keydown", handleKeyDown);
  });
}

function getChildLockApi() {
  const childLock = globalThis.PhishShieldChildLock;
  if (!childLock) {
    throw new Error("Child Lock security helper is unavailable.");
  }
  return childLock;
}

function hasStoredPassword(data) {
  return getChildLockApi().isPasswordRecord(data?.childPasswordRecord) ||
    (typeof data?.childPassword === "string" && data.childPassword.length > 0);
}

async function verifyStoredPassword(password, data) {
  const childLock = getChildLockApi();

  if (childLock.isPasswordRecord(data?.childPasswordRecord)) {
    return childLock.verifyPassword(password, data.childPasswordRecord);
  }

  if (typeof data?.childPassword !== "string" || password !== data.childPassword) {
    return false;
  }

  await saveChildPassword(password);
  return true;
}

async function saveChildPassword(password, extraValues = {}) {
  const record = await getChildLockApi().createPasswordRecord(password);
  await storageSet({
    ...extraValues,
    childPasswordRecord: record,
  });
  await storageRemove("childPassword");
}

async function updateChildLockStatus(root, storedData) {
  const data = storedData || await storageGet(CHILD_LOCK_STORAGE_KEYS);
  const status = root.querySelector("#child-lock-password-status");
  const resetButton = root.querySelector("#reset-child-password-btn");
  const hasPassword = hasStoredPassword(data);

  if (status) {
    status.textContent = hasPassword
      ? "Password is set. The current password is required to change it."
      : "Set when Child Lock is enabled for the first time.";
  }
  if (resetButton) {
    resetButton.disabled = !hasPassword;
  }
}

function storageGet(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, resolve);
  });
}

function storageSet(values) {
  return new Promise((resolve) => {
    chrome.storage.local.set(values, resolve);
  });
}

function storageRemove(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.remove(keys, resolve);
  });
}

function showProtectionOffNoticeOnce(root) {
  chrome.storage.local.get([PROTECTION_OFF_NOTICE_KEY], (data) => {
    if (data[PROTECTION_OFF_NOTICE_KEY]) return;

    chrome.storage.local.set({ [PROTECTION_OFF_NOTICE_KEY]: true });
    showProtectionOffNotice(root);
  });
}

function showProtectionOffNotice(root) {
  const toast = root.querySelector("#protection-off-toast");
  if (!toast) return;

  toast.classList.add("show");
  clearTimeout(toast.__hideTimer);
  toast.__hideTimer = setTimeout(() => {
    toast.classList.remove("show");
  }, 6500);
}

function bindTabs(root, tabButtons) {
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const tab = button.dataset.tab;

      tabButtons.forEach((item) => {
        item.classList.toggle("active", item === button);
      });

      root.querySelectorAll(".tab-panel").forEach((panel) => {
        panel.classList.toggle("active", panel.dataset.panel === tab);
      });
    });
  });
}

async function loadDashboard(root) {
  const keys = [...new Set([...Object.keys(DEFAULTS), ...CHILD_LOCK_STORAGE_KEYS])];
  const data = await storageGet(keys);
  const settings = { ...DEFAULTS, ...data };
  const blockedList = Array.isArray(settings.blockedList) ? settings.blockedList : [];
  const bypassedList = Array.isArray(settings.bypassedList) ? settings.bypassedList : [];

  setText(root, "#scanned-count", settings.scannedCount || 0);
  setText(root, "#blocked-count", settings.blockedCount || 0);
  setText(root, "#download-blocked-count", settings.downloadBlockedCount || 0);
  setText(root, "#bypassed-count", bypassedList.length);
  setChecked(root, "#protection-toggle", settings.protectionEnabled ?? true);
  setChecked(root, "#safe-notification-toggle", settings.showSafeNotifications ?? true);
  setChecked(root, "#remember-bypass", settings.rememberBypass ?? true);
  setChecked(root, "#child-lock-toggle", settings.childLockEnabled ?? false);

  renderList(root, "#blocked-list-container", blockedList);
  renderList(root, "#bypassed-list-container", bypassedList);
  await updateChildLockStatus(root, settings);
}

function renderList(root, selector, list) {
  const container = root.querySelector(selector);
  if (!container) return;

  container.innerHTML = "";

  if (!list || list.length === 0) {
    container.textContent = selector.includes("bypassed")
      ? "No allowed sites yet."
      : "No blocked sites yet.";
    return;
  }

  list.slice(-12).reverse().forEach((site) => {
    const item = document.createElement("div");
    item.className = "list-item";
    const getBypassHostname =
      globalThis.PhishShieldBypassRecords?.getBypassHostname;
    item.textContent = selector.includes("bypassed") && getBypassHostname
      ? getBypassHostname(site)
      : String(site);
    container.appendChild(item);
  });
}

async function checkBackendStatus(root) {
  const status = root.querySelector("#backend-status");
  const headline = root.querySelector("#protection-headline");
  const copy = root.querySelector("#protection-copy");
  if (!status) return;

  status.classList.remove("online", "offline");
  status.textContent = "Checking backend";

  try {
    const response = await fetch(BACKEND_URL, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    status.classList.add("online");
    status.textContent = data.model
      ? `Backend online: ${data.model}`
      : "Backend online";
    setText(root, "#protection-headline", "Browser protection is active");
    if (copy) {
      copy.textContent = "Backend analysis, heuristics, download checks, and URLHaus intelligence are available for scanning.";
    }
  } catch (error) {
    status.classList.add("offline");
    status.textContent = "Backend offline";
    if (headline) {
      headline.textContent = "Backend is offline";
    }
    if (copy) {
      copy.textContent = "Start the Flask backend before demoing live scan results.";
    }
  }
}

async function loadThreatIntel(root) {
  setNotice(root, "Checking threat intelligence status...", "neutral");

  try {
    const response = await fetch(THREAT_INTEL_STATUS_URL, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const status = await response.json();
    renderThreatIntel(root, status);
  } catch (error) {
    renderThreatIntel(root, null);
    setNotice(root, "Threat intelligence status is unavailable while the backend is offline.", "error");
  }
}

async function updateThreatIntel(root, button) {
  if (button) {
    button.disabled = true;
    button.textContent = "Updating...";
  }
  setNotice(root, "Requesting URLHaus CSV refresh...", "neutral");

  try {
    const response = await fetch(THREAT_INTEL_UPDATE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const payload = await response.json();

    renderThreatIntel(root, payload.urlhaus || null);
    setNotice(root, payload.message || "URLHaus update completed.", payload.ok ? "success" : "error");
  } catch (error) {
    renderThreatIntel(root, null);
    setNotice(root, "URLHaus update failed because the backend could not be reached.", "error");
  }
}

function renderThreatIntel(root, status) {
  if (!status) {
    setUrlhausUpdateButtonState(root, "offline");
    setText(root, "#overview-urlhaus-count", "-- URLs loaded");
    setText(root, "#overview-urlhaus-updated", "Backend offline");
    setText(root, "#intel-url-count", "--");
    setText(root, "#intel-domain-count", "--");
    setText(root, "#intel-loaded-at", "--");
    setText(root, "#intel-update-mode", "--");
    setText(root, "#intel-source-file", "--");
    return;
  }

  const urlCount = Number(status.loaded_urls || 0);
  const domainCount = Number(status.loaded_domains || 0);
  const loadedAt = formatDate(status.last_loaded_at || status.file_modified_at);
  const updateMode = status.update_configured
    ? (status.auto_update_enabled ? "Auto enabled" : "Manual ready")
    : "Needs API key";

  setUrlhausUpdateButtonState(root, status.update_configured ? "ready" : "needs-key");
  setText(root, "#overview-urlhaus-count", `${urlCount.toLocaleString()} URLs loaded`);
  setText(root, "#overview-urlhaus-updated", loadedAt ? `Updated ${loadedAt}` : "No update timestamp");
  setText(root, "#intel-url-count", urlCount.toLocaleString());
  setText(root, "#intel-domain-count", domainCount.toLocaleString());
  setText(root, "#intel-loaded-at", loadedAt || "--");
  setText(root, "#intel-update-mode", updateMode);
  setText(root, "#intel-source-file", status.source_file || "--");

  if (status.last_error) {
    setNotice(root, status.last_error, "error");
  } else if (!status.update_configured) {
    setNotice(root, "Local URLHaus data is loaded. To refresh from the official feed, set URLHAUS_AUTH_KEY or URLHAUS_CSV_URL before starting the backend.", "neutral");
  } else {
    setNotice(root, "Threat intelligence is loaded and ready for scanning.", "success");
  }
}

function setUrlhausUpdateButtonState(root, state) {
  const button = root.querySelector("#update-urlhaus-btn");
  if (!button) return;

  if (state === "ready") {
    button.disabled = false;
    button.textContent = "Update URLHaus now";
    button.title = "Download the latest URLHaus CSV into the local backend data file.";
    return;
  }

  button.disabled = true;
  button.textContent = state === "offline" ? "Backend offline" : "Needs URLHaus key";
  button.title = state === "offline"
    ? "Start the backend, then check status again."
    : "Set URLHAUS_AUTH_KEY or URLHAUS_CSV_URL before starting the backend.";
}

function setNotice(root, message, tone = "neutral") {
  const notice = root.querySelector("#intel-message");
  if (!notice) return;

  notice.className = `notice ${tone}`;
  notice.textContent = message;
}

function formatDate(value) {
  if (!value) return "";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";

  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function openDemoLink(key) {
  const url = DEMO_LINKS[key];
  if (!url) return;

  if (typeof chrome !== "undefined" && chrome.tabs?.create) {
    chrome.tabs.create({ url });
    return;
  }

  window.open(url, "_blank", "noopener,noreferrer");
}

function setText(root, selector, value) {
  const element = root.querySelector(selector);
  if (element) {
    element.textContent = value;
  }
}

function setChecked(root, selector, checked) {
  const element = root.querySelector(selector);
  if (element) {
    element.checked = Boolean(checked);
  }
}
