(function () {
  if (window === window.top) return;

  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || event.button !== 0) return;

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
  }, true);
})();
