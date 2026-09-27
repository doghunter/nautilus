// Conticini - UI helpers (external file: CSP-compliant, no inline handlers)
(function () {
  "use strict";

  // confirmation before destructive form submits
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (form && form.hasAttribute && form.hasAttribute("data-confirm")) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        ev.preventDefault();
      }
    }
  }, true);

  // "paid" checkbox toggles the paid-date field visibility
  document.addEventListener("change", function (ev) {
    var el = ev.target;
    if (el && el.hasAttribute && el.hasAttribute("data-paid-toggle")) {
      var box = el.closest("form");
      var pd = box ? box.querySelector("[data-paid-date]") : null;
      if (pd) {
        pd.style.display = el.checked ? "" : "none";
      }
    }
  });
})();
