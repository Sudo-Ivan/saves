// SPDX-License-Identifier: 0BSD
// Progressive enhancement only: every page works without this file.
document.documentElement.classList.add("js");

document.querySelectorAll("[data-copy]").forEach(function (b) {
  if (!navigator.clipboard) return;
  b.hidden = false;
  b.addEventListener("click", function () {
    var t = document.querySelector(b.getAttribute("data-copy"));
    if (!t) return;
    navigator.clipboard.writeText(t.textContent.trim()).then(function () {
      var old = b.textContent;
      b.textContent = "Copied";
      setTimeout(function () { b.textContent = old; }, 1500);
    });
  });
});

document.querySelectorAll("[data-append-ip]").forEach(function (b) {
  var src = document.getElementById(b.getAttribute("data-append-ip"));
  var dst = document.getElementById(b.getAttribute("data-target"));
  if (!src || !dst) return;
  b.hidden = false;
  b.addEventListener("click", function () {
    var ip = src.textContent.trim();
    var lines = dst.value.split(/\r?\n/).map(function (l) { return l.trim(); });
    if (lines.indexOf(ip) === -1) {
      dst.value = dst.value.replace(/\s+$/, "") + (dst.value.trim() ? "\n" : "") + ip;
    }
    dst.focus();
  });
});
