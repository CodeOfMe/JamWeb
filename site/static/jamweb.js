/* JamWeb front-end helpers: KaTeX math + highlight.js code blocks.
   Loaded with defer, strict mode, no inline handlers. */
"use strict";

(function () {
  function renderMath() {
    if (typeof katex === "undefined") return;
    var nodes = document.querySelectorAll(".math[data-tex]");
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var tex = el.getAttribute("data-tex") || "";
      var display = el.getAttribute("data-display") === "1";
      try {
        katex.render(tex, el, {
          displayMode: display,
          throwOnError: false,
          strict: "ignore",
          trust: false,
          output: "htmlAndMathml"
        });
      } catch (err) {
        el.className += " math-error";
        el.textContent = tex;
        el.title = String(err && err.message ? err.message : err);
      }
    }
  }

  function highlight() {
    if (typeof hljs === "undefined") return;
    var blocks = document.querySelectorAll("pre code");
    for (var i = 0; i < blocks.length; i++) {
      try {
        hljs.highlightElement(blocks[i]);
      } catch (err) {
        /* leave the plain text in place */
      }
    }
  }

  function ready() {
    renderMath();
    highlight();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
