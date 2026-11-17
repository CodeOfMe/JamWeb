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

  function initUpload() {
    var ta = document.querySelector('textarea[name="body"]');
    if (!ta) return;
    var url = ta.getAttribute("data-upload-url");
    var csrf = ta.getAttribute("data-csrf");
    if (!url || !csrf) return;

    function insert(text) {
      var start = ta.selectionStart || 0;
      var end = ta.selectionEnd || 0;
      var before = ta.value.slice(0, start);
      var after = ta.value.slice(end);
      if (before && !/\n$/.test(before)) text = "\n" + text;
      ta.value = before + text + after;
      var pos = (before + text).length;
      ta.selectionStart = ta.selectionEnd = pos;
      ta.focus();
    }

    function upload(blob, name) {
      var fd = new FormData();
      fd.append("csrf", csrf);
      fd.append("file", blob, name || "pasted.png");
      return fetch(url, { method: "POST", body: fd, credentials: "same-origin" })
        .then(function (r) {
          return r.json().then(function (j) {
            if (!r.ok) throw new Error(j && j.error ? j.error : ("HTTP " + r.status));
            return j;
          });
        })
        .then(function (j) {
          insert("![" + (name || "image") + "](" + j.url + ")\n");
        })
        .catch(function (e) {
          window.alert("Image upload failed: " + e.message);
        });
    }

    ta.addEventListener("paste", function (ev) {
      var items = ev.clipboardData ? ev.clipboardData.items : [];
      for (var i = 0; i < items.length; i++) {
        if (items[i].kind === "file" && items[i].type.indexOf("image/") === 0) {
          var f = items[i].getAsFile();
          if (f) { ev.preventDefault(); upload(f, f.name); return; }
        }
      }
    });

    ["dragover", "dragenter"].forEach(function (t) {
      ta.addEventListener(t, function (e) { e.preventDefault(); });
    });
    ta.addEventListener("drop", function (e) {
      if (!e.dataTransfer) return;
      var files = e.dataTransfer.files || [];
      for (var i = 0; i < files.length; i++) {
        if (files[i].type.indexOf("image/") === 0) {
          e.preventDefault();
          upload(files[i], files[i].name);
          return;
        }
      }
    });

    var btn = document.getElementById("jw-image-btn");
    if (btn) {
      var picker = document.createElement("input");
      picker.type = "file";
      picker.accept = "image/*";
      picker.style.display = "none";
      document.body.appendChild(picker);
      btn.addEventListener("click", function () { picker.click(); });
      picker.addEventListener("change", function () {
        if (picker.files && picker.files[0]) upload(picker.files[0], picker.files[0].name);
        picker.value = "";
      });
    }
  }

  function ready() {
    renderMath();
    highlight();
    initUpload();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ready);
  } else {
    ready();
  }
})();
