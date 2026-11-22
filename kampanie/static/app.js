// Small comforts only: the pages work without JavaScript.
document.querySelectorAll("[data-drop]").forEach((drop) => {
  const out = drop.querySelector("[data-files]");
  const show = () => {
    const files = [...drop.querySelectorAll("input[type=file]")].flatMap((i) => [...i.files]);
    if (!files.length) return;
    const folders = new Set(files.map((f) => (f.webkitRelativePath || "").split("/")[0]).filter(Boolean));
    const mb = files.reduce((s, f) => s + f.size, 0) / 1e6;
    out.textContent = `${files.length} ${files.length === 1 ? "plik" : "pliki"}${folders.size ? ` z folderu ${[...folders][0]}` : ""}, `
      + `${mb.toLocaleString("pl-PL", { maximumFractionDigits: 1 })} MB`;
    out.classList.add("on");
  };
  drop.querySelectorAll("input[type=file]").forEach((i) => i.addEventListener("change", show));
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, () => drop.classList.add("over")));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, () => drop.classList.remove("over")));
});
document.querySelectorAll("form[data-confirm]").forEach((f) =>
  f.addEventListener("submit", (e) => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));
// sending files: a window with how much has gone, then that the server is reading them
{  // a block: an error page written into this window runs this file again, a top-level const would clash
const mb = (n) => (n / 1e6).toLocaleString("pl-PL", { maximumFractionDigits: 1 });
document.querySelectorAll("form.add").forEach((f) => f.addEventListener("submit", (ev) => {
  const b = f.querySelector("button"), label = b.firstChild.textContent;
  b.disabled = true; b.firstChild.textContent = "Wgrywam i analizuję ";
  if (!window.HTMLDialogElement) return;  // an old browser sends the form the plain way
  ev.preventDefault();
  const d = document.createElement("dialog");
  d.className = "upload";
  d.innerHTML = '<h2>Wysyłam materiał</h2><progress max="100" value="0"></progress><p role="status" aria-live="polite">Zaczynam wysyłanie</p>';
  document.body.append(d);
  d.addEventListener("cancel", (x) => x.preventDefault());  // Esc would hide it while the upload goes on
  d.showModal();
  const [head, bar, msg] = d.children;
  const x = new XMLHttpRequest();
  x.upload.onprogress = (p) => {
    if (!p.lengthComputable) return;
    const pct = Math.round(p.loaded / p.total * 100);
    bar.value = pct;
    msg.textContent = `Wysłano ${mb(p.loaded)} z ${mb(p.total)} MB (${pct}%)`;
  };
  x.upload.onload = () => {
    head.textContent = "Wysłane, analizuję";
    bar.removeAttribute("value");  // no value: the bar moves without a percent
    msg.textContent = "Odczytujemy pliki i sprawdzamy stronę. Zwykle kilka sekund, przy adresie strony do pół minuty.";
  };
  x.onload = () => {
    const to = new URL(x.responseURL);
    if (x.status >= 300 || !(to.pathname.startsWith("/wynik/") || to.pathname === "/")) {
      document.open(); document.write(x.responseText); document.close();  // an error page from the server
    } else if (to.pathname === "/" && location.pathname === "/") {
      location.hash = "kampanie"; location.reload();  // a set of materials: the page shows how far it got
    } else location.href = to.pathname === "/" ? "/#kampanie" : to.href;
  };
  x.onerror = () => {
    head.textContent = "Nie udało się wysłać";
    bar.remove();
    msg.textContent = "Połączenie przerwało się. Pliki nie zostały zapisane, spróbuj jeszcze raz.";
    const close = Object.assign(document.createElement("button"), { className: "btn btn-ink btn-sm", textContent: "Zamknij" });
    close.onclick = () => { d.remove(); b.disabled = false; b.firstChild.textContent = label; };
    d.append(close);
    close.focus();
  };
  x.open("POST", f.action);
  x.send(new FormData(f));
}));
}
addEventListener("pageshow", () => document.querySelectorAll("dialog.upload").forEach((d) => d.remove()));  // back button
document.querySelectorAll("select[form=mf]").forEach((s) => s.addEventListener("change", () => s.form.requestSubmit()));
document.querySelectorAll("#mf").forEach((f) => f.addEventListener("submit", () =>  // a short address: empty filters stay out of it
  document.querySelectorAll("[form=mf]").forEach((x) => { if (!x.value) x.disabled = true; })));
addEventListener("pageshow", () => document.querySelectorAll("[form=mf]").forEach((x) => { x.disabled = false; }));  // back button
if ("wait" in document.documentElement.dataset) {  // one reload when the grouping ends, not one every 3 s mid-reading
  const ask = () => fetch("/stan", { cache: "no-store" }).then((r) => r.text())
    .then((busy) => (busy === "0" ? location.reload() : setTimeout(ask, 3000)), () => setTimeout(ask, 10000));
  setTimeout(ask, 3000);
}
