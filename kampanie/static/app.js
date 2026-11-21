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
document.querySelectorAll("form.add").forEach((f) =>
  f.addEventListener("submit", () => { const b = f.querySelector("button"); b.disabled = true; b.firstChild.textContent = "Wgrywam i analizuję "; }));
document.querySelectorAll("select[form=mf]").forEach((s) => s.addEventListener("change", () => s.form.requestSubmit()));
document.querySelectorAll("#mf").forEach((f) => f.addEventListener("submit", () =>  // a short address: empty filters stay out of it
  document.querySelectorAll("[form=mf]").forEach((x) => { if (!x.value) x.disabled = true; })));
addEventListener("pageshow", () => document.querySelectorAll("[form=mf]").forEach((x) => { x.disabled = false; }));  // back button
