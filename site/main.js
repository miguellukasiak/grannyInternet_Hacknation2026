// grannyinternet.me and its jury page: case file, scroll reveals, counting numbers, the dots.
document.documentElement.classList.add("js");
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

function whenSeen(element, then, threshold = 0.25) {
  if (!("IntersectionObserver" in window)) return then();
  const watch = new IntersectionObserver(entries => {
    if (entries.some(e => e.isIntersecting)) { watch.disconnect(); then(); }
  }, { threshold });
  watch.observe(element);
}

// "~9 173%" -> its prefix, value, decimals and suffix, so a count can rewrite it in the same form
function parse(text) {
  const m = text.match(/^(\D*?)(\d[\d\s]*(?:,\d+)?)(\D*)$/);
  return m && { pre: m[1], value: parseFloat(m[2].replace(/\s/g, "").replace(",", ".")),
    decimals: (m[2].split(",")[1] || "").length, post: m[3] };
}

function show(el, n, v) {
  const [whole, part] = v.toFixed(n.decimals).split(".");
  el.textContent = n.pre + whole.replace(/\B(?=(\d{3})+$)/g, "\u00a0") + (part ? "," + part : "") + n.post;
}

function count(el, n, from = +el.dataset.count || 0, ms = el.closest(".bars") ? 900 : 1400) {
  if (still) return show(el, n, n.value);
  const start = performance.now(), to = n.value;
  const step = now => {
    const k = Math.min(1, (now - start) / ms);
    show(el, n, k < 1 ? from + (to - from) * (1 - (1 - k) ** 3) : to);
    if (k < 1 && n.value === to) requestAnimationFrame(step);  // a newer live figure starts its own count
  };
  requestAnimationFrame(step);
}

document.addEventListener("DOMContentLoaded", () => {
  const card = document.getElementById("case");
  whenSeen(card, () => card.classList.add("run"), 0.4);
  document.getElementById("replay").onclick = () => {
    card.classList.remove("run");
    void card.offsetWidth;  // restart the transitions
    requestAnimationFrame(() => card.classList.add("run"));
  };

  // endless animations run only while on screen
  if ("IntersectionObserver" in window) {
    const onScreen = new IntersectionObserver(es => es.forEach(e => e.target.classList.toggle("off", !e.isIntersecting)));
    for (const el of document.querySelectorAll(".ticker, .scene, .wip")) onScreen.observe(el);
  }

  for (const element of document.querySelectorAll(".reveal")) whenSeen(element, () => element.classList.add("seen"), 0.15);

  // the ticker loops by sliding half its width, so it needs a second, hidden copy of the words
  const set = document.querySelector(".ticker-set"), copy = set.cloneNode(true);
  copy.setAttribute("aria-hidden", "true");
  set.after(copy);

  // bars start at 50%, a coin toss; set from JS because the CSP forbids inline styles
  for (const [i, bar] of document.querySelectorAll(".bars li[data-v]").entries()) {
    bar.style.setProperty("--w", Math.max(0, (bar.dataset.v - 50) / 50));
    bar.querySelector("i").style.transitionDelay = `${(i % 8) * 90}ms`;
    bar.querySelector("b").dataset.count = "50";
  }

  // numbers count up when their group comes into view, one after another
  const numbers = new Map();
  for (const el of document.querySelectorAll("[data-count]")) {
    const n = parse(el.textContent);
    if (!n) continue;
    numbers.set(el, n);
    if (!still) show(el, n, +el.dataset.count || 0);
  }
  for (const group of new Set([...numbers.keys()].map(el => el.closest(".stat-grid, .scale, .bars, .big-fig, .gap-bars")))) {
    const step = group.matches(".bars") ? 90 : 650;
    whenSeen(group, () => [...numbers.keys()].filter(el => group.contains(el)).forEach((el, i) =>
      setTimeout(() => { el.dataset.done = ""; count(el, numbers.get(el)); }, i * step)), 0.3);
  }

  // the base's own numbers, live from the panel; without them the figures written in the page stay
  const live = async () => {
    try {
      const response = await fetch("https://panel.example.org/api/liczby", { signal: AbortSignal.timeout(5000) });
      if (!response.ok) return;
      const figures = await response.json();
      for (const el of document.querySelectorAll("[data-live]")) {
        const n = numbers.get(el), to = figures[el.dataset.live];
        if (!n || !Number.isFinite(to) || to === n.value) continue;
        const from = n.value;
        n.value = to;
        if ("done" in el.dataset) count(el, n, from);  // already counted: roll on from the old figure
      }
      const since = Date.parse(figures.since), at = new Date(figures.at);
      if (since && !isNaN(at)) {
        document.getElementById("numbers-note").textContent = `Stan bazy na żywo: ${at.toLocaleString("pl-PL",
          { day: "numeric", month: "long", hour: "2-digit", minute: "2-digit" })}.`;
      }
    } catch { /* panel unreachable: the page keeps its written figures */ }
  };
  live();
  setInterval(live, 300000);

  // 995 of our ad blocks checked; Quad9 and Cloudflare for Families knew 21
  const dots = document.getElementById("dots"), total = 995, known = new Set();
  if (!dots) return;
  let seed = 7;
  const next = () => (seed = (seed * 16807) % 2147483647) / 2147483647;  // fixed spread, same on every visit
  while (known.size < 21) known.add(Math.floor(next() * total));
  const cells = [];
  for (let i = 0; i < total; i++) {
    const cell = document.createElement("i");
    if (known.has(i)) cell.className = "known";
    if (!still) cell.style.transitionDelay = `${Math.floor(i / 35) * 28 + (known.has(i) ? 700 : 0)}ms`;
    cells.push(cell);
  }
  dots.append(...cells);
  whenSeen(dots, () => dots.classList.add("on"), 0.2);

  // a wave under the pointer: squares around it lift and settle, nearest first
  let last = -1;
  if (!still) dots.addEventListener("pointermove", e => {
    const at = cells.indexOf(e.target);
    if (at < 0 || at === last) return;
    last = at;
    const columns = getComputedStyle(dots).gridTemplateColumns.split(" ").length, reach = 6;
    const row = Math.floor(at / columns), column = at % columns;
    for (let r = Math.max(0, row - reach); r <= row + reach; r++)
      for (let c = Math.max(0, column - reach); c < Math.min(columns, column + reach + 1); c++) {
        const cell = cells[r * columns + c], d = Math.hypot(r - row, c - column);
        if (!cell || d > reach) continue;
        cell.animate([{ translate: "0 0" }, { translate: `0 ${-(1 - d / (reach + 1)) * 12}px`, offset: .35 }, { translate: "0 0" }],
          { duration: 650, delay: d * 45, easing: "ease-out", composite: "add" });
      }
  });
});
