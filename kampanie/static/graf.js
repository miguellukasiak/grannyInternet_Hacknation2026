// The expandable graph: campaigns first; a click loads a campaign's materials or what a material shares with others.
// Without JavaScript the page shows the static graph in <noscript>.
const box = document.querySelector(".g-live");
if (box) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = box.querySelector("svg"), info = box.querySelector(".g-info");
  const nodes = new Map(), edges = new Map();
  const gE = mk("g"), gN = mk("g");
  svg.append(gE, gN);
  let view = { x: -500, y: -350, w: 1000, h: 700 }, alpha = 0, fitted = false, focus = null;  // the node just opened: the view zooms to it once the layout settles

  function mk(tag, attrs = {}, text) {
    const x = document.createElementNS(NS, tag);
    for (const k in attrs) x.setAttribute(k, attrs[k]);
    if (text != null) x.textContent = text;
    return x;
  }
  const get = (q) => fetch("/graf.json" + q).then((r) => r.json());
  const cut = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  function add(id, kind, data, near, owner) {
    if (nodes.has(id)) return nodes.get(id);
    const r = kind === "hub" ? 12 + 5 * Math.sqrt(data.n) : kind === "mat" ? 9 : 6;
    const a = Math.random() * 2 * Math.PI, d = near ? near.r + 30 + Math.random() * 30 : 40 + 400 * Math.sqrt(Math.random());
    const n = { id, kind, data, r, owner, open: false, vx: 0, vy: 0,
                x: (near ? near.x : 0) + d * Math.cos(a), y: (near ? near.y : 0) + d * Math.sin(a) };
    n.g = mk("g", { class: `g-n ${kind} ${data.cls || ""}`, tabindex: 0, role: "button" });
    const label = kind === "hub" ? `${data.id} · ${data.label} · ${data.n} mat.` : kind === "mat" ? data.label : `${data.kind}: ${data.name}`;
    n.g.append(mk("title", {}, label));
    n.g.append(kind === "trait" ? mk("rect", { class: "g-s", x: -r, y: -r, width: 2 * r, height: 2 * r })
                                : mk("circle", { class: "g-s", r }));
    if (kind === "hub") n.g.append(mk("text", { class: "g-in", y: 4 }, data.id));
    n.g.append(mk("text", { class: "g-lb", x: r + 5, y: 4 }, cut(kind === "hub" ? (data.label === "bez wspólnego motywu" ? "" : data.label) : kind === "mat" ? data.label : data.name, 32)));
    n.g.addEventListener("click", () => toggle(n));
    n.g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggle(n); } });
    gN.append(n.g);
    const lb = n.g.querySelector(".g-lb");  // the label takes room too: nodes are kept apart as boxes, label included
    n.lw = (lb.textContent ? lb.getComputedTextLength() || 7 * lb.textContent.length : 0) + 5;
    nodes.set(id, n);
    return n;
  }

  function link(a, b, kind, s = 0.5, why = []) {
    if (!a || !b || a === b) return;
    const key = [a.id, b.id].sort().join("|");
    if (edges.has(key)) return;
    const el = mk("line", { class: `g-e ${kind}`, "stroke-width": (1 + 4 * s).toFixed(1) });
    if (why.length) el.append(mk("title", {}, why.join("\n")));
    gE.append(el);
    edges.set(key, { a, b, kind, el });
  }

  function remove(n) {
    for (const m of [...nodes.values()]) if (m.owner === n) remove(m);
    for (const [key, x] of edges) if (x.a === n || x.b === n) { x.el.remove(); edges.delete(key); }
    n.g.remove();
    nodes.delete(n.id);
  }

  function collapse(n) {
    for (const m of [...nodes.values()]) if (m.owner === n) remove(m);
    n.open = false;
    n.g.classList.remove("open");
  }

  async function toggle(n) {
    show(n);
    if (n.kind === "trait") return;
    if (n.open) { collapse(n); return kick(); }
    n.open = true;
    focus = n; fitted = false;
    n.g.classList.add("open");
    try {
      if (n.kind === "hub") {
        const d = await get("?c=" + encodeURIComponent(n.data.id));
        for (const m of d.members || []) link(n, add("m:" + m.id, "mat", m, n, n), "in");
        for (const l of d.links || []) link(nodes.get("m:" + l.a), nodes.get("m:" + l.b), "pair", l.s, l.why);
      } else {
        const d = await get("?m=" + encodeURIComponent(n.data.id));
        n.data = { ...n.data, ...d };
        for (const t of d.traits || []) {
          const tn = add("t:" + t.id, "trait", t, n, n);
          link(n, tn, "trait");
          for (const o of t.others) {
            const on = add("m:" + o.id, "mat", o, tn, n);
            link(tn, on, "trait");
            link(on, nodes.get("c:" + o.campaign), "in");  // which campaign the other one belongs to, if it is drawn
          }
        }
        show(n);
      }
    } catch (err) {
      info.textContent = "Nie udało się wczytać: " + err;
    }
    kick();
  }

  function show(n) {
    const d = n.data, out = [];
    const p = (text, tag = "p") => { const x = document.createElement(tag); x.textContent = text; out.push(x); return x; };
    const a = (text, href) => { const x = document.createElement("a"); x.className = "g-go"; x.textContent = text; x.href = href; out.push(x); };
    if (n.kind === "hub") {
      p(`${d.id} · ${d.label}`, "h3");
      a("Otwórz kartę kampanii →", d.href);  // first, so it is in sight without scrolling
      p(`${d.n} materiałów · temat: ${d.topic} · rodzina ${d.family}`);
    } else if (n.kind === "mat") {
      p(d.label, "h3");
      a("Otwórz kartę materiału →", "/m/" + encodeURIComponent(d.id));
      p(`Kampania ${d.campaign || "—"}`);
      for (const t of d.traits || []) p(`${t.kind}: ${t.name} · także w ${t.others.length + t.more} innych`);
      if (d.traits && !d.traits.length) p("Nie dzieli z innymi żadnego identyfikatora, osoby, marki, domeny ani serwera.");
    } else {
      p(`${d.kind}: ${d.name}`, "h3");
      p(`Wspólne dla ${d.others.length + d.more + 1} materiałów${d.more ? `, pokazujemy ${d.others.length + 1}` : ""}.`
        + (d.kind === "hosting" ? " Tylko informacja: jedna firma hostuje setki niezwiązanych stron." : ""));
    }
    info.replaceChildren(...out);
  }

  function step() {
    const list = [...nodes.values()];
    for (let i = 0; i < list.length; i++) {  // repulsion, and no overlap
      const a = list[i];
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j];
        let dx = b.x - a.x, dy = b.y - a.y;
        const d = Math.hypot(dx, dy) || 1, d2 = Math.max(d * d, (a.r + b.r) ** 2);  // two nodes born on top of each other flung one far away
        let f = (1800 * alpha * (a.r + b.r)) / 18 / d2;
        dx /= d; dy /= d;
        a.vx -= dx * f; a.vy -= dy * f; b.vx += dx * f; b.vy += dy * f;
      }
    }
    apart(list);
    for (const { a, b, kind } of edges.values()) {  // springs
      const want = (kind === "soft" ? 160 : kind === "trait" ? 70 : 90) + a.r + b.r;
      const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1, f = ((d - want) / d) * 0.06 * alpha;
      a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
    }
    for (const n of list) {
      n.vx -= n.x * 0.02 * alpha; n.vy -= n.y * 0.02 * alpha;
      n.x += n.vx; n.y += n.vy; n.vx *= 0.55; n.vy *= 0.55;
    }
  }

  function apart(list) {  // boxes of node and label must not overlap: push along the shorter overlap
    const box = (n) => [n.x - n.r - 6, n.x + n.r + n.lw + 6, n.y - Math.max(n.r, 9) - 5, n.y + Math.max(n.r, 9) + 5];
    for (let i = 0; i < list.length; i++) {
      const a = list[i], A = box(a);
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j], B = box(b);
        const ox = Math.min(A[1], B[1]) - Math.max(A[0], B[0]), oy = Math.min(A[3], B[3]) - Math.max(A[2], B[2]);
        if (ox <= 0 || oy <= 0) continue;
        if (ox < oy) { const s = (a.x < b.x ? -1 : 1) * ox / 2; a.x += s; b.x -= s; }
        else { const s = (a.y < b.y ? -1 : 1) * oy / 2; a.y += s; b.y -= s; }
      }
    }
  }

  function draw() {
    for (const n of nodes.values()) n.g.setAttribute("transform", `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
    for (const { a, b, el } of edges.values()) {
      el.setAttribute("x1", a.x.toFixed(1)); el.setAttribute("y1", a.y.toFixed(1));
      el.setAttribute("x2", b.x.toFixed(1)); el.setAttribute("y2", b.y.toFixed(1));
    }
  }

  function kick() {  // the layout at once, not animated: a background tab gets 2 frames a second and never settled
    for (alpha = 0.7; alpha > 0.01; alpha *= 0.96) for (let i = 0; i < 3; i++) step();
    for (let i = 0; i < 40; i++) apart([...nodes.values()]);  // the springs left some overlap: settle it last
    draw();
    if (!fitted) { fitted = true; fit(); }
  }

  function setView() { svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`); }

  function fit() {
    const all = focus && nodes.has(focus.id) ? [focus, ...[...nodes.values()].filter((m) => m.owner === focus)] : [...nodes.values()];
    if (!all.length) return;
    const pad = 60, xs = all.map((n) => n.x), ys = all.map((n) => n.y);
    const x0 = Math.min(...xs) - pad, x1 = Math.max(...xs) + pad + 120, y0 = Math.min(...ys) - pad, y1 = Math.max(...ys) + pad;
    const ratio = svg.clientHeight / svg.clientWidth || 0.7;
    const w = Math.max(x1 - x0, (y1 - y0) / ratio, 500);
    view = { x: (x0 + x1) / 2 - w / 2, y: (y0 + y1) / 2 - (w * ratio) / 2, w, h: w * ratio };
    setView();
  }

  function zoom(k, cx = view.x + view.w / 2, cy = view.y + view.h / 2) {
    view = { x: cx - (cx - view.x) / k, y: cy - (cy - view.y) / k, w: view.w / k, h: view.h / k };
    setView();
  }

  svg.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const box = svg.getBoundingClientRect();
    zoom(ev.deltaY < 0 ? 1.15 : 1 / 1.15, view.x + ((ev.clientX - box.left) / box.width) * view.w,
         view.y + ((ev.clientY - box.top) / box.height) * view.h);
  }, { passive: false });
  let drag = null;
  svg.addEventListener("pointerdown", (ev) => {
    if (ev.target.closest(".g-n")) return;
    drag = { x: ev.clientX, y: ev.clientY, view: { ...view } };
    svg.setPointerCapture(ev.pointerId);
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    const k = view.w / svg.clientWidth;
    view = { ...drag.view, x: drag.view.x - (ev.clientX - drag.x) * k, y: drag.view.y - (ev.clientY - drag.y) * k };
    setView();
  });
  svg.addEventListener("pointerup", () => { drag = null; });
  box.querySelectorAll("[data-zoom]").forEach((b) => b.addEventListener("click", () => zoom(+b.dataset.zoom)));
  box.querySelector("[data-fit]").addEventListener("click", () => { focus = null; fit(); });
  box.querySelector("[data-reset]").addEventListener("click", () => {
    for (const n of [...nodes.values()]) if (n.kind === "hub" && n.open) collapse(n);
    fitted = false; focus = null;
    kick();
  });

  box.hidden = false;
  setView();
  get(box.dataset.src.slice("/graf.json".length)).then((d) => {
    for (const h of d.hubs || []) add("c:" + h.id, "hub", h);
    for (const l of d.links || []) link(nodes.get("c:" + l.a), nodes.get("c:" + l.b), "soft", l.s, l.why);
    if (!d.hubs || !d.hubs.length) info.textContent = "Brak kampanii z więcej niż jednym materiałem w tym temacie.";
    kick();
  }).catch((err) => { info.textContent = "Nie udało się wczytać grafu: " + err; });
}
