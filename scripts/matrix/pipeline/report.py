"""Self-contained HTML report, a Markdown summary and a recheck plan."""

import html
import os
import time

from .analysis import ABS_PCT, CELL_ROW, MS_FLOOR, REL

STATUS_RU = {
    "ok": "ок", "hung": "зависание", "stalled": "молчание генератора", "crashed": "падение процесса",
    "gen_failed": "сбой генератора", "timeout": "таймаут ячейки", "setup_failed": "не поднялась",
    "cell_error": "ошибка ячейки", "interrupted": "прервана", "pending": "не запускалась",
}


def _e(s):
    return html.escape(str(s), quote=True)


def num(v, unit=""):
    if v is None:
        return "-"
    a = abs(v)
    if unit == "%":
        return f"{v:.1f}"
    if a >= 100:
        return f"{v:.0f}"
    if a >= 10:
        return f"{v:.1f}"
    if a >= 1:
        return f"{v:.2f}"
    return f"{v:.3f}"


def change(row):
    if row["unit"] == "%":
        return f"{row['delta']:+.1f} п.п."
    if row["rel"] is None:
        return "-"
    return f"{100 * row['rel']:+.1f}%"


def net_title(net):
    if net == "loopback":
        return "loopback, без сети"
    if net == "wan":
        return "WAN: сервер и клиент на удаленных машинах"
    parts = [f"RTT {net['rtt_ms']:g} мс", f"потери {net['loss_pct']:g}%"]
    if net.get("loss_burst", 1) > 1:
        parts[-1] += f" пачками по {net['loss_burst']:g} пакета"
    if net.get("loss_outage_ms"):
        parts[-1] += f" времени, провалы по {net['loss_outage_ms']:g} мс"
    if net.get("delay_jitter_ms"):
        parts.append(f"разброс задержки {net['delay_jitter_ms']:g} мс на проход без перестановки")
    if net.get("delay_spike_ms"):
        parts.append(f"всплески +{net['delay_spike_ms']:g} мс по {net['delay_spike_len_ms']:g} мс, {net['delay_spike_pct']:g}% времени")
    if net["rate_mbit"]:
        parts.append(f"{net['rate_mbit']:g} Мбит/с")
    return "netem: " + ", ".join(parts)


def arm(side):
    return side["variant"] if side["auth"] in ("none", None) else f"{side['variant']} ({side['auth']})"


CSS = """
:root{--bg:#fbfbfa;--fg:#1d1f21;--muted:#62666d;--line:#e2e3e5;--card:#ffffff;--head:#f2f3f4;
--worse:#b3261e;--worse-bg:#fbe9e7;--better:#1b6e3a;--better-bg:#e5f4ea;--warn:#8a5a00;--warn-bg:#fdf3dc;--accent:#2f5d9e}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#141517;--fg:#e6e6e6;--muted:#a0a4ab;--line:#2c2f33;
--card:#1b1d20;--head:#222529;--worse:#ff8a80;--worse-bg:#3a1d1b;--better:#7fd49b;--better-bg:#17301f;--warn:#f2c46b;--warn-bg:#352a12;--accent:#8fb4ea}}
:root[data-theme="dark"]{--bg:#141517;--fg:#e6e6e6;--muted:#a0a4ab;--line:#2c2f33;--card:#1b1d20;--head:#222529;
--worse:#ff8a80;--worse-bg:#3a1d1b;--better:#7fd49b;--better-bg:#17301f;--warn:#f2c46b;--warn-bg:#352a12;--accent:#8fb4ea}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 8px;padding-top:8px;border-top:1px solid var(--line)}
h3{font-size:16px;margin:22px 0 6px}p{margin:6px 0}.muted{color:var(--muted)}code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}.card b{display:block;font-size:22px}
.wrap{overflow-x:auto;margin:8px 0}table{border-collapse:collapse;width:100%;background:var(--card);font-size:13.5px}
th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--head);font-weight:600;white-space:nowrap}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.v-worse{color:var(--worse);background:var(--worse-bg);font-weight:600}.v-better{color:var(--better);background:var(--better-bg);font-weight:600}
.v-few{color:var(--muted)}.bad{color:var(--worse)}.warn{background:var(--warn-bg);color:var(--warn)}
details{margin:8px 0}summary{cursor:pointer;color:var(--accent)}.pill{display:inline-block;padding:0 7px;border-radius:9px;font-size:12px;border:1px solid var(--line)}
.theme{position:fixed;top:10px;right:12px;font-size:12px;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:3px 8px;cursor:pointer}
"""

JS = """
(function(){var b=document.querySelector('.theme');b.addEventListener('click',function(){var r=document.documentElement;
var d=r.getAttribute('data-theme');var dark=d?d==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
r.setAttribute('data-theme',dark?'light':'dark');});})();
"""


def _vclass(v):
    return {"хуже": "v-worse", "лучше": "v-better", "мало пар": "v-few"}.get(v, "")


def _rows_table(rows, a, b, with_raw):
    head = "<tr><th>Сценарий</th><th>Метрика</th>" + ("<th>raw</th>" if with_raw else "") + \
           f"<th>{_e(a)}</th><th>{_e(b)}</th><th>Изменение</th><th>Пары хуже/лучше</th><th>p</th><th>Вердикт</th></tr>"
    body = []
    for r in rows:
        unit = "" if r["unit"] in ("%",) else f" {r['unit']}"
        body.append(
            f"<tr><td><code>{_e(r['scenario'])}</code></td><td>{_e(r['label'])}{_e(unit)}</td>"
            + (f"<td class=n>{num(r['raw'], r['unit'])}</td>" if with_raw else "")
            + f"<td class=n>{num(r['a'], r['unit'])}</td><td class=n>{num(r['b'], r['unit'])}</td>"
            f"<td class=n>{change(r)}</td><td class=n>{r['worse']}/{r['better']} из {r['n']}</td><td class=n>{r['p']:.2f}</td>"
            f"<td class='{_vclass(r['verdict'])}'>{_e(r['verdict'])}</td></tr>")
    return f"<div class=wrap><table>{head}{''.join(body)}</table></div>"


def _slow_table(slow, a, b):
    head = f"<tr><th>Сценарий</th><th>{_e(a)}</th><th>{_e(b)}</th><th>p</th></tr>"
    body = "".join(
        f"<tr><td><code>{_e(x['scenario'])}</code></td><td class=n>{x['a_slow']} из {x['a_n']} ({100 * x['a_slow'] / x['a_n']:.1f}%)</td>"
        f"<td class=n>{x['b_slow']} из {x['b_n']} ({100 * x['b_slow'] / x['b_n']:.1f}%)</td>"
        f"<td class='n{' v-worse' if x['p'] < 0.05 and x['b_slow'] / x['b_n'] > x['a_slow'] / x['a_n'] else ''}'>{x['p']:.3f}</td></tr>"
        for x in slow)
    return f"<div class=wrap><table>{head}{body}</table></div>"


def _soak_table(rows):
    head = "<tr><th>Ячейка</th><th>Статус</th><th>Операций</th><th>Ошибки</th><th>Простой</th><th>RSS сервера, МБ</th><th>RSS клиента, МБ</th><th>Сессии после</th></tr>"
    body = []
    for r in rows:
        rss = {k: f"{v[0] / 1024:.0f} → {v[1] / 1024:.0f} (пик {v[2] / 1024:.0f})" for k, v in r["rss"].items()}
        errs = ", ".join(f"{k} {v}" for k, v in r["errors"].items()) or "0"
        idle = "; ".join(f"{k}: {v}" for k, v in sorted(r["idle"].items())) or "-"
        sess = "-" if r["sessions"] is None else f"{r['sessions']:g}"
        body.append(f"<tr><td><code>{_e(r['id'])}</code></td><td>{_e(STATUS_RU.get(r['status'], r['status']))}</td><td class=n>{r['ops']}</td>"
                    f"<td class='{'bad' if r['errors'] else ''}'>{_e(errs)}</td><td>{_e(idle)}</td>"
                    f"<td class=n>{_e(rss.get('server', '-'))}</td><td class=n>{_e(rss.get('client', '-'))}</td>"
                    f"<td class='n{' bad' if r['sessions'] else ''}'>{sess}</td></tr>")
    return f"<div class=wrap><table>{head}{''.join(body)}</table></div>"


def html_report(rep, out):
    p, m = rep["plan"], rep["manifest"]
    worse = sum(1 for s in rep["series"] for c in s["comparisons"] for r in c["rows"] if r["verdict"] == "хуже")
    better = sum(1 for s in rep["series"] for c in s["comparisons"] for r in c["rows"] if r["verdict"] == "лучше")
    total = sum(rep["counts"].values())
    ok = rep["counts"].get("ok", 0)
    build = m.get("build", {})
    parts = [f"<!doctype html><html lang=ru><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             f"<title>Бенчмарк {_e(p['name'])}</title><style>{CSS}</style></head><body><button class=theme>тема</button><main>"]
    parts.append(f"<h1>Бенчмарк {_e(p['name'])}</h1><p class=muted>{_e(p.get('description', ''))}</p>"
                 f"<p class=muted>План <code>{_e(p['hash'])}</code>, создан {_e(m.get('created', '?'))}, обновлен {_e(m.get('updated', '?'))}, "
                 f"состояние: {_e(m.get('state', 'running'))}. Сравнение: <b>{_e(p['base'])}</b> → <b>{_e(p['candidate'])}</b>.</p>")
    parts.append("<div class=cards>"
                 f"<div class=card><b>{ok} из {total}</b>ячеек прошли</div>"
                 f"<div class=card><b class='{'bad' if worse else ''}'>{worse}</b>метрик хуже</div>"
                 f"<div class=card><b>{better}</b>метрик лучше</div>"
                 f"<div class=card><b class='{'bad' if rep['problems'] else ''}'>{len(rep['problems'])}</b>проблем</div>"
                 f"<div class=card><b>{len(rep['flags'])}</b>флагов на перепроверку</div></div>")
    parts.append(f"<p class=muted>Правило вердикта: разница медиан не меньше {100 * REL:g}% (для долей - {ABS_PCT:g} п.п., для миллисекунд еще и не меньше "
                 f"{MS_FLOOR:g} мс) и один знак во всех парных раундах. При 3 раундах шум получает такой вердикт примерно в 25% случаев, при 5 - в 6%, "
                 "поэтому \"хуже\" - это флаг на перепроверку (<code>matrix.py recheck</code>), а не вывод. p - двусторонний знаковый тест без ничьих. "
                 "Прерванные сценарии, ячейки не в статусе \"ок\" и раунды на шумной машине в сравнение не входят.</p>")

    parts.append("<h2>Проблемы</h2>")
    if rep["problems"]:
        rows = "".join(f"<tr><td>{_e(x['kind'])}</td><td><code>{_e(x['where'])}</code></td><td>{_e(x['text'])}</td></tr>" for x in rep["problems"])
        parts.append(f"<div class=wrap><table><tr><th>Что</th><th>Где</th><th>Подробности</th></tr>{rows}</table></div>")
    else:
        parts.append("<p>Нет: все ячейки прошли, ошибок, прерываний, незакрытых сессий и записей WARN/ERROR нет.</p>")

    for s in rep["series"]:
        parts.append(f"<h2>{_e(s['title'])} <span class=pill>{_e(s['name'])}</span></h2><p class=muted>{_e(net_title(s['network']))}, раундов {s['rounds']}</p>")
        if s["kind"] == "soak":
            parts.append(_soak_table(s["soak"]))
            continue
        if not s["comparisons"]:
            parts.append("<p class=muted>Сравнений нет: в серии нет пары вариантов.</p>")
        for c in s["comparisons"]:
            a, b = arm(c["a"]), arm(c["b"])
            parts.append(f"<h3>{_e(c['transport'])}: {_e(a)} → {_e(b)}</h3>")
            if not c["rows"]:
                parts.append(f"<p class=bad>Нет ни одной пары раундов, где обе ячейки прошли ({c['rounds']}).</p>")
                continue
            flagged = [r for r in c["rows"] if r["verdict"] in ("хуже", "лучше")]
            with_raw = any(r["raw"] is not None for r in c["rows"])
            if flagged:
                parts.append(_rows_table(flagged, a, b, with_raw))
            else:
                parts.append(f"<p>Ни одна метрика не прошла правило вердикта ({c['rounds']} пар раундов).</p>")
            if c["slow"]:
                parts.append("<p class=muted>Доля запросов медленнее p50 + slow_ms, суммарно по раундам (биномиальный тест): p99 под потерями - "
                             "это попадание RTO в верхний процент, а доля показывает, сколько запросов его заплатили.</p>")
                parts.append(_slow_table(c["slow"], a, b))
            parts.append(f"<details><summary>Все метрики ({len(c['rows'])})</summary>{_rows_table(c['rows'], a, b, with_raw)}</details>")

    parts.append("<h2>Ячейки</h2>")
    rows = "".join(
        f"<tr><td><code>{_e(c['id'])}</code></td><td class='{'' if c['status'] == 'ok' else 'bad'}'>{_e(STATUS_RU.get(c['status'], c['status']))}</td>"
        f"<td class=n>{num(c['seconds'])}</td><td class='{'warn' if c['noisy'] else ''}'>{'' if c['foreign'] is None else num(c['foreign'])}</td>"
        f"<td>{_e(c['reason'])}</td></tr>" for c in rep["cells"])
    parts.append(f"<details><summary>{len(rep['cells'])} ячеек</summary><div class=wrap><table><tr><th>Ячейка</th><th>Статус</th><th>Замер, с</th>"
                 f"<th>Посторонняя нагрузка, ядер</th><th>Причина</th></tr>{rows}</table></div></details>")

    parts.append("<h2>Сборки</h2>")
    rows = []
    for name, v in p["variants"].items():
        b = build.get(name, {})
        src = "прямой путь, без прокси" if v["direct"] else f"{v['ref']}" + (f" + {os.path.basename(v['patch'])}" if v["patch"] else "")
        rows.append(f"<tr><td><b>{_e(name)}</b></td><td>{_e(src)}</td><td><code>{_e(b.get('commit', '')[:12])}</code>{' (с правками)' if b.get('dirty') else ''}</td>"
                    f"<td><code>{_e(b.get('s5core_sha256', '')[:16])}</code></td><td><code>{_e(b.get('s5client_sha256', '')[:16])}</code></td></tr>")
    parts.append("<div class=wrap><table><tr><th>Вариант</th><th>Источник</th><th>Коммит</th><th>sha256 s5core</th><th>sha256 s5client</th></tr>" + "".join(rows) + "</table></div>")
    parts.append(f"<h2>Как повторить</h2><p><code>python3 scripts/matrix/matrix.py run &lt;план&gt;</code> - тот же план, новый каталог. Этот каталог: "
                 f"<code>matrix.py resume {_e(out)}</code> (доделать), <code>matrix.py recheck {_e(out)}</code> (план перепроверки флагов).</p>")
    parts.append(f"<p class=muted>Собрано {time.strftime('%Y-%m-%d %H:%M')}.</p></main><script>{JS}</script></body></html>")
    return "".join(parts)


def markdown(rep):
    p = rep["plan"]
    lines = [f"# Бенчмарк {p['name']}", "", f"План `{p['hash']}`, {p['base']} -> {p['candidate']}.", ""]
    lines.append("Ячейки: " + ", ".join(f"{STATUS_RU.get(k, k)} {v}" for k, v in sorted(rep["counts"].items())))
    lines.append("")
    if rep["problems"]:
        lines += ["## Проблемы", ""] + [f"- {x['kind']}: `{x['where']}` - {x['text']}" for x in rep["problems"]] + [""]
    for s in rep["series"]:
        found = [(c, r) for c in s["comparisons"] for r in c["rows"] if r["verdict"] in ("хуже", "лучше")]
        lines += [f"## {s['title']} ({net_title(s['network'])})", ""]
        if s["kind"] == "soak":
            for r in s["soak"]:
                lines.append(f"- `{r['id']}`: {STATUS_RU.get(r['status'], r['status'])}, операций {r['ops']}, ошибки {r['errors'] or 0}, сессии после {r['sessions']}")
        elif not found:
            lines.append("Вердиктов нет.")
        for c, r in found:
            lines.append(f"- {c['transport']} {arm(c['a'])} -> {arm(c['b'])}: `{r['scenario']}` {r['label']} {num(r['a'], r['unit'])} -> "
                         f"{num(r['b'], r['unit'])} ({change(r)}), {r['worse']}/{r['better']} из {r['n']}, p={r['p']:.2f}: **{r['verdict']}**")
        lines.append("")
    return "\n".join(lines)


def recheck_toml(rep, rounds):
    """A plan that reruns only the flagged scenarios, base against candidate, on more rounds."""
    p = rep["plan"]
    flagged = {}
    for f in rep["flags"]:
        e = flagged.setdefault(f["series"], {"transports": set(), "scenarios": set(), "pairs": set()})
        e["transports"].add(f["transport"])
        e["pairs"].add((f["a"]["variant"], f["b"]["variant"]))
        if f["scenario"] != CELL_ROW:
            e["scenarios"].add(f["scenario"])
    if not flagged:
        return None

    def q(v):
        return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def val(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return f"{v:g}" if isinstance(v, float) else str(v)
        if isinstance(v, list):
            return "[" + ", ".join(val(x) for x in v) + "]"
        return q(v)

    out = [f"name = {q(p['name'] + '-recheck')}", f"description = {q('Перепроверка флагов ' + p['name'] + ' на ' + str(rounds) + ' раундах')}",
           f"base = {q(p['base'])}", f"candidate = {q(p['candidate'])}", ""]
    used = {p["base"], p["candidate"]}
    for e in flagged.values():
        for a, b in e["pairs"]:
            used |= {a, b}
    for name in sorted(used):
        v = p["variants"][name]
        out.append(f"[variants.{name}]")
        out.append(f"ref = {q(v['ref'])}")
        if v["patch"]:
            out.append(f"patch = {q(v['patch'])}")
        for side in ("server", "client"):
            if v["env"][side]:
                out.append(f"env.{side} = {{ " + ", ".join(f"{k} = {q(x)}" for k, x in sorted(v['env'][side].items())) + " }")
        out.append("")
    if p["cpus"]:
        out.append("[cpus]")
        for k, v in p["cpus"].items():
            out.append(f"{k} = {val(v)}")
        out.append("")
    out.append("[guard]")
    for k, v in p["guard"].items():
        out.append(f"{k} = {val(v)}")
    out.append("")
    if p.get("wan"):
        out.append("[wan]")
        for k, v in p["wan"].items():
            out.append(f"{k} = {val(v)}")
        out.append("")
    for s in p["series"]:
        if s["name"] not in flagged:
            continue
        e = flagged[s["name"]]
        out.append("[[series]]")
        out.append(f"name = {q(s['name'])}")
        out.append(f"title = {q(s['title'] + ', перепроверка')}")
        if s["network"] in ("loopback", "wan"):
            out.append(f"network = {q(s['network'])}")
        else:
            out.append("network = { " + ", ".join(f"{k} = {v:g}" for k, v in s["network"].items()) + " }")
        vs = sorted({x for pr in e["pairs"] for x in pr})
        pairs = sorted(pr for pr in e["pairs"] if pr[0] != pr[1])
        out.append(f"variants = {val(vs)}")
        out.append(f"compare = [{', '.join(val(list(pr)) for pr in pairs)}]")
        out.append(f"transports = {val(sorted(e['transports']))}")
        out.append(f"rounds = {rounds}")
        if e["scenarios"]:
            out.append(f"only = {val(['=' + x for x in sorted(e['scenarios'])])}")
        elif s["only"]:
            out.append(f"only = {val(s['only'])}")
        for k, v in s["settings"].items():
            out.append(f"{k} = {val(v)}")
        for side in ("server", "client"):
            if s["env"][side]:
                out.append(f"env.{side} = {{ " + ", ".join(f"{k} = {q(x)}" for k, x in sorted(s['env'][side].items())) + " }")
        out.append("")
    return "\n".join(out)
