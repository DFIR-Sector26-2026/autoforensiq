"""Dev HTML report — collect every pipeline artifact into one tabbed page.

A development/debug convenience (NOT the user-facing final_report.md). After a
full run, autoforensiq.py calls generate_dev_report() to build a single
self-contained output/dev_report.html: a left-hand tab list switches between
artifacts (case_context, execution_plan, audit_log, each raw tool output,
unified_evidence, shap_explanations and the rendered final report), showing one
at a time. The page auto-opens.

Stdlib only, fully offline (no CDN, no third-party deps): all styling and the
tiny tab-switch script are inlined, so it works from a file:// URL.

Standalone regen (no pipeline rerun needed):
    python -m src.utils.dev_report [--no-open]
"""

from __future__ import annotations

import html
import json
import os
import re
import shutil
import webbrowser
from datetime import datetime
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]

# Expected artifacts in pipeline order: (relative path or glob, stage, label).
# Globs (containing "*") expand to every match; a non-glob path that is absent
# becomes a "not generated" entry (shown disabled in the tab list).
_MANIFEST: list[tuple[str, str, str]] = [
    ("case_context.json",       "P1", "Intent Classifier"),
    ("execution_plan.json",     "P2", "Tool Selector"),
    ("audit_log.json",          "P3", "Orchestrator audit"),
    ("raw/*_output.json",       "P3", "Raw tool output"),
    ("unified_evidence.json",   "P4", "Aggregated evidence"),
    ("shap_explanations.json",  "P5", "ML / XAI"),
    ("final_report.md",         "P7", "Final report"),
    ("ioc_report.md",           "P7", "IOC indicators"),
]

_OUTPUT_FILENAME = "dev_report.html"
_LEGACY_DIRNAME = "dev_report"  # the old multi-file site; removed on regen


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "item"


# ── markdown ────────────────────────────────────────────────────────────────

def _inline(text: str) -> str:
    """Apply inline markdown (escape first, then re-introduce **bold** / `code` / <br>)."""
    out = html.escape(text)
    parts = out.split("`")  # `code` first so backticks aren't disturbed
    for i in range(1, len(parts), 2):
        parts[i] = f"<code>{parts[i]}</code>"
    out = "".join(parts)
    segs = out.split("**")  # **bold**
    for i in range(1, len(segs), 2):
        segs[i] = f"<strong>{segs[i]}</strong>"
    out = "".join(segs)
    # _italic_ — only at word boundaries, so intraword underscores (e.g.
    # wannacry_dropper, ioc_report.md inside a code span) are left alone, matching
    # GitHub's emphasis rules.
    out = re.sub(r"(?<!\w)_(?=\S)(.+?)(?<=\S)_(?!\w)", r"<em>\1</em>", out)
    # Honour an explicit <br> line break (e.g. the IOC badge on its own line in
    # a table cell) — the only raw-HTML tag allowed; it arrives as &lt;br&gt;
    # after escaping. Also restore &nbsp; (used to indent the badge), which
    # html.escape turned into &amp;nbsp;.
    out = re.sub(r"&lt;br\s*/?&gt;", "<br>", out)
    return out.replace("&amp;nbsp;", "&nbsp;")


def _render_markdown(md_text: str) -> str:
    """Minimal, dependency-free markdown → HTML.

    Covers what the report generator emits: ATX headings, GitHub pipe tables,
    unordered lists, horizontal rules, **bold**, `code`, and blank-line
    paragraphs. Everything is HTML-escaped via _inline; no raw HTML passthrough.
    """
    lines = md_text.splitlines()
    out: list[str] = []
    i, n = 0, len(lines)
    open_ul = False

    def close_list(flag: bool) -> bool:
        if flag:
            out.append("</ul>")
        return False

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            open_ul = close_list(open_ul)
            i += 1
            continue

        # fenced code block — preserve whitespace (process tree indentation)
        if stripped.startswith("```"):
            open_ul = close_list(open_ul)
            i += 1  # skip opening fence
            code_lines: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # skip closing fence (if present)
            out.append("<pre>" + html.escape("\n".join(code_lines)) + "</pre>")
            continue

        if stripped in ("---", "***", "___"):
            open_ul = close_list(open_ul)
            out.append("<hr>")
            i += 1
            continue

        if stripped.startswith("#"):
            open_ul = close_list(open_ul)
            level = min(max(len(stripped) - len(stripped.lstrip("#")), 1), 6)
            out.append(f"<h{level}>{_inline(stripped[level:].strip())}</h{level}>")
            i += 1
            continue

        # table: a pipe row followed by a |---|---| separator row
        if "|" in line and i + 1 < n and set(lines[i + 1].strip()) <= set("|-: "):
            open_ul = close_list(open_ul)
            header = [c.strip() for c in stripped.strip("|").split("|")]
            out.append("<table><thead><tr>")
            out.extend(f"<th>{_inline(c)}</th>" for c in header)
            out.append("</tr></thead><tbody>")
            i += 2
            while i < n and "|" in lines[i] and lines[i].strip():
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                out.append("<tr>")
                out.extend(f"<td>{_inline(c)}</td>" for c in cells)
                out.append("</tr>")
                i += 1
            out.append("</tbody></table>")
            continue

        if stripped[:2] in ("- ", "* "):
            if not open_ul:
                out.append("<ul>")
                open_ul = True
            out.append(f"<li>{_inline(stripped[2:].strip())}</li>")
            i += 1
            continue

        open_ul = close_list(open_ul)
        out.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    close_list(open_ul)
    return "\n".join(out)


# ── artifact bodies ───────────────────────────────────────────────────────────

def _meta(path: Path) -> str:
    """Size + mtime summary for a tab header."""
    stat = path.stat()
    size = float(stat.st_size)
    unit = "B"
    for u in ("B", "KB", "MB"):
        unit = u
        if size < 1024:
            break
        size /= 1024.0
    mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    shown = f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
    return f"{shown} · {mtime}"


def _body_for(path: Path) -> str:
    """Render one artifact's body based on extension."""
    if path.suffix == ".md":
        return f'<div class="md">{_render_markdown(path.read_text(encoding="utf-8"))}</div>'
    if path.suffix == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            pretty = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception:
            pretty = path.read_text(encoding="utf-8")
        return f"<pre>{html.escape(pretty)}</pre>"
    return f"<pre>{html.escape(path.read_text(encoding='utf-8', errors='replace'))}</pre>"


def _open_silently(uri: str) -> None:
    """Open a URI in the browser, discarding the browser's own stdout/stderr.

    Browsers (esp. Chromium) spew sandbox / VA-API noise to the inherited
    terminal. The spawned process inherits our fds, so we point 1 & 2 at
    /dev/null just while it launches, then restore — our own output is
    untouched, and the browser's later chatter goes to the void.
    """
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        webbrowser.open(uri)
        return
    saved_out, saved_err = os.dup(1), os.dup(2)
    try:
        os.dup2(devnull, 1)
        os.dup2(devnull, 2)
        webbrowser.open(uri)
    finally:
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        for fd in (devnull, saved_out, saved_err):
            os.close(fd)


# ── page shell ────────────────────────────────────────────────────────────────

_STYLE = """
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0d1117; color: #c9d1d9;
    font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; }
  header.top { padding: 18px 24px; background: #111827; border-bottom: 1px solid #30363d; }
  header.top h1 { margin: 0; font-size: 18px; }
  header.top .sub { color: #8b949e; font-size: 12px; margin-top: 4px; }
  .layout { display: flex; align-items: flex-start; }
  nav { position: sticky; top: 0; align-self: flex-start; min-width: 230px;
    max-height: 100vh; overflow: auto; padding: 16px; border-right: 1px solid #30363d; }
  nav a, nav span { display: block; padding: 6px 9px; border-radius: 6px;
    font-size: 12px; text-decoration: none; cursor: pointer; }
  nav a { color: #58a6ff; }
  nav a:hover { background: #161b22; }
  nav a.active { background: #1f6feb33; color: #79c0ff; font-weight: 600; }
  nav .missing { color: #6e7681; cursor: default; }
  main { flex: 1; padding: 20px 24px; min-width: 0; }
  .tab { display: none; }
  .tab.active { display: block; }
  .tab h2 { margin-top: 0; }
  .tab .meta { color: #8b949e; font-size: 12px; margin: -6px 0 14px; }
  pre { margin: 0; padding: 16px; overflow: auto; background: #161b22;
    border: 1px solid #30363d; border-radius: 10px;
    font: 12px/1.5 Consolas, Menlo, monospace; color: #c9d1d9; }
  .md { background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 4px 22px 22px; }
  .md h1, .md h2, .md h3 { border-bottom: 1px solid #30363d; padding-bottom: 4px; }
  .md table { border-collapse: collapse; width: 100%; margin: 12px 0; }
  .md th, .md td { border: 1px solid #30363d; padding: 6px 10px; text-align: left;
    font-size: 13px; }
  .md th { background: #1c2333; }
  .md code { background: #0d1117; padding: 1px 5px; border-radius: 4px;
    font: 12px Consolas, monospace; }
  .md hr { border: 0; border-top: 1px solid #30363d; }
"""

_SCRIPT = """
  function showTab(id){
    document.querySelectorAll('.tab').forEach(function(s){ s.classList.remove('active'); });
    document.querySelectorAll('nav a').forEach(function(a){ a.classList.remove('active'); });
    var sec = document.getElementById(id);
    var link = document.querySelector('nav a[data-tab="'+id+'"]');
    if(sec){ sec.classList.add('active'); }
    if(link){ link.classList.add('active'); }
    if(history.replaceState){ history.replaceState(null, '', '#'+id); }
    else { location.hash = id; }
  }
  document.addEventListener('DOMContentLoaded', function(){
    var id = location.hash.slice(1);
    if(!id || !document.getElementById(id)){
      var first = document.querySelector('.tab');
      id = first ? first.id : null;
    }
    if(id){ showTab(id); }
  });
"""


# ── page assembly ─────────────────────────────────────────────────────────────

def generate_dev_report(
    output_dir: Path,
    out_path: Path | None = None,
    auto_open: bool = True,
) -> Path:
    """Build a single tabbed output/dev_report.html from everything in output_dir.

    Returns the path written. Tabs follow pipeline order (the manifest), then
    any other files found in output_dir are appended.
    """
    output_dir = Path(output_dir)
    if out_path is None:
        out_path = output_dir / _OUTPUT_FILENAME

    # Remove the old multi-file site, if present, so only one artifact remains.
    legacy_dir = output_dir / _LEGACY_DIRNAME
    if legacy_dir.is_dir():
        shutil.rmtree(legacy_dir)

    # Resolve manifest into a flat, ordered entry list.
    entries: list[dict] = []
    covered: set[Path] = {out_path.resolve()}
    for rel, stage, label in _MANIFEST:
        if "*" in rel:
            matches = sorted(output_dir.glob(rel))
            if not matches:
                entries.append({"anchor": _slug(f"{stage}_{label}"), "stage": stage,
                                "label": label, "name": rel, "src": None})
            for m in matches:
                entries.append({"anchor": f"raw_{_slug(m.stem)}", "stage": stage,
                                "label": label, "name": m.name, "src": m})
                covered.add(m.resolve())
        else:
            p = output_dir / rel
            entries.append({"anchor": _slug(Path(rel).stem), "stage": stage,
                            "label": label, "name": Path(rel).name,
                            "src": p if p.exists() else None})
            if p.exists():
                covered.add(p.resolve())

    # Append any other files (new/unexpected artifacts), skipping our own output.
    for p in sorted(output_dir.rglob("*")):
        if not p.is_file() or p.resolve() in covered:
            continue
        rel = p.relative_to(output_dir)
        entries.append({"anchor": f"other_{_slug(str(rel))}", "stage": "+",
                        "label": str(rel), "name": p.name, "src": p})
        covered.add(p.resolve())

    # Tab list (nav) + tab panels (main).
    nav: list[str] = []
    panels: list[str] = []
    for e in entries:
        label = html.escape(f'{e["stage"]} · {e["label"]}')
        if e["src"] is None:
            nav.append(f'<span class="missing">{label} — n/a</span>')
            continue
        nav.append(
            f'<a data-tab="{e["anchor"]}" onclick="showTab(\'{e["anchor"]}\');return false">'
            f"{label}</a>"
        )
        title = html.escape(f'[{e["stage"]}] {e["label"]} — {e["name"]}')
        panels.append(
            f'<section class="tab" id="{e["anchor"]}">'
            f"<h2>{title}</h2>"
            f'<div class="meta">{html.escape(_meta(e["src"]))}</div>'
            f'{_body_for(e["src"])}</section>'
        )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoForensiq — Dev Report</title>
<style>{_STYLE}</style></head>
<body>
<header class="top">
  <h1>⚡ AutoForensiq — Dev Report</h1>
  <div class="sub">All pipeline artifacts · generated {generated} · {output_dir}</div>
</header>
<div class="layout">
  <nav>{''.join(nav)}</nav>
  <main>{''.join(panels)}</main>
</div>
<script>{_SCRIPT}</script>
</body></html>
"""

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page, encoding="utf-8")

    if auto_open:
        _open_silently(out_path.resolve().as_uri())

    return out_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Rebuild output/dev_report.html")
    parser.add_argument("--output-dir", default=str(ROOT_DIR / "output"),
                        help="Pipeline output directory to scan")
    parser.add_argument("--no-open", action="store_true",
                        help="Do not open the page in a browser")
    cli = parser.parse_args()

    path = generate_dev_report(Path(cli.output_dir), auto_open=not cli.no_open)
    print(f"[DEV] HTML report → {path}")
