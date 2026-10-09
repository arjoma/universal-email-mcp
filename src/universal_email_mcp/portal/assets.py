"""Static assets of the portal pages. The CSS is served from our own origin so that the
content security policy needs no ``unsafe-inline`` for styles."""

from __future__ import annotations

PORTAL_CSS = """\
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --card: #ffffff; --text: #1b1f24; --muted: #596270;
  --line: #d5dae1; --accent: #1f5fbf; --accent-text: #ffffff; --danger: #a52222;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171b; --card: #1d2227; --text: #e8ebef; --muted: #a2abb8;
    --line: #333b45; --accent: #6ea4ff; --accent-text: #0b1220; --danger: #ff8a8a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 16px; background: var(--bg); color: var(--text);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main {
  max-width: 40rem; margin: 2rem auto; padding: 1.5rem; background: var(--card);
  border: 1px solid var(--line); border-radius: 10px;
}
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
h2 { font-size: 1.1rem; margin: 1.5rem 0 .5rem; }
h3 { font-size: 1rem; margin: 1rem 0 .25rem; }
label { display: block; margin: 1rem 0 .25rem; font-weight: 600; }
input[type=email], input[type=password] {
  width: 100%; padding: .6rem .7rem; font: inherit; color: inherit; background: transparent;
  border: 1px solid var(--line); border-radius: 6px;
}
input:focus-visible, button:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
.hint, .signed-in { color: var(--muted); font-size: .9rem; }
.note { padding: .75rem; border: 1px solid var(--line); border-radius: 6px; }
.error { color: var(--danger); font-weight: 600; }
.client { margin: 1rem 0; padding: .75rem 1rem; border: 1px solid var(--line); border-radius: 8px; }
.client-name { font-size: 1.15rem; font-weight: 700; margin: 0 0 .5rem; overflow-wrap: anywhere; }
dl { margin: 0; } dt { color: var(--muted); font-size: .85rem; } dd { margin: 0 0 .5rem; overflow-wrap: anywhere; }
code { font-family: ui-monospace, monospace; font-size: .9em; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid var(--line); vertical-align: top; }
thead th { font-size: .85rem; color: var(--muted); }
td input { width: 1.2rem; height: 1.2rem; }
ul.plain { list-style: none; padding: 0; margin: 0; }
ul.plain label { display: inline; font-weight: 400; }
.buttons { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1.5rem; }
button {
  font: inherit; padding: .6rem 1.2rem; border-radius: 6px; cursor: pointer;
  border: 1px solid var(--line); background: transparent; color: var(--text);
}
button.primary { background: var(--accent); color: var(--accent-text); border-color: var(--accent); }
button.link { border: 0; padding: 0; color: var(--muted); text-decoration: underline; }
form.inline { margin-top: 1.25rem; }
.sr-only {
  position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap;
}
"""
