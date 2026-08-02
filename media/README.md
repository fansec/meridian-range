# media/

Range-wide artwork. Keep diagrams as **SVG** (text, diff-able, committable). Raw screenshots belong in
`modules/<NN-slug>/evidence/raw/` (git-ignored), not here.

Module-specific figures live with their module, under `modules/<NN-slug>/media/`, so a module stays a
self-contained directory. Only range-wide artwork lives here.

- [`logo.png`](./logo.png) - the project logo, embedded at the top of the top-level
  [`README.md`](../README.md): the compass reticle ring and its dashed graticule, the snow-capped
  range, and the shield monogram at the centre, over the wordmark.
- [`logo-emblem.png`](./logo-emblem.png) - the same emblem cropped square, without the wordmark, for
  avatars, favicons and a slide corner. Below about 32px use this one; the full logo silts up.

  **The logo is raster, and it is the one exception in this directory** (decision, 2026-08-02). Every
  other file here is SVG for the reasons at the top of this page, and an earlier version of this logo
  was vector too. It was replaced by a rendered image chosen for the project, so the rule now reads:
  diagrams are drawn and stay vector, the logo is artwork and is whatever the artwork is. The cost is
  real and worth stating plainly: it does not diff, and it cannot be re-coloured or re-typeset by
  editing a file.

  **It is transparent, not a card, and it is checked on both themes.** The source render carried an
  opaque-looking grey backdrop that was in fact fully transparent, so the logo is cropped to its own
  bounds and composites onto whatever background the page has. Because the artwork is monochrome, the
  dark ring and wordmark are the parts at risk on a dark page, so any replacement gets composited onto
  white and onto GitHub's dark canvas (`#0d1117`) and read at its true display width before it is
  committed. The current one holds on both: the wordmark dims on dark but stays legible.

  **Keep it small.** The 1536x1024 source is 2.1 MB, which is an order of magnitude past either module
  screencast and has no business in a clone. Cropped to its content and quantised to a 256-colour
  palette it is 80 KB, and at the 340px it is displayed at, that is indistinguishable from the full
  RGBA original. Re-check that comparison at display size, not at full size, if the artwork changes.
- [`social-card.svg`](./social-card.svg) - source for the GitHub **social preview**, the Open Graph
  card that X, LinkedIn, Slack, Discord and Bluesky render when the repo URL is pasted. Without one,
  GitHub falls back to a generic auto-built card. It is 1280x640 (2:1, GitHub's recommended size), and
  it is full-bleed with square corners: unlike the diagrams here it carries no rounded corners, because
  the card *is* the whole image and a link unfurl crops it to a rectangle, so rounded corners would show
  the host page through them. Palette and font stacks are the same Primer set as the diagrams.

  It references [`logo.png`](./logo.png) relatively rather than inlining it, so it stays diff-able. That
  means it must be rendered as a **top-level document**, not via `<img>`, which cannot load external
  refs. To re-render after an edit:

  ```
  google-chrome --headless --force-device-scale-factor=2 --window-size=1280,640 \
      --screenshot=/tmp/card-2x.png media/social-card.svg
  convert /tmp/card-2x.png -resize 1280x640 -strip -colors 256 media/social-card.png
  ```

- [`social-card.png`](./social-card.png) - the render of the above, 116 KB, uploaded by hand under
  repo Settings, General, Social preview (there is no REST API for it, so it cannot be scripted).
  **This is not a second instance of the logo's raster exception:** its vector source sits next to it
  and is committed, so it re-typesets by editing a file. Rendered at 2x and downscaled for text
  antialiasing, then quantised to a 256-colour palette; that costs 0.6% RMSE against the full-colour
  render, which is invisible at any display size, and keeps it far under GitHub's 1 MB ceiling.

  Re-render it whenever the module count changes: the green chip claims a number.

- [`engine-design.svg`](./engine-design.svg) - the design view embedded in the top-level
  [`README.md`](../README.md): how a module is authored, what shared engine runs it, the two lanes of
  the reproduce-to-detect loop, and what is in the range today.
- [`labnet-topology.svg`](./labnet-topology.svg) - the labnet topology (attack 01), embedded in
  [`docs/topology.md`](../docs/topology.md).

Both are self-contained and theme-robust: they carry their own light card, so they render on a light
or a dark README background.

## Published clips

**Where a clip is embedded (decision, 2026-08-02).** A module's recording lives in
`modules/<NN-slug>/media/` and is embedded **at the top of that module's own README**, directly under
the title block. The top-level [`README.md`](../README.md) **links** to the module pages and embeds no
module clip. Two reasons, and both get worse with every module added: one hero cannot stay
representative once there are several attacks, and these are terminal recordings whose payoff is
readable text (a repeated session id, `uid=0(root)`, the canary), so a side-by-side pair at half width
is unreadable on desktop and gone on mobile. Only range-wide artwork
([`engine-design.svg`](./engine-design.svg)) is embedded on the front page.

- [`01-cors-hijack.gif`](../modules/01-cors-session-hijack/media/01-cors-hijack.gif) - attack 01 in
  motion, embedded at the top of
  [`modules/01-cors-session-hijack/README.md`](../modules/01-cors-session-hijack/README.md) and
  committed next to its module under `modules/01-cors-session-hijack/media/`. Cut from a
  **single-host** screencast: a real browser
  driving the attack over the lab's own DNS names through Traefik, with the victim MCP, the drive-by
  page and the exfil sink all on one isolated VM so their telemetry lands in a single file. Raw
  captures stay out of this repo, next to the capture rig in the private `ops/` checkout; only the
  finished, reviewed clip is committed.

  The clip has to carry three things, and a version missing any of them is not worth publishing: the
  victim's tab never changing, the request table showing one session id reused across calls from a
  foreign origin, and the **exfiltrated canary output** at the end. That last part is the only evidence
  that a command actually executed rather than that requests merely happened.

  **Publication rule: hostnames may appear, addresses may not.** Lab hostnames are publishable by
  decision: the lab zone resolves only on the isolated lab LAN, it is not reachable or resolvable from
  the internet, and the same goes for the hypervisor host names that show up in a frame (that
  environment is built and torn down from a separate automation repo). So a clip is not rejected for
  showing `*.lab.consulereit.nl` or the real lab zone. No IP address may ever appear in a frame: check the URL
  bar, the terminal pane, the tab title and the page body before committing a clip. A recording that
  captures an address is re-cut or re-shot, never published and patched later.

  Tier choice is not cosmetic here. The pane can only ever tail the telemetry local to the host it runs
  on, so the exfil line and the `/mcp` request table appear together **only** when the sink and the
  server share a host. On the split-host tier the sink sits on the attacker host and the proof of
  execution is logged out of shot, which is why the published clip is single-host.

  The capture rig that produced it is **operator-side tooling and ships separately**, so this repo does
  not carry a way to re-record the clip. It is Playwright, Xvfb and ffmpeg driving a real browser next to
  a terminal tailing the shared telemetry file; nothing in the reproduce-to-detect loop depends on it,
  and every module is verified by `./range verify`, not by a recording.

## The module 02 clip

- [`02-dns-rebind.gif`](../modules/02-dns-rebind/media/02-dns-rebind.gif) - the DNS rebinding attack in
  motion, embedded at the top of
  [`modules/02-dns-rebind/README.md`](../modules/02-dns-rebind/README.md). A real headed Chromium tab
  next to the victim's live `/mcp` request log, driven over real DNS across the two-host tier: the page
  and the sink on the attacker host, the capability-bearing MCP and the capture rig on the victim VM.

  **The sink stays on the attacker host, unlike module 01.** That is where the split topology puts it,
  so the collector's EXFIL line is logged off-camera. It costs nothing here because the drive-by page
  prints the command output in its own transcript, so the proof of execution (`uid=0(root)`, the
  container hostname, `LAB_CANARY_24`) is in the browser pane rather than the log pane.

  **Two A records, not a TTL expiry.** The documented runbook flips a short-TTL record. Chromium held
  the first answer regardless of the 1-second TTL and never re-resolved inside a 20-second take, so the
  capture serves two A records with the attacker first and stops the attacker's listener at the moment
  of the flip; the browser fails over to the second address inside the same cached entry. This is
  published rebind technique rather than a camera trick, but it is a different mechanism from the
  runbook, and both the clip's caption and the module's researcher notes say so.

  **What the clip has to carry**, on the same standard as module 01: the tab's URL never changing, the
  request rows showing a `Host` the server does not serve, and the command output coming back. A take
  missing the last one proves only that requests happened.

  **Pending re-record (2026-08-02).** This clip is the one artifact that did not follow the rename to
  the lab's real role names. It was captured against `rebind.lab.example`, and that name is burned
  into the URL bar, the page transcript and the telemetry pane, so it now disagrees with the module's
  own code and writeup, which say `rebind.lab.consulereit.nl`. The clip is left in place rather than
  pulled, because it is still an accurate recording of the attack and removing it would leave the
  module page with no demonstration at all. Re-shoot it on the current split-host tier and the
  disagreement goes away; nothing else in module 02 is waiting on it, since `./range verify 02` is
  what proves the reproduction. Module 01's clip needs nothing: it was already captured on
  `attacker.lab.consulereit.nl`.

  The rig is operator-side tooling and ships separately, so this repo carries no way to re-record it.

## Module 01 figures

Publication-quality figures for the module 01 writeup
([`modules/01-cors-session-hijack/README.md`](../modules/01-cors-session-hijack/README.md)), all
self-contained and theme-robust, all under `modules/01-cors-session-hijack/media/`:

- `01-architecture.svg` - security architecture and trust boundaries (attacker / victim-browser
  Same-Origin-Policy / developer host), with the numbered cross-origin attack path.
- `01-sequence.svg` - the HTTP/SSE attack sequence (the four-phase protocol dance).
- `01-detection-pipeline.svg` - the two-layer SOC-owned detection pipeline (raw `mcp.access` telemetry,
  SOC-side `mcp.cors.cross_origin` derivation, ATR rule, and the EDR payload layer).

## Module 02 figures

The same three views for module 02, under `modules/02-dns-rebind/media/`:

- `02-architecture.svg` - trust boundaries with the attacker's authoritative DNS zone as the weapon,
  and the numbered path from opening the link to the post-rebind exec.
- `02-sequence.svg` - the two phases either side of the DNS flip, on five lifelines.
- `02-detection-pipeline.svg` - the same two-layer SOC-owned pipeline, keyed on a foreign `Host` with
  a request that is not cross-origin, and why module 01's CORS rule stays silent.

The attack-01 **flow** diagram is rendered inline in that module's README via mermaid;
`labnet-topology.svg` here is the labnet **topology** view and `01-architecture.svg` the
**trust-boundary** view that complement it.
