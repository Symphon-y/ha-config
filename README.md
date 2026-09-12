# Home Assistant configuration

Source-controlled Home Assistant config. The repository **is** the live `/config`
directory on the HA box, not a copy — so `git pull` there applies changes and nothing
drifts.

## What is not here, and why

`.storage/` is excluded and always must be: it holds auth tokens, user accounts and
integration credentials in plaintext JSON. `secrets.yaml`, the database, logs, backups
and caches are excluded for the same or obvious reasons.

`esphome/` is its own git repository with its own `secrets.yaml`, so it stays separate.

**Consequence worth knowing:** UI-edited dashboards live in `.storage`, so they are *not*
versioned. That is why the wall panel is a YAML dashboard — it is the only way its design
can be reviewed, diffed and rolled back.

## Layout

| Path | Holds |
|---|---|
| `configuration.yaml` | Integrations, includes, dashboard registration |
| `dashboards/wall-panel.yaml` | The tablet dashboard — one view per kiosk page |
| `themes/wall-panel.yaml` | Design tokens for the tablet |
| `themes/modern.yaml` | The previous theme, untouched |
| `automations.yaml`, `scripts.yaml`, `scenes.yaml`, `templates.yaml` | Managed in the UI, stored here |
| `entity-inventory.txt` | Every entity id, regenerated for design work |
| `tools/` | Maintenance scripts. Not loaded by Home Assistant |
| `entity-renames.json` | Proposed entity id renames, awaiting review |
| `entity-renames.applied.json` | Renames that were actually applied — the revert log |

## The wall panel

Designed for an 11" tablet at 1280×800 CSS px, running the
[kiosk app](https://github.com/Symphon-y/kiosk). Direction: *a dark room with lamps in it.*

The rule that makes it legible from across a room: **amber means on.** Warm 2700K amber is
reserved for lights that are actually burning, so the panel reads as a map of the house
without parsing a word. Nothing else may use that colour.

Navigation is **external** — the kiosk app swipes between views with a two-finger gesture —
so no view may depend on Home Assistant's tab bar. Each view has a `path`, and each is a
separate page in the kiosk deck:

```
http://home.uselocal.app/wall-panel/home
```

## Applying changes

```sh
# on the HA box
cd /config && git pull
```

Then reload from **Developer tools → YAML → Reload all YAML configuration**, or restart
Home Assistant if `configuration.yaml` itself changed. Themes need a browser refresh.

## Regenerating the entity inventory

```sh
cd /config && python3 -c "import json;d=json.load(open('.storage/core.entity_registry'));print('\n'.join(sorted(e['entity_id'] for e in d['data']['entities'])))" > entity-inventory.txt
```

Only entity ids are extracted — the full registry carries device serials and MAC
addresses in `unique_id`, which do not belong in a repository.

## Renaming entities

Home Assistant derives an entity id from the device name at first discovery and never
revises it when the device is renamed upstream. So ids drift away from what they
control: `light.kitchen` is the Bathroom, and `light.floor_lamp` is a ceiling fan bulb.

`tools/ha_entity_rename.py` realigns ids with the current friendly names. Run it from
the **Studio Code Server add-on terminal**, where `SUPERVISOR_TOKEN` is already set —
renaming is only possible over the WebSocket API, so it needs a live connection.

```sh
cd /config
python3 tools/ha_entity_rename.py plan          # read-only; writes entity-renames.json
# review that file, set "apply": false on anything unwanted
python3 tools/ha_entity_rename.py apply --yes   # performs the renames
python3 tools/ha_entity_rename.py refs --write  # updates references in tracked YAML
```

`plan` defaults to Hue; `--platform all` widens it, which is what picks up the outdoor
TP-Link lights.

Two devices can legitimately share a friendly name — there are two Hue lights called
"Desk Light". Home Assistant disambiguates those by appending `_2`, `_3` and so on, and
so does this: `light.desk_light_2` is already the correct id for the second one, so it
is left alone, and a genuinely new clash gets the next free suffix rather than an error.
Rename one of them in the Hue app if you want ids that actually tell them apart.

Entities disabled in the registry are included and marked `d` — Hue's
`zigbee_connectivity` diagnostics are disabled by default, so they never reach the state
machine and their names have to be composed from the device registry rather than read
from a state. `--skip-disabled` leaves them alone.
`apply` is idempotent, so a partial run is safe to repeat, and it writes
`entity-renames.applied.json` — `apply --revert` undoes the batch.

Both JSON files are committed on purpose. The rename set is then reviewable and
revertable in git, for the same reason the wall panel is YAML.

**Manual overrides live at the top of the script**, in two tables, so exceptions are
recorded in one place instead of being re-decided every run:

- `NAME_FIXUPS` corrects a friendly name before it is slugged. Home Assistant slugs with
  `python-slugify`, which deletes apostrophes, so "Travis's Lamp" would become
  `traviss_lamp`; the fixup maps it to "Travis Lamp" and both the light and its
  companion diagnostics then land on `travis_lamp`.
- `SKIP` never renames an entity at all. The Hue entertainment zones are in there
  because they are parented to the bridge, so their composed name is "Hue Bridge
  Bedroom" and the id would get worse rather than better.

Renames are ordered, so a chain works: if A must vacate an id before B can claim it,
that happens in the right order automatically, and a true cycle is broken by parking one
entity on a temporary id. Identity is tracked by `unique_id`, not by entity id, which is
what makes re-running safe after a chain has already been applied.

Renames break dashboard references and Home Assistant does not rewrite them. `refs`
finds them. It never writes `.storage/` (the UI dashboards) or `current-dashboard.json`
(an export of them) — fix those in the browser editor.
