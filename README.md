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
