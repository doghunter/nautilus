# ⚓ Nautilus Telemetry

Self-hosted marine telemetry for sailboats: collects data from onboard BLE
sensors and the GPS through a MikroTik KNOT router (connected e.g. via
WireGuard) and serves it on a real-time web dashboard, packaged as a single
Docker container.

One codebase serves any number of boats: all boat-specific values (sensor MACs,
KNOT address/credentials, boat name) come from environment variables — no
per-boat code changes.

## What it does

- **BM6 battery monitor** — real voltage, SoC, temperature and state via a
  persistent GATT connection through the KNOT (advertisements are also decoded,
  but GATT values always win).
- **MPPT solar charger** (Power Queen / Lumiax BT-PQCC2430) — presence and RSSI;
  Modbus register reading is documented together with the current RouterOS
  limitation that blocks it.
- **Optional MPPT integrations** — BL917 via the ZhiJinPower cloud, Victron
  SmartSolar via encrypted Instant Readout advertisements.
- **GPS** — position, speed in knots, course, satellites, altitude from the
  KNOT's internal GPS.
- **LTE signal** — RSRP/RSRQ/SINR/RSSI, operator and band.
- **Dashboard** — dark theme, 5 s auto-refresh, map with the OpenSeaMap nautical
  overlay, historical track page with date-range filters, clear "no data"
  indicators when a sensor stops transmitting.
- **Adaptive GPS reporting** — when the boat is stationary the expensive blocking GPS call to the KNOT is skipped (configurable interval), reducing power and data consumption.
- **Solar production history** — power samples are logged to SQLite and shown as a daily graph (today vs. yesterday) with a forecast built from previous days.
- **Settings page** — all polling intervals (including night mode and the adaptive GPS skip) editable live from the dashboard.
- **Consumption monitoring** — load current is logged too; a "Current used" graph sits next to solar production, and a `/stats` page totals produced/consumed energy by month and year with the net balance.
- **JSON API** — everything available at `/api/data`.

Full documentation: [docs/MANUAL.md](docs/MANUAL.md)

## Quick start

```bash
cp .env.example .env   # fill in KNOT address/credentials and sensor MACs
docker compose up -d --build
```

The dashboard is then served on port 8080 (default URL prefix `/nautilus`).

## Files

| File | Contents |
|---|---|
| `app.py` | Complete application: parsers, pure-Python AES, background threads, dashboard |
| `Dockerfile` | python:3.11-slim |
| `docker-compose.yml` | Service with restart: always, port 8080, env passthrough |
| `.env.example` | All supported configuration variables |
| `docs/MANUAL.md` | Full manual (architecture, BLE protocols, API, troubleshooting) |

## Credits

BLE decoding is based on the open-source reverse-engineering efforts for the
[BM6 battery monitor](https://github.com/JeffWDH/bm6-battery-monitor) and the
[solarlife MPPT BLE client](https://github.com/rahulthakoor/solarlife-mppt-ble-client).
Map tiles © OpenStreetMap contributors, nautical overlay © OpenSeaMap.
