# Nautilus Telemetry — Manual

Nautilus is a self-hosted marine telemetry system for sailboats. It collects data
from onboard BLE sensors and the internal GPS through a MikroTik KNOT router
(typically connected via WireGuard) and serves everything on a real-time web
dashboard, packaged as a single Docker container.

A single codebase serves any number of boats: everything boat-specific is passed
through environment variables, with no per-boat code changes.

## 1. Architecture

```
BM6 battery monitor ──┐                        ┌──> BLE advertisement poll (60 s)
                      │                        │
MPPT solar charger ───┼─ BLE ─> MikroTik KNOT ──┼──> BM6 GATT connection (120 s)
                      │        REST API         └──> GPS monitor (120 s)
Internal GPS ─────────┘
                              │
                              v
                 nautilus-telemetry container (Flask :8080)
                              │
                              v
              dashboard (5 s auto-refresh) + /api/data JSON
```

Besides the web server, the app runs background threads:

| Thread | Interval | Purpose |
|---|---|---|
| poll_loop | 60 s | Reads `peripheral-devices` from the KNOT (only `persist=true` entries) and LTE monitor (RSRP/RSRQ/SINR) |
| gatt_loop | 120 s | Persistent GATT connection to the BM6 for real voltage/temperature/SoC/state |
| gps_loop | 120 s | Reads `/rest/system/gps/monitor` from the KNOT (blocking call, ~15–20 s) |
| bl917_loop (optional) | 300 s | Fetches BL917 MPPT data from the ZhiJinPower cloud via websocket |

## 2. Supported devices

### 2.1 Leagend BM6 battery monitor

The BM6 broadcasts two kinds of BLE advertisements, **neither of which contains
the real voltage**:

- **iBeacon** (Apple 0x004C): static identification only. The `major` field is a
  static ID, NOT the voltage — the "major/100 = V" formula from the original
  specification is wrong.
- **AES-128-CBC encrypted frame** (service data 0xFFF0, key
  `leagend\xff\xfe0100009`, null IV — see JeffWDH/bm6-battery-monitor):
  contains temperature and SoC, but the advertised values are unreliable
  (~15 °C off vs. the GATT reading).

**The reliable path is GATT** (RouterOS >= 7.12 supports the central role on
the KNOT):

1. `POST /rest/iot/bluetooth/connections/connect` with `pdev` = peripheral `.id`
2. `POST .../subscribe` on characteristic `fff4` (notify)
3. `POST .../write` on `fff3` with `data-hex` = `697ea0b5d54cf024e794772355554114`
   (AES-encrypted `d15507` command, constant)
4. `GET .../async-data` → encrypted notifications; decrypt and parse frame
   `d15507`:
   - byte 3: temperature sign (1 = negative), byte 4: temperature °C
   - byte 5: state (0=OK, 1=low voltage, 2=charging)
   - byte 6: SoC %
   - bytes 7–8: voltage big-endian / 100

The GATT connection is persistent: the BM6 keeps notifying while connected. The
app reuses the connection and re-issues the command each cycle (idempotent).
GATT values always take precedence and are never overwritten by ADV data.

Note: the BM6 temperature measures the internal chip, not ambient air. The
dashboard labels it "CPU temperature".

### 2.2 Power Queen / Lumiax BT-PQCC2430 MPPT charger

- The advertisement only carries MAC, name and UART service 0xFFE0: no
  Modbus data via ADV.
- Modbus RTU registers (map from solarlife-mppt-ble-client: V_pv 0x304E,
  V_bat 0x3046, I_bat 0x3047, SoC 0x3045, powers, energies…) travel on GATT
  service `ffe0`, characteristics `ffe1` (read/write/notify) and `ffe2`
  (write-no-response), device-id 0xFE, function code 0x04, CRC16 Modbus.
- **Known limitation**: RouterOS `connections/write` only does
  write-with-response, but `ffe2` accepts write-without-response only, so the
  Modbus command never leaves. The MPPT card shows presence/RSSI with a
  technical note. Unlocking the registers requires a script on the KNOT
  itself or an external BLE proxy (ESP32/ESPHome).

### 2.3 BL917 MPPT (optional)

Data lives on the ZhiJinPower cloud (`ws://device.gz529.com/`) and is read via
websocket using only the MAC. Enable with `BL917_ENABLED=1`. If the controller
was never registered through the vendor app, the cloud returns empty data.

### 2.4 Victron SmartSolar MPPT (optional)

Data comes from encrypted "Instant Readout" advertisements (manufacturer data
0x02E1, AES-128-CTR with a per-device key readable in VictronConnect → Product
Info → Instant Readout Details). Enable by setting `VICTRON_MAC` or
`VICTRON_SERIAL`.

### 2.5 KNOT GPS

`POST /rest/system/gps/monitor` with `{"once": "true"}` → latitude/longitude in
decimal degrees, speed, course, satellites, altitude. The call is **blocking**
(it waits for the fix): do not call it in parallel with the poll loop and use
a timeout >= 75 s.

## 3. Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Required | Purpose |
|---|---|---|
| `KNOT_HOST` | yes | KNOT address (e.g. its WireGuard IP) |
| `KNOT_USER` / `KNOT_PASS` | yes | KNOT REST API Basic Auth credentials |
| `BM6_MAC` / `MPPT_MAC` | yes | MAC addresses of the BLE sensors |
| `BOAT_NAME` | no | Boat name shown in the dashboard (default "Nautilus") |
| `URL_PREFIX_ALIAS` | no | Alternative URL prefix for the dashboard (default `/nautilus`) |
| `INTERNAL_TOKEN` | no | Shared token for the position-history backend APIs |
| `CONTICINI_BASE` | no | Base URL of the external position-history backend |
| `BL917_ENABLED` | no | `1` to enable the BL917 cloud thread |
| `BL917_MAC` / `BL917_WS` | no | BL917 MAC / cloud websocket URL |
| `BL917_TEMP_OFFSET` | no | Temperature correction in °C (default 0) |
| `VICTRON_MAC` / `VICTRON_SERIAL` | no | Victron MPPT identifiers |
| `VICTRON_ADV_KEY` | no | Victron Instant Readout AES key |
| `VICTRON_PUK` | no | Victron PUK (for key derivation) |

## 4. Dashboard

- Dark theme, responsive, auto-refresh every 5 s, boat name in the header
- **BM6 card**: voltage (GATT source), SoC with progress bar, temperature
  ("CPU temperature"), state, RSSI
- **MPPT card**: presence, RSSI, technical note when registers are unreachable
- **GPS card**: coordinates, **speed in knots** (converted from the KNOT km/h;
  `speed_kmh` also present in the API), course, satellites, altitude
- **LTE card**: RSRP as the main value with a qualitative rating (Excellent >
  -80, Good > -95, Weak > -110, Poor below), RSRQ, SINR, RSSI, operator, band
- **Map**: Leaflet + OpenStreetMap with the OpenSeaMap nautical overlay
  (buoys, lights, shallows) as the default view; Google Maps toggle
- **Track history page** (`/nautilus/track`): polyline of saved positions with
  hover tooltips (date/time, speed in knots, course with compass direction);
  filters by date range or last N points
- Clear indicators when a sensor stops transmitting (cards show "no data")
- `/api/data` returns the full state as JSON:

```json
{
  "bm6":  {"voltage": 13.29, "voltage_source": "gatt", "soc": 76,
           "temperature": 33, "state": "OK", "rssi": "-40"},
  "mppt": {"adv_name": "BT-PQCC2430", "rssi": "-35", "telemetry": false},
  "gps":  {"latitude": 41.0026, "longitude": 9.5599, "valid": true,
           "speed_kn": 0.0, "true_bearing": 18.4, "satellites": 8,
           "altitude_m": 3.0},
  "lte":  {"operator": "…", "band": "B7", "rsrp": -98.0, "rsrq": -19.0,
           "sinr": -4.0, "rssi": -63.0, "quality": "…"},
  "version": "…", "last_poll": "15:49:30", "updated": "2026-09-05T15:49:30"
}
```

## 5. Position history (optional backend)

Valid GPS fixes are POSTed to an external "conticini" management app
(`CONTICINI_BASE + /internal/boat/position`), authenticated with the
`X-Internal-Token` header. The backend deduplicates fixes closer than 25 m
(a boat moored in port produces one point). Nautilus proxies
`/api/boat/track-history` to the backend so the dashboard can draw the
historical track. Both features are inactive when `INTERNAL_TOKEN` is empty.

## 6. Running

```bash
cp .env.example .env   # fill in your values
docker compose up -d --build
```

Quick checks:

```bash
docker logs -f nautilus-telemetry
curl -s http://localhost:8080/api/data | python3 -m json.tool
```

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| BM6 voltage missing > 5 min | GATT connection dropped | The thread re-establishes it on the next cycle; `docker logs` shows "GATT BM6 fallito" |
| 400 errors on connect | BM6 already connected (or slots full) | The app reuses the connection; check `GET .../connections` |
| GPS missing | Blocking call / timeout | Test with curl and a 90 s timeout; the KNOT needs open sky |
| Odd BM6 temperature | Taken from ADV instead of GATT | Unreliable ADV value; overwritten when GATT is active |
| No MPPT register data | write-no-response unsupported via REST | Structural limitation, see §2.2 |
