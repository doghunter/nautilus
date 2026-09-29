#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nautilus-telemetry — BLE dashboard for sensors relayed by the MikroTik KNOT over WireGuard.

Supported devices (configured via environment variables, see docs/MANUAL.md):
  * Leagend BM6 battery monitor (BLE advertisements + GATT)
  * Power Queen / Lumiax BT-PQCC2430 MPPT solar charger (BLE advertisements)
  * BL917 MPPT via ZhiJinPower cloud (optional)
  * Victron SmartSolar MPPT (encrypted Instant Readout advertisements, optional)

Decoding based on the open-source projects:
  * BM6:  https://github.com/JeffWDH/bm6-battery-monitor
          https://www.tarball.ca/posts/reverse-engineering-the-bm6-ble-battery-monitor/
          https://github.com/Rafciq/BM6 (layout frame real-time)
  * MPPT: https://github.com/rahulthakoor/solarlife-mppt-ble-client
          https://github.com/subDesTagesMitExtraKaese/solarlife-mppt-ble-client

Frame formats observed on real traffic (empirically verified on 3 devices):

  BM6 iBeacon (Apple):
    02 01 06 1A FF 4C 00 02 15 <UUID(16)> <major(2 BE)> <minor(2 BE)> <tx@1m>
    major/minor = static beacon IDs ("vehicle finder" feature), NOT the voltage:
    verified empirically (major constant for hours, fixed value 4428).

  BM6 frame cifrato (service data 0xFFF0, 16 byte AES-128-CBC, IV nullo):
    AD "03 02 F0 FF 11 FF" + 16 byte cifrati. Dopo decifratura:
      byte 0..5   MAC del dispositivo
      byte 6      tipo frame (05 osservato)
      byte 7      temperatura (°C)
      byte 8      SoC (%)
      byte 9      segno temperatura (00 = +, 01 = −)
      byte 10     stato (00=OK, 01=tensione bassa, 02=in carica, altro=sconosciuto)
      bytes 11-12  big-endian voltage/100 (not always populated: 0x0000 when absent)

  MPPT BT-PQCC2430 (adv):
    03 03 E0 FF   → servizio UART 0xFFE0 (canale Modbus RTU via BLE GATT)
    09 FF 5A 58 <MAC> 0C   → manufacturer data ("ZX" + MAC)
    0C 09 "BT-PQCC2430"   → nome locale
    The advertisement does NOT carry the Modbus registers (V_pv/V_bat/I_bat
    are only readable via a GATT connection, which the KNOT does not relay):
    the Modbus parser stays active with sanity checks should data arrive.

Dependencies: only flask + requests (AES implemented in pure Python).
The Victron parser uses pycryptodome (AES-CTR, if available).
"""

import base64
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta

import requests
from flask import Flask, Response, jsonify, request

# --------------------------------------------------------------------------
# Configuration (fully parametric via environment, see docs/MANUAL.md)
# --------------------------------------------------------------------------
KNOT_HOST = os.environ.get("KNOT_HOST", "")
KNOT_USER = os.environ.get("KNOT_USER", "")
KNOT_PASS = os.environ.get("KNOT_PASS", "")
KNOT_URL = f"http://{KNOT_HOST}/rest/iot/bluetooth/peripheral-devices"
KNOT_GPS_URL = f"http://{KNOT_HOST}/rest/system/gps/monitor"
KNOT_LTE_URL = f"http://{KNOT_HOST}/rest/interface/lte/monitor"
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "60"))
# Reduced night poll (local time; 0 = disabled, POLL_SECONDS is always used)
NIGHT_START = int(os.environ.get("NIGHT_START", "22"))
NIGHT_END = int(os.environ.get("NIGHT_END", "7"))
POLL_SECONDS_NIGHT = int(os.environ.get("POLL_SECONDS_NIGHT", "0"))
GPS_POLL_SECONDS = 120   # the GPS monitor call is blocking (~15-20s): dedicated cadence
GPSBUF_POLL_SECONDS = int(os.environ.get("GPSBUF_POLL_SECONDS", "900"))
# Archives older than this many days are deleted on each log download
# (0 = keep forever). Applies to data/knot-log-archive/*.json only; the
# GBUF archive (data/gpsbuf-archive.log) is tiny and always kept.
GPSBUF_RETENTION_DAYS = int(os.environ.get("GPSBUF_RETENTION_DAYS", "30"))
# How often the KNOT-side gps-buffer script writes a GBUF log line (its
# scheduler interval). Applied to the KNOT via REST when changed here.
GBUF_WRITE_SECONDS = int(os.environ.get("GBUF_WRITE_SECONDS", "300"))


def _seconds_to_interval(sec):
    """RouterOS interval string from seconds."""
    if sec % 3600 == 0:
        return f"{sec // 3600}h"
    if sec % 60 == 0:
        return f"{sec // 60}m"
    return f"{sec}s"


def apply_gbuf_interval(sec):
    """Push the GBUF write interval to the KNOT gps-buffer scheduler (REST).

    Best effort: failures are logged, never raised - the scheduler entry
    must be owned by the REST user (recreated that way on 2026-09-28).
    Called from the settings POST handler with a thread.
    """
    global _gbuf_apply_error
    try:
        r = requests.post(
            f"http://{KNOT_HOST}/rest/system/scheduler/set",
            json={"numbers": "gps-buffer", "interval": _seconds_to_interval(int(sec))},
            auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS), timeout=20)
        if r.status_code == 200:
            log.info("GBUF write interval set on KNOT: %s s", int(sec))
            _gbuf_apply_error = None
        else:
            msg = f"KNOT scheduler set failed: HTTP {r.status_code} {r.text[:120]}"
            log.warning(msg)
            _gbuf_apply_error = msg
    except Exception as exc:
        _gbuf_apply_error = f"KNOT unreachable: {exc}"
        log.warning("GBUF interval apply failed: %s", exc)


_gbuf_apply_error = None

# Adaptive reporting interval: when the boat is stationary (speed < threshold)
# the expensive KNOT GPS call is skipped until GPS_STATIONARY_INTERVAL
# seconds have passed since the last valid fix (power saving).
STATIONARY_SPEED_KN = float(os.environ.get("STATIONARY_SPEED_KN", "0.5"))
GPS_STATIONARY_INTERVAL = int(os.environ.get("GPS_STATIONARY_INTERVAL", "600"))

# SIM data usage: monthly budget (MB) and counter sampling cadence.
# The KNOT's WireGuard counters (peer rx/tx towards the relay) are read via
# REST; deltas are accumulated per day in the solar DB (data_usage
# table). The tunnel carries all telemetry, so it is a good approximation
# of the SIM LTE traffic.
DATA_BUDGET_MB = float(os.environ.get("DATA_BUDGET_MB", "1000"))
DATA_USAGE_POLL_SECONDS = int(os.environ.get("DATA_USAGE_POLL_SECONDS", "600"))
KNOT_WG_URL = f"http://{KNOT_HOST}/rest/interface/wireguard/peers"
# Max WireGuard handshake age beyond which the tunnel is considered down
KNOT_TUNNEL_STALE_S = int(os.environ.get("KNOT_TUNNEL_STALE_S", "180"))

# Solar production history (local SQLite; dir mounted as a volume).
SOLAR_DB = os.environ.get("SOLAR_DB", "data/nautilus.db")
# Server-side archive of the GBUF lines recovered from the KNOT log
GPSBUF_ARCHIVE = os.path.join(os.path.dirname(SOLAR_DB) or "data",
                              "gpsbuf-archive.log")

# MAC addresses of the BLE sensors (required)
BM6_MAC = os.environ.get("BM6_MAC", "").upper()
MPPT_MAC = os.environ.get("MPPT_MAC", "").upper()

# BM6 AES-128 key (JeffWDH/bm6-battery-monitor): "leagend\xff\xfe0100009"
BM6_KEY = bytes([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])
BM6_ADV_MARKER = "0302f0ff11ff"   # AD: service UUID 0xFFF0 + 0x11 0xFF + AES block

MPPT_SERVICE_UART = "0303e0ff"    # AD: 16-bit UUID list with 0xFFE0 (Modbus channel)

BM6_STATES = {0: "OK", 1: "Low voltage", 2: "Charging"}

# Rest-voltage SoC estimate (like the BM6 app does with a battery profile).
# The BM6 firmware's internal SoC is calibrated for 12V lead-acid car
# batteries and reports nonsense on LiFePO4; with BM6_BATTERY_TYPE set we
# also show the voltage-derived estimate. Indicative only: while charging or
# discharging the voltage is shifted from the rest value.
BM6_SOC_CURVES = {
"lifepo4": [  # (V, SoC%) 12V LiFePO4 at rest (flat in the middle: rough estimate)
        (14.6, 100), (13.6, 99), (13.4, 95), (13.3, 85), (13.2, 70),
        (13.1, 55), (13.0, 40), (12.9, 30), (12.7, 20), (12.4, 10),
        (12.0, 5), (11.5, 0),
    ],
    "agm": [
        (14.7, 100), (13.0, 100), (12.8, 75), (12.6, 60), (12.4, 45),
        (12.2, 30), (12.0, 20), (11.8, 10), (11.6, 0),
    ],
    "fla": [
        (14.4, 100), (12.7, 100), (12.5, 75), (12.3, 55), (12.1, 40),
        (11.9, 25), (11.7, 15), (11.5, 0),
    ],
}
BM6_BATTERY_TYPE = os.environ.get("BM6_BATTERY_TYPE", "").lower()

# Temperature correction (deg C, added to the sensor value): the BM6 chip
# self-heats and its internal temperature sits above ambient (the BM6 app
# applies an equivalent calibration). Example: -18 for a chip that reads
# 38 deg C when ambient is 20 deg C.
BM6_TEMP_OFFSET = float(os.environ.get("BM6_TEMP_OFFSET", "0"))


def estimate_soc(voltage, btype=None):
    """Interpolates SoC from rest voltage according to the battery-type curve."""
    curve = BM6_SOC_CURVES.get(btype or BM6_BATTERY_TYPE)
    if not curve or voltage is None:
        return None
    pts = sorted(curve)
    if voltage >= pts[-1][0]:
        return pts[-1][1]
    for (v0, s0), (v1, s1) in zip(pts, pts[1:]):
        if v0 <= voltage <= v1:
            return round(s0 + (s1 - s0) * (voltage - v0) / (v1 - v0))
    return pts[0][1]

# GATT via REST (RouterOS >= 7.12): real voltage read from the BM6.
# The encrypted "d15507..." AES command is constant (BM6 key, null IV) —
# verified identical to the one used by the JeffWDH repo and the tarball.ca post.
KNOT_GATT = f"http://{KNOT_HOST}/rest/iot/bluetooth/connections"
BM6_GATT_CMD = "697ea0b5d54cf024e794772355554114"   # encrypt("d15507" + 00*10)
GATT_POLL_SECONDS = 120   # cadenza dedicata (connect+read ~15-20s)

# --------------------------------------------------------------------------
# BL917 MPPT: data lives on the ZhiJinPower cloud (ws://device.gz529.com)
# and is read over websocket using only the MAC. No GATT available.
# --------------------------------------------------------------------------
BL917_WS = os.environ.get("BL917_WS", "ws://device.gz529.com/")
BL917_MAC = os.environ.get("BL917_MAC", "")
BL917_POLL_SECONDS = 300   # 5 min: the cloud is slow, no point hammering it

# BL917 temperature correction (deg C, added to the cloud value): like the
# BM6, the sensor measures its own chip, not the air. 0 = no correction.
BL917_TEMP_OFFSET = float(os.environ.get("BL917_TEMP_OFFSET", "0"))

# --------------------------------------------------------------------------
# Victron SmartSolar MPPT: dati via advertisement "Instant
# Readout" cifrati AES-128-CTR. Protocollo: manufacturer data 0x02E1,
# payload 0x10 <model_id LE16> <readout_type> <iv LE16> <encrypted>.
# The key is read from VictronConnect (Product Info -> Instant Readout
# Details) or must be derived; the first encrypted byte is a key-check byte
# (it must match the first byte of the key).
# --------------------------------------------------------------------------
VICTRON_MAC = os.environ.get("VICTRON_MAC", "").upper()
VICTRON_ADV_KEY = os.environ.get("VICTRON_ADV_KEY", "").lower()
VICTRON_SERIAL = os.environ.get("VICTRON_SERIAL", "")
VICTRON_PUK = os.environ.get("VICTRON_PUK", "")
VICTRON_MARKER = "ffe10210"    # AD type FF + company 0x02E1 (LE) + prefix 0x10

VIC_SHUNT_METRICS = {0x64: ("SmartShunt 500A/50mV",),
                      0x65: ("SmartShunt 500A/50mV",)}


def _victron_devices():
    """Victron devices to decode: list of {mac, key, serial, puk}.

    Sources (merged): the VICTRON_* env vars (single legacy device) and the
    VICTRON_DEVICES runtime setting (JSON list, editable in Settings UI).
    """
    items = []
    env_mac = (os.environ.get("VICTRON_MAC") or "").upper()
    if env_mac:
        items.append({"mac": env_mac,
                      "key": (os.environ.get("VICTRON_ADV_KEY") or "").lower(),
                      "serial": os.environ.get("VICTRON_SERIAL", ""),
                      "puk": os.environ.get("VICTRON_PUK", "")})
    raw = _runtime_cfg.get("VICTRON_DEVICES")
    if raw:
        try:
            for it in json.loads(raw):
                mac = str(it.get("mac", "")).upper()
                if mac:
                    items.append({"mac": mac,
                                  "key": str(it.get("key", "")).lower(),
                                  "serial": str(it.get("serial", "") or ""),
                                  "puk": str(it.get("puk", "") or ""),
                                  "bt_pin": str(it.get("bt_pin", "") or ""),
                                  "part_number": str(it.get("part_number", "") or "")})
        except (ValueError, AttributeError):
            log.warning("VICTRON_DEVICES: JSON non valido, ignorato")
    # dedupe by MAC (runtime entry wins over env)
    seen = {}
    for it in items:
        seen[it["mac"]] = it
    return list(seen.values())


def _victron_store_key(mac, key):
    """Locks a validated advertisement key into the runtime VICTRON_DEVICES."""
    raw = _runtime_cfg.get("VICTRON_DEVICES")
    items = json.loads(raw) if raw else []
    for it in items:
        if str(it.get("mac", "")).upper() == mac:
            it["key"] = key.lower()
            _runtime_cfg["VICTRON_DEVICES"] = json.dumps(items)
            _runtime_cfg_save()
            return


class _VicBitReader:
    """Reads Victron packed bit-fields, LSB first (victron-ble layout)."""

    def __init__(self, data):
        self._data = data
        self._index = 0

    def _bit(self):
        b = (self._data[self._index >> 3] >> (self._index & 7)) & 1
        self._index += 1
        return b

    def unsigned(self, n):
        v = 0
        for p in range(n):
            v |= self._bit() << p
        return v

    def signed(self, n):
        v = self.unsigned(n)
        return v - (1 << n) if v & (1 << (n - 1)) else v


def _victron_batt_monitor_parse(dec):
    """Battery-monitor readout (SmartShunt/BMV) - victron-ble bitfield layout:
    remaining_mins u16, voltage s16, alarm u16, aux u16, aux_mode u2,
    current s22 (mA), consumed_ah u20 (0.1Ah), soc u10 (0.1%)."""
    r = _VicBitReader(dec)
    remaining_mins = r.unsigned(16)
    voltage = r.signed(16)
    alarm = r.unsigned(16)
    aux = r.unsigned(16)
    aux_mode = r.unsigned(2)
    current = r.signed(22)
    consumed_ah = r.unsigned(20)
    soc = r.unsigned(10)
    return {
        "readout_kind": "battery-monitor",
        "soc_pct": (soc / 10.0) if soc != 0x3FF else None,
        "v_bat": (voltage / 100.0) if voltage != 0x7FFF else None,
        "i_bat": (current / 1000.0) if current != 0x3FFFFF else None,
        "consumed_ah": (-consumed_ah / 10.0) if consumed_ah != 0xFFFFF else None,
        "remaining_mins": remaining_mins if remaining_mins != 0xFFFF else None,
        "alarm": alarm,
        "aux_mode": ["starter-voltage", "midpoint-voltage", "temperature",
                     "disabled"][aux_mode] if aux_mode < 4 else "unknown",
    }


VIC_CHARGE_STATES = {0: "Off", 1: "Low power", 2: "Fault", 3: "Bulk",
                     4: "Absorption", 5: "Float", 6: "Storage",
                     7: "Equalize (manual)", 9: "Inverting", 11: "Power supply",
                     245: "Starting up", 246: "Repeated absorption",
                     247: "Recondition", 248: "Battery safe", 249: "Active",
                     252: "External control"}


def _victron_ctr_decrypt(key, iv, data):
    """AES-128-CTR with little-endian counter (like victron-ble/pycryptodome)."""
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    ctr = Counter.new(128, initial_value=iv, little_endian=True)
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(data + b"\x00" * (-len(data) % 16))


def _victron_derive_key(serial, puk):
    """Key-derivation candidates from serial+PUK (to be validated against the
    first frame's key-check byte: if it does not match, none is correct)."""
    import hashlib
    cands = []
    serial, puk = serial or "", puk or ""
    for combo in (serial + puk, puk + serial,
                  serial + ":" + puk, puk + ":" + serial,
                  serial + "-" + puk, serial + "_" + puk):
        cands.append(hashlib.sha256(combo.encode()).digest()[:16].hex())
        cands.append(hashlib.md5(combo.encode()).hexdigest())
    return cands


def parse_victron(dev, adv_key):
    """Decodes a Victron solar charger's Instant Readout advertisement.

    Returns a dict with the charger data, or with 'error' when the key
    is invalid (key-check byte mismatch).
    """
    out = {
        "model": "SmartSolar", "name": dev.get("name", "Victron"),
        "mac": dev.get("address", ""),
        "rssi": dev.get("rssi"),
        "last_seen": (dev.get("last-seen") or "").split(" ")[-1],
    }
    raw = (dev.get("last-data") or "").lower()
    idx = raw.find(VICTRON_MARKER)
    if idx < 0:
        out["error"] = "no Victron advertisement in last-data"
        return out
    payload = raw[idx + len(VICTRON_MARKER):]
    try:
# solar readout = 19 bytes, battery-monitor = 23: take up to 46 hex-escaped bytes
        data = bytes.fromhex(payload[:52])
    except ValueError:
        out["error"] = "malformed advertisement"
        return out
    # layout victron-ble: prefix(2: 10 02) model(LE16) readout(1) iv(LE16) enc
    # solar readout = 12 decrypted bytes, battery-monitor = 15 (118 bits):
    # keep the whole encrypted payload, not just the first 13 bytes
    if len(data) < 19:
        out["error"] = "advertisement too short"
        return out
    model_id = data[1] | (data[2] << 8)
    readout_type = data[3]
    iv = data[4] | (data[5] << 8)
    enc = data[6:]
    key = bytes.fromhex(adv_key)
    if enc[0] != key[0]:
        out["error"] = "advertisement key mismatch (key-check byte)"
        return out
    dec = _victron_ctr_decrypt(key, iv, enc[1:])
    b = dec[:12]
    def _s16(v): return v - 0x10000 if v & 0x8000 else v
    # readout type 0x02 = battery monitor (SmartShunt / BMV): different layout
    if readout_type == 0x02:
        out.update(_victron_batt_monitor_parse(dec))
        out["model"] = "SmartShunt"
        return out
    load9 = 0x1FF if len(b) < 12 else ((b[10] | (b[11] << 8)) & 0x1FF)
    out.update({
        "model_id": model_id,
        "charge_state_code": b[0],
        "charge_state": VIC_CHARGE_STATES.get(b[0], "Unknown (%d)" % b[0]),
        "charger_error_code": b[1],
        "v_bat": _s16(b[2] | (b[3] << 8)) / 100.0,
        "i_charge": _s16(b[4] | (b[5] << 8)) / 10.0,
        "yield_today_wh": (b[6] | (b[7] << 8)) * 10,
        "solar_power_w": b[8] | (b[9] << 8),
# 9 bits little-endian starting from byte 10
        "i_load": load9 / 10.0,
        "readout_type": readout_type,
    })
    return out

# --------------------------------------------------------------------------
# Position history backend (optional): an external "conticini" management app
# exposes internal APIs protected by X-Internal-Token; nautilus posts valid GPS
# fixes there and proxies the track history to the dashboard.
CONTICINI_BASE = os.environ.get("CONTICINI_BASE", "")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")


def _conticini_headers():
    return {"X-Internal-Token": INTERNAL_TOKEN, "Content-Type": "application/json"}


def save_position(gps, buffered=False):
    """POSTs the valid fix to conticini (which deduplicates < 25 m).

    buffered=True marks a point replayed from the KNOT-side gps buffer
    (recorded while offline, e.g. out of LTE coverage while sailing):
    conticini stores it with source='buffer' so the track page can render
    it in a different color.
    """
    if not gps or not gps.get("valid") or not INTERNAL_TOKEN:
        return False
    try:
        payload = {"timestamp": gps.get("fix_time_iso"),
                   "latitude": gps["latitude"],
                   "longitude": gps["longitude"],
                   "speed": gps.get("speed_kn"),
                   "heading": gps.get("true_bearing"),
                   "satellites": gps.get("satellites"),
                   "altitude_m": gps.get("altitude_m")}
        if buffered:
            payload["source"] = "buffer"
        r = requests.post(CONTICINI_BASE + "/internal/boat/position",
                          headers=_conticini_headers(),
                          json=payload,
                          timeout=10)
        r.raise_for_status()
        return r.json().get("saved", False)
    except Exception as exc:
        log.warning("Position POST to conticini failed: %s", exc)
        return False

# --------------------------------------------------------------------------
# KNOT-side GPS buffer replay (points recorded while offline, e.g. sailing
# out of LTE coverage). The KNOT gps-buffer script appends one log line
# "gpsbuf|lat|lon|speed|bearing|sats|date time" every 5 minutes; when the
# tunnel comes back this replay reads the log via REST and POSTs the missing
# points to conticini with source='buffer' (different color on the track).
# The log download is throttled (GPSBUF_POLL_SECONDS) because the log grows
# with every REST login; every read is archived on the server (raw JSON +
# GBUF lines in data/). RouterOS 7 cannot clear /log, so the KNOTs are
# configured with a small memory ring buffer (memory-lines=300) and the
# account topic silenced to keep the log GBUF-only.
# --------------------------------------------------------------------------
_gpsbuf_last_ts = None    # newest gpsbuf line already replayed (log .id time)
_gpsbuf_last_fetch = None # last successful /rest/log download (unix time)
_knot_tunnel_was_up = None  # previous poll's tunnel state (gap detection)
_knot_serial = None  # KNOT board serial (static, read once)
_lte_if_id = ""        # cached lte1 interface .id (changes on KNOT reboot)
_knot_iccid = None     # SIM ICCID (static per SIM, read once)


def _parse_gpsbuf_time(t):
    """Parses '2026-09-26 18:29:58' (log time, KNOT local) into a datetime."""
    try:
        return datetime.strptime(t.strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _gpsbuf_cleanup_archives():
    """Delete raw log archives older than GPSBUF_RETENTION_DAYS days."""
    days = _cfg("GPSBUF_RETENTION_DAYS", GPSBUF_RETENTION_DAYS)
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = GPSBUF_RETENTION_DAYS
    if days <= 0:
        return
    rawdir = os.path.join(os.path.dirname(GPSBUF_ARCHIVE), "knot-log-archive")
    if not os.path.isdir(rawdir):
        return
    cutoff = time.time() - days * 86400
    removed = 0
    for fn in os.listdir(rawdir):
        p = os.path.join(rawdir, fn)
        try:
            if fn.endswith(".json") and os.path.isfile(p) \
                    and os.path.getmtime(p) < cutoff:
                os.unlink(p)
                removed += 1
        except OSError:
            continue
    if removed:
        log.info("KNOT log archive: %d file(s) older than %d day(s) removed",
                 removed, days)


def replay_gps_buffer(force=False):
    """Reads GBUF lines from the KNOT log and replays the new ones.

    The full log download is expensive (it grows with every REST login) so it
    is throttled: it happens on the GPSBUF_POLL_SECONDS cadence, or right
    away after a coverage gap (tunnel was down), or when forced. Every read
    is archived on the server (raw JSON + GBUF lines in data/) before the
    KNOT's ring buffer scrolls on.
    """
    global _gpsbuf_last_ts, _gpsbuf_last_fetch
    now = time.time()
    if not force:
        interval = max(60, _cfg("GPSBUF_POLL_SECONDS", GPSBUF_POLL_SECONDS))
        if _gpsbuf_last_fetch is not None and now - _gpsbuf_last_fetch < interval:
            return
    try:
        r = requests.get(f"http://{KNOT_HOST}/rest/log",
                        auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                        timeout=30)
        r.raise_for_status()
        rows = r.json()
        _gpsbuf_last_fetch = now
        _gpsbuf_cleanup_archives()
        track_lte_resets(rows)
    except Exception as exc:
        log.warning("GPS buffer read failed: %s", exc)
        return
    points = []
    archived = 0
    # keep the full downloaded log on the server (the KNOT one is cleared)
    try:
        os.makedirs(os.path.dirname(GPSBUF_ARCHIVE), exist_ok=True)
        rawdir = os.path.join(os.path.dirname(GPSBUF_ARCHIVE), "knot-log-archive")
        os.makedirs(rawdir, exist_ok=True)
        with open(os.path.join(rawdir,
                              datetime.now().strftime("%Y%m%d-%H%M%S") + ".json"),
                  "w") as rf:
            json.dump(rows, rf)
    except Exception as exc:
        log.warning("KNOT log raw archive failed: %s", exc)
    with open(GPSBUF_ARCHIVE, "a") as af:
        for row in rows:
            msg = row.get("message", "")
            if not msg.startswith("GBUF|"):
                continue
            ts = _parse_gpsbuf_time(row.get("time", ""))
            if ts is None:
                continue
            # archive every line exactly once (same dedup key as replay)
            if _gpsbuf_last_ts is None or ts > _gpsbuf_last_ts:
                af.write(json.dumps({"time": row.get("time", ""),
                                     "message": msg}) + "\n")
                archived += 1
            if _gpsbuf_last_ts is not None and ts <= _gpsbuf_last_ts:
                continue
            parts = msg.split("|")
            if len(parts) < 7:
                continue
            try:
                lat = float(parts[1])
                lon = float(parts[2])
                speed_kmh = float(parts[3].split()[0])
                bearing = float(parts[4].split()[0])
                sats = int(parts[5])
            except (ValueError, IndexError):
                continue
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                continue
            points.append((ts, lat, lon, speed_kmh, bearing, sats))
    # NOTE: RouterOS 7 has no REST/CLI command to clear /log; the memory log is
    # a ring buffer (KNOTs configured with memory-lines=300 and the account
    # topic silenced), so old lines fall off on their own. Everything read is
    # archived on the server before the log scrolls on.
    if not points:
        if archived:
            log.info("GPS buffer: %d line(s) archived, 0 new point(s)", archived)
        return
    points.sort(key=lambda p: p[0])
    sent = 0
    for ts, lat, lon, speed_kmh, bearing, sats in points:
        gps = {"valid": True,
               "latitude": lat,
               "longitude": lon,
               "speed_kn": round(speed_kmh / 1.852, 2),
               "true_bearing": bearing,
               "satellites": sats,
               "altitude_m": None,
               "fix_time_iso": ts.isoformat()}
        if save_position(gps, buffered=True):
            sent += 1
    _gpsbuf_last_ts = points[-1][0]
    log.info("GPS buffer replay: %d point(s) recovered, %d line(s) archived",
             sent, archived)


# --------------------------------------------------------------------------
# Solar production history: samples panel power at every poll (60 s) into
# local SQLite, exposes it via API and builds a forecast from the average
# of previous days curves.
# --------------------------------------------------------------------------
def _solar_db():
    import sqlite3
    d = os.path.dirname(SOLAR_DB)
    if d:
        os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(SOLAR_DB, timeout=10)
    con.execute("CREATE TABLE IF NOT EXISTS solar_samples ("
                "ts TEXT NOT NULL, watt REAL NOT NULL, source TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS load_samples ("
                "ts TEXT NOT NULL, watt REAL NOT NULL, source TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS data_usage ("
               "day TEXT NOT NULL PRIMARY KEY, rx INTEGER NOT NULL, "
               "tx INTEGER NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS outages ("
               "id INTEGER PRIMARY KEY AUTOINCREMENT, "
               "day TEXT NOT NULL, start TEXT NOT NULL, "
               "end TEXT, duration_s INTEGER, source TEXT DEFAULT 'tunnel')")
    # older installs created the table without the source column
    cols = [r[1] for r in con.execute("PRAGMA table_info(outages)")]
    if "source" not in cols:
        con.execute("ALTER TABLE outages ADD COLUMN source TEXT DEFAULT 'tunnel'")
    con.commit()
    return con


def log_solar_sample():
    """Logs a solar power sample (W) from the available source."""
    try:
        watt, source = None, None
        v = _state.get("victron")
        if isinstance(v, dict) and v.get("solar_power_w") is not None:
            watt, source = float(v["solar_power_w"]), "victron"
        else:
            m = _state.get("mppt")
            if isinstance(m, dict):
                if m.get("watt") is not None:
                    watt, source = float(m["watt"]), "mppt"
                elif (m.get("model") == "BL917"
                      and isinstance(m.get("i_charge"), (int, float))
                      and isinstance(m.get("v_bat"), (int, float))):
                    watt, source = round(m["i_charge"] * m["v_bat"], 1), "bl917"
        if watt is None:
            return
        con = _solar_db()
        con.execute("INSERT INTO solar_samples VALUES (?, ?, ?)",
                    (datetime.now().isoformat(timespec="seconds"), watt, source))
        con.commit()
        con.close()
    except Exception as exc:
        log.warning("Solar sample non salvato: %s", exc)


def log_load_sample():
    """Logs a consumption sample (W): i_load * v_bat from the available source."""
    try:
        watt, source = None, None
        v = _state.get("victron")
        if isinstance(v, dict) and isinstance(v.get("i_load"), (int, float)) \
                and isinstance(v.get("v_bat"), (int, float)):
            watt, source = round(float(v["i_load"]) * float(v["v_bat"]), 1), "victron"
        else:
            m = _state.get("mppt")
            if isinstance(m, dict) and m.get("model") == "BL917" \
                    and isinstance(m.get("i_load"), (int, float)) \
                    and isinstance(m.get("v_bat"), (int, float)):
                watt, source = round(float(m["i_load"]) * float(m["v_bat"]), 1), "bl917"
        if watt is None:
            return
        con = _solar_db()
        con.execute("INSERT INTO load_samples VALUES (?, ?, ?)",
                    (datetime.now().isoformat(timespec="seconds"), watt, source))
        con.commit()
        con.close()
    except Exception as exc:
        log.warning("Load sample non salvato: %s", exc)


# --------------------------------------------------------------------------
# SIM data usage: KNOT WireGuard counters -> cumulative per-day deltas
# --------------------------------------------------------------------------
_data_usage_last = None    # (rx, tx) of the last valid sample


def log_data_usage():
    """Samples the KNOT WireGuard peer counters and accumulates the delta.

    Counters reset on KNOT reboot: a negative delta is discarded (the new
    value becomes the base). Each sample costs one REST request in the
    tunnel (~1 KB), at DATA_USAGE_POLL_SECONDS cadence.
    """
    global _data_usage_last
    try:
        r = requests.get(KNOT_WG_URL,
                         auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                         timeout=10)
        r.raise_for_status()
        peers = r.json()
        if not peers:
            _state["data_usage"] = None
            return
        rx, tx = int(peers[0].get("rx", 0)), int(peers[0].get("tx", 0))
        last = _data_usage_last
        _data_usage_last = (rx, tx)
        if last is not None:
            d_rx, d_tx = rx - last[0], tx - last[1]
            if d_rx < 0 or d_tx < 0:
                # contatori azzerati (reboot KNOT): ribasamento, nessun delta
                return
            con = _solar_db()
            today = datetime.now().strftime("%Y-%m-%d")
            con.execute("UPDATE data_usage SET rx = rx + ?, tx = tx + ? "
                        "WHERE day = ?", (d_rx, d_tx, today))
            if con.total_changes == 0:
                con.execute("INSERT INTO data_usage VALUES (?, ?, ?)",
                            (today, d_rx, d_tx))
            con.commit()
            con.close()
    except Exception as exc:
        log.warning("Data usage sample fallito: %s", exc)


def data_usage_loop():
    while True:
        log_data_usage()
        time.sleep(DATA_USAGE_POLL_SECONDS)


def data_usage_summary():
    """Current-month total + statistics for the dashboard card."""
    try:
        con = _solar_db()
        month = datetime.now().strftime("%Y-%m")
        rows = con.execute("SELECT day, rx, tx FROM data_usage "
                           "WHERE day LIKE ? ORDER BY day", (month + "%",)).fetchall()
        con.close()
        budget = DATA_BUDGET_MB * 1024 * 1024
        used = sum(r[1] + r[2] for r in rows)
        days = len(rows)
        now = datetime.now()
# month-end projection based on the average of days with data
        days_in_month = (datetime(now.year + (now.month == 12),
                                  now.month % 12 + 1, 1) - now).days + 1
        avg_day = used / max(days, 1)
        projected = avg_day * days_in_month
        pct = 100 * used / budget if budget else 0
        alert_class = ("bad" if pct >= 90 else
                       "warn" if pct >= 75 else "ok")
        return {
            "used_bytes": used,
            "used_mb": round(used / (1024 * 1024), 1),
            "budget_mb": DATA_BUDGET_MB,
            "pct": round(pct, 1),
            "alert_class": alert_class,
            "days_with_data": days,
            "avg_mb_day": round(avg_day / (1024 * 1024), 1),
            "projected_mb": round(projected / (1024 * 1024), 1),
        }
    except Exception as exc:
        log.warning("Data usage summary fallito: %s", exc)
        return None


def _samples_daily(table):
    """30-min curves from a sample table: today, yesterday, forecast."""
    from datetime import timedelta

    def day_curve(day):
        rows = con.execute(
            "SELECT ts, watt FROM " + table + " WHERE ts LIKE ?", (day + "%",)).fetchall()
        buckets = {}
        for ts, w in rows:
            try:
                idx = int(ts[11:13]) * 2 + (1 if int(ts[14:16]) >= 30 else 0)
            except (ValueError, IndexError):
                continue
            buckets.setdefault(idx, []).append(float(w))
        return [[round(i / 2, 2), round(sum(v) / len(v), 1)]
                for i, v in sorted(buckets.items())]

    def curve_wh(curve):
        return round(sum(w * 0.5 for _, w in curve), 1) if curve else 0.0

    now = datetime.now()
    con = _solar_db()
    try:
        today = day_curve(now.strftime("%Y-%m-%d"))
        yesterday = day_curve((now - timedelta(days=1)).strftime("%Y-%m-%d"))
        past = []
        for k in range(2, 2 + max(1, _cfg("SOLAR_HISTORY_DAYS", 7))):
            c = day_curve((now - timedelta(days=k)).strftime("%Y-%m-%d"))
            if c:
                past.append(c)
        forecast = None
        if past:
            bmap = {}
            for c in past:
                for h, w in c:
                    bmap.setdefault(int(round(h * 2)), []).append(w)
            forecast = [[round(i / 2, 2), round(sum(v) / len(v), 1)]
                        for i, v in sorted(bmap.items())]
        return {
            "today": today, "yesterday": yesterday, "forecast": forecast,
            "today_wh": curve_wh(today), "yesterday_wh": curve_wh(yesterday),
            "history_days": len(past),
        }
    finally:
        con.close()


def solar_daily():
    """Curve di produzione solare: oggi, ieri e previsione (bucket 30 min)."""
    return _samples_daily("solar_samples")


def load_daily():
    """Consumption curves: today, yesterday and forecast (30-min buckets)."""
    return _samples_daily("load_samples")


def _totals():
    """Monthly and yearly totals of production and consumption (kWh)."""
    con = _solar_db()
    try:
        def month_year(table):
            rows = con.execute(
                "SELECT substr(ts,1,7) ym, sum(watt)*60.0/3600000.0 kwh, "
                "count(*) n FROM " + table + " WHERE length(ts)>=10 "
                "GROUP BY substr(ts,1,7) ORDER BY ym").fetchall()
            monthly = [{"month": ym, "kwh": round(kwh, 2), "samples": n} for ym, kwh, n in rows]
            ymap = {}
            for m in monthly:
                y = m["month"][:4]
                ymap.setdefault(y, 0.0)
                ymap[y] += m["kwh"]
            yearly = [{"year": y, "kwh": round(v, 2)} for y, v in sorted(ymap.items())]
            return {"monthly": monthly, "yearly": yearly}
        return {"solar": month_year("solar_samples"),
                "load": month_year("load_samples")}
    finally:
        con.close()


def _monthly_curves():
    """Average daily production curve per month (30-min buckets, W).

    For each month: per-slot mean of each day's average power (so days
    with more samples do not weigh double).
    """
    con = _solar_db()
    try:
        rows = con.execute(
            "SELECT ts, watt FROM solar_samples WHERE length(ts)>=16 "
            "ORDER BY ts").fetchall()
        per_day = {}
        days = {}
        for ts, w in rows:
            try:
                idx = int(ts[11:13]) * 2 + (1 if int(ts[14:16]) >= 30 else 0)
            except (ValueError, IndexError):
                continue
            ym, day = ts[:7], ts[:10]
            per_day.setdefault((ym, day, idx), []).append(float(w))
            days.setdefault(ym, set()).add(day)
        day_means = {}
        for (ym, day, idx), vals in per_day.items():
            day_means.setdefault(ym, {}).setdefault(idx, []).append(
                sum(vals) / len(vals))
        months = []
        for ym, buckets in sorted(day_means.items()):
            curve = [[round(i / 2, 2), round(sum(v) / len(v), 1)]
                     for i, v in sorted(buckets.items())]
            wh = round(sum(w * 0.5 for _, w in curve), 0)
            months.append({
                "month": ym, "days": len(days.get(ym, ())),
                "peak_w": max(w for _, w in curve),
                "total_wh": wh, "curve": curve})
        return {"months": months}
    finally:
        con.close()


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nautilus-telemetry")

# --------------------------------------------------------------------------
# Pure-Python AES-128 (decrypt only, to avoid extra dependencies)
# --------------------------------------------------------------------------
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)
_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gmul(a, b):
    """Multiplication in GF(2^8) (for InvMixColumns)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _expand_key(key):
    """Espansione chiave AES-128: 44 parole da 4 byte."""
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                    # RotWord
            t = [_SBOX[b] for b in t]             # SubWord
            t[0] ^= _RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return w


def _aes_decrypt_block(block, rk):
    """Decrypt di un blocco da 16 byte (state in ordine colonna-major)."""
    s = list(block)

    def addrk(rnd):
        for c in range(4):
            kcol = rk[4 * rnd + c]
            for r in range(4):
                s[4 * c + r] ^= kcol[r]

    def invshift():
        for r in range(1, 4):                    # row r: rotate right by r
            row = [s[4 * c + r] for c in range(4)]
            row = row[-r:] + row[:-r]
            for c in range(4):
                s[4 * c + r] = row[c]

    def invsub():
        for i in range(16):
            s[i] = _INV_SBOX[s[i]]

    def invmix():
        for c in range(4):
            col = [s[4 * c + r] for r in range(4)]
            s[4 * c + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
            s[4 * c + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
            s[4 * c + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
            s[4 * c + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)

    addrk(10)
    for rnd in range(9, 0, -1):
        invshift()
        invsub()
        addrk(rnd)
        invmix()
    invshift()
    invsub()
    addrk(0)
    return bytes(s)


def aes_cbc_decrypt(data, key, iv=b"\x00" * 16):
    """AES-128-CBC decryption (no padding)."""
    rk = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data) - len(data) % 16, 16):
        block = data[i:i + 16]
        dec = _aes_decrypt_block(block, rk)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


# --------------------------------------------------------------------------
# Parser BLE
# --------------------------------------------------------------------------
def parse_bm6(dev):
    """Decodes the BM6 device: iBeacon (voltage) + encrypted frame."""
    out = {
        "name": dev.get("name", "BM6"),
        "mac": dev.get("address", ""),
        "voltage": None,          # V (from iBeacon major/100)
        "major": None,
        "minor": None,
        "uuid": None,
        "soc": None,              # % (frame cifrato)
        "temperature": None,      # °C (frame cifrato)
        "state_code": None,
        "state": None,            # testo
"frame_voltage": None,     # V from the encrypted frame (when populated)
        "rssi": dev.get("rssi"),
        "last_seen": (dev.get("last-seen") or "").split(" ")[-1],
        "raw_adv": dev.get("last-data"),
        "frames": [],
    }

# --- iBeacon: beacon ID ("vehicle finder"), NOT the voltage ---
# Empirically verified: major constant for hours (4428) and an impossible
# value for a 12V battery - not a measurement. The voltage only arrives
# from the encrypted-frame field (bytes 11-12), often 0x0000 (not populated).
    major = dev.get("ibeacon-major")
    if major not in (None, ""):
        try:
            out["major"] = int(major)
            out["frames"].append("ibeacon")
        except ValueError:
            pass
    try:
        out["minor"] = int(dev.get("ibeacon-minor") or 0)
    except ValueError:
        pass
    if dev.get("ibeacon-uuid"):
        out["uuid"] = dev["ibeacon-uuid"]

    # --- frame cifrato AES (service data 0xFFF0) ---
    raw = (dev.get("last-data") or "").lower()
    idx = raw.find(BM6_ADV_MARKER)
    if idx >= 0:
        payload = raw[idx + len(BM6_ADV_MARKER):]
        if len(payload) >= 32:
            try:
                dec = aes_cbc_decrypt(bytes.fromhex(payload[:32]), BM6_KEY)
                out["frames"].append("encrypted")
                mac_hex = out["mac"].replace(":", "").lower()
                if dec[:6].hex() == mac_hex:
                    b = dec
                    temp = b[7]
                    if temp > 100:
# signed byte (two's complement, e.g. 0xF1 -> -15 deg C)
                        temp -= 256
                    elif b[9] == 0x01:
                        # flag di segno negativo (semantica GATT BM6)
                        temp = -temp
                    out["temperature"] = temp
                    out["soc"] = b[8]
                    out["state_code"] = b[10]
                    out["state"] = BM6_STATES.get(b[10], "Unknown (%d)" % b[10])
                    vframe = ((b[11] << 8) | b[12]) / 100.0
                    if vframe > 0:
                        out["frame_voltage"] = round(vframe, 2)
                    log.info("BM6 frame cifrato: temp=%s°C soc=%s%% stato=%s volt_frame=%s",
                             out["temperature"], out["soc"], out["state"],
                             out["frame_voltage"])
                else:
                    log.warning("BM6: MAC nel frame cifrato non corrisponde (%s)", dec[:6].hex())
            except Exception as exc:
                log.warning("BM6: decrypt fallito: %s", exc)
    return out


def parse_mppt(dev):
    """Decodes the Power Queen/Lumiax MPPT (Modbus registers via BLE 0xFFE0).

    The advertisement only carries the 0xFFE0 service + name. The Modbus RTU
    registers (V_pv, V_bat, I_charge — solarlife-mppt-ble-client project) only
    arrive via a GATT connection, which the MikroTik KNOT does not relay: the
    parser stays active with sanity checks should the data be in the payload.
    """
    out = {
        "name": dev.get("name", "MPPT"),
        "mac": dev.get("address", ""),
        "v_pv": None, "v_bat": None, "c_charge": None, "watt": None,
        "adv_name": None,
"telemetry": False,       # True if Modbus registers decoded
        "rssi": dev.get("rssi"),
        "last_seen": (dev.get("last-seen") or "").split(" ")[-1],
        "raw": dev.get("last-data"),
    }

    raw = (dev.get("last-data") or "").lower()
    if not raw:
        return out

    out["has_uart_service"] = MPPT_SERVICE_UART in raw

    # Nome locale (AD type 09): "BT-PQCC2430"
    p = raw.find("0909")
# the name is preceded by an AD with length; looks for the 0x0C 09 length pattern
    if "0c0942542d5051" in raw:  # 0C 09 "BT-PQ"
        try:
            start = raw.index("0c09") + 4
            length = int(raw[raw.index("0c09"):raw.index("0c09") + 2], 16) - 1
            out["adv_name"] = bytes.fromhex(raw[start:start + length * 2]).decode("ascii", "replace")
        except Exception:
            pass

# Encapsulated Modbus registers (if one day present in last-data):
    # byte 0..1 BE /10 = V_pv, byte 2..3 BE /10 = V_bat, byte 4..5 BE /10 = I_carica.
# The Modbus payload does NOT start with standard AD (02 01 06 ...): we look for it
# only in a "naked" hex block of at least 6 bytes with plausible values.
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        data = b""
    if len(data) >= 6 and not data.startswith(b"\x02\x01"):
        v_pv = ((data[0] << 8) | data[1]) / 10.0
        v_bat = ((data[2] << 8) | data[3]) / 10.0
        c_ch = ((data[4] << 8) | data[5]) / 10.0
        # sanity-check (controller 12/24/48V, max ~60V / 30A)
        if 0 < v_pv < 100 and 0 < v_bat < 60 and 0 <= c_ch < 30:
            out.update({
                "v_pv": round(v_pv, 1), "v_bat": round(v_bat, 1),
                "c_charge": round(c_ch, 1), "watt": round(v_bat * c_ch, 1),
                "telemetry": True,
            })
            log.info("MPPT: registri Modbus decodificati: V_pv=%s V_bat=%s I=%s P=%sW",
                     out["v_pv"], out["v_bat"], out["c_charge"], out["watt"])
    return out


# --------------------------------------------------------------------------
# KNOT polling
# --------------------------------------------------------------------------
# Override a runtime (tab Settings):vincolati ai limiti di sicurezza.
# Since v1.17.0 they are PERSISTENT: saved as JSON in the ./data volume and
# reloaded at startup, so they survive a container restart. "Reset all" in the
# Settings page clears them (back to the .env values).
_runtime_cfg = {}    # es. {"POLL_SECONDS": "120"}
_RUNTIME_CFG_FILE = os.path.join(os.path.dirname(SOLAR_DB) or ".",
                                 "runtime_settings.json")


def _runtime_cfg_load():
    """Loads persistent overrides from the volume (if present and valid)."""
    global _runtime_cfg
    try:
        with open(_RUNTIME_CFG_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            _runtime_cfg = {str(k): str(v) for k, v in data.items()}
            log.info("Runtime settings caricate da %s: %s",
                     _RUNTIME_CFG_FILE, sorted(_runtime_cfg))
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.warning("Runtime settings non leggibili (%s): parto dai .env", exc)


def _runtime_cfg_save():
    """Writes the current overrides to disk (silent on failure)."""
    try:
        os.makedirs(os.path.dirname(_RUNTIME_CFG_FILE) or ".", exist_ok=True)
        with open(_RUNTIME_CFG_FILE, "w", encoding="utf-8") as fh:
            json.dump(_runtime_cfg, fh, indent=2)
    except Exception as exc:
        log.warning("Runtime settings non salvate su disco: %s", exc)

def _cfg(name, default):
    if name in _runtime_cfg:
        try:
            return int(_runtime_cfg[name])
        except (TypeError, ValueError):
            pass
    return default


def _poll_seconds():
    h = datetime.now().hour
    night = _cfg("POLL_SECONDS_NIGHT", POLL_SECONDS_NIGHT)
    ns = _cfg("NIGHT_START", NIGHT_START)
    ne = _cfg("NIGHT_END", NIGHT_END)
    if night and (h >= ns or h < ne):
        return max(60, night)
    return max(60, _cfg("POLL_SECONDS", POLL_SECONDS))


def _cfg_snapshot():
    return {
        "POLL_SECONDS": max(60, _cfg("POLL_SECONDS", POLL_SECONDS)),
        "POLL_SECONDS_NIGHT": _cfg("POLL_SECONDS_NIGHT", POLL_SECONDS_NIGHT),
        "NIGHT_START": _cfg("NIGHT_START", NIGHT_START),
        "NIGHT_END": _cfg("NIGHT_END", NIGHT_END),
        "GPS_POLL_SECONDS": max(60, _cfg("GPS_POLL_SECONDS", GPS_POLL_SECONDS)),
        "GATT_POLL_SECONDS": max(60, _cfg("GATT_POLL_SECONDS", GATT_POLL_SECONDS)),
        "GPSBUF_POLL_SECONDS": max(60, _cfg("GPSBUF_POLL_SECONDS", GPSBUF_POLL_SECONDS)),
        "GPSBUF_RETENTION_DAYS": max(0, _cfg("GPSBUF_RETENTION_DAYS", GPSBUF_RETENTION_DAYS)),
        "GBUF_WRITE_SECONDS": max(60, _cfg("GBUF_WRITE_SECONDS", GBUF_WRITE_SECONDS)),
        "STATIONARY_SPEED_KN": _cfg_float("STATIONARY_SPEED_KN", STATIONARY_SPEED_KN),
        "GPS_STATIONARY_INTERVAL": max(30, _cfg("GPS_STATIONARY_INTERVAL", GPS_STATIONARY_INTERVAL)),
        "solar_history_days": max(1, _cfg("SOLAR_HISTORY_DAYS", 7)),
        "BLE_DEVICES": _selected_ble_macs() or [],
        "BLE_NOTES": _ble_notes(),
        "VICTRON_DEVICES": _victron_devices(),
    }


def _cfg_float(name, default):
    if name in _runtime_cfg:
        try:
            return float(_runtime_cfg[name])
        except (TypeError, ValueError):
            pass
    return default


_state = {
    "bm6": None,
    "mppt": None,
    "victron": None,
    "gps": None,
    "updated": None,
    "source_ok": False,
    "last_poll": None,
    "tz_label": None,
    "victron_devices": [],
    "gps_ok": False,
    "error": None,
}
# MAC->.id cache of the KNOT peripherals for per-device GETs (vs the ~12 KB
# full dump, a single GET carries ~270 bytes: 47x less traffic).
# Re-discovered with the full dump every _BLE_ID_RESCAN seconds (ids can
# change after a KNOT reboot).
_ble_id_cache = {}
_ble_id_cache_ts = 0.0
_BLE_ID_RESCAN = 600    # seconds between full-list re-discoveries


def _selected_ble_macs():
    """MACs selected in the Settings page (list = runtime override)."""
    raw = _runtime_cfg.get("BLE_DEVICES")
    if not raw:
        return None
    try:
        macs = json.loads(raw)
        return [str(m).upper() for m in macs if m] or None
    except (ValueError, TypeError):
        return None


def _ble_notes():
    """Note/nomi assegnati ai device BLE (dict MAC→testo, persistente)."""
    raw = _runtime_cfg.get("BLE_NOTES")
    if not raw:
        return {}
    try:
        notes = json.loads(raw)
        return {str(k).upper(): str(v)[:40] for k, v in notes.items()
                if v} if isinstance(notes, dict) else {}
    except (ValueError, TypeError):
        return {}
# Retention of values carried only by some frame types (the KNOT exposes the
# last adv received: the BM6 alternates iBeacon and encrypted frames)
_bm6_keep = {}
_bm6_dev_name = None   # cached BM6 peripheral name (avoids the 10.8 KB dump)
_bm6_dev_id = ""       # cached BM6 peripheral .id (changes on KNOT reboot)


def _bm6_retain(parsed):
    """Keeps SoC/temperature/state from the last valid encrypted frame."""
    global _bm6_keep
    now = datetime.now().strftime("%H:%M:%S")
    for key in ("soc", "temperature", "state", "state_code", "frame_voltage"):
        kept = _bm6_keep.get(key)
        if kept and kept.get("src") == "gatt":
# GATT is the sensor's direct measurement: the adv does not overwrite it
            parsed[key] = kept["value"]
            continue
        v = parsed.get(key)
        if v is not None:
            _bm6_keep[key] = {"value": v, "seen": now}
        elif kept:
            parsed[key] = kept["value"]
    if _bm6_keep:
        parsed["cached_fields_seen"] = _bm6_keep.get("soc", {}).get("seen", now)
# voltage: the GATT read (real) takes precedence over everything;
# then the encrypted frame, else nothing (the major is NOT the voltage)
    vg = _bm6_keep.get("voltage_gatt", {}).get("value")
    if vg is not None:
        parsed["voltage"] = vg
        parsed["voltage_source"] = "gatt"
    elif parsed.get("frame_voltage") is not None:
        parsed["voltage"] = parsed["frame_voltage"]
        parsed["voltage_source"] = "adv-frame"
    parsed["soc_est"] = estimate_soc(parsed.get("voltage"))
    if parsed.get("temperature") is not None and BM6_TEMP_OFFSET:
        parsed["temperature"] = round(parsed["temperature"] + BM6_TEMP_OFFSET)
# BM6 signal: age of the last GATT read (None = never read).
# > 5 min = the sensor is no longer transmitting (KNOT offline, BM6 off or
# busy with another BLE connection).
    seen = _bm6_keep.get("voltage_gatt", {}).get("seen_iso")
    if seen:
        age = (datetime.now() - datetime.fromisoformat(seen)).total_seconds()
        parsed["gatt_age_s"] = int(age)
        parsed["signal_ok"] = age < 300
    else:
        parsed["gatt_age_s"] = None
        parsed["signal_ok"] = None
    return parsed


def fetch_gps():
    """Reads the KNOT GPS (blocking call: invoked by its dedicated thread)."""
    try:
        r = requests.post(
            KNOT_GPS_URL,
            auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
            json={"once": "true"},
            timeout=75,
        )
        r.raise_for_status()
        rows = r.json()
        if rows:
            g = rows[0]
            fix_dt = g.get("date-and-time") or ""
            _state["gps"] = {
                "latitude": float(g["latitude"]),
                "longitude": float(g["longitude"]),
                "valid": g.get("valid") == "true",
                "speed_kmh": float(g.get("speed", "0").split()[0]),
                "speed_kn": round(float(g.get("speed", "0").split()[0]) / 1.852, 2),
                "true_bearing": float(g.get("true-bearing", "0").split()[0]),
                "satellites": int(g.get("satellites", "0")),
                "altitude_m": float(g.get("altitude", "0").split()[0]),
                "fix_time": fix_dt.split(" ")[-1] if fix_dt else "",
# full local timestamp for history (container TZ = boat time, see compose)
                "fix_time_iso": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
            _state["gps_ok"] = True
            _state["gps"]["report_mode"] = (
                "stationary" if _state["gps"]["speed_kn"] < STATIONARY_SPEED_KN
                else "moving")
            if save_position(_state["gps"]):
                log.info("Posizione salvata nello storico: %.6f, %.6f",
                         _state["gps"]["latitude"], _state["gps"]["longitude"])
            log.info("GPS: %.6f, %.6f (%d sat, %.2f kn)",
                     _state["gps"]["latitude"], _state["gps"]["longitude"],
                     _state["gps"]["satellites"], _state["gps"]["speed_kn"])
    except Exception as exc:
        log.warning("Lettura GPS fallita: %s", exc)
        _state["gps_ok"] = False


def gps_loop():
    """Adaptive GPS polling: while stationary (last fix below the speed
    threshold) the blocking KNOT call is skipped entirely until
    GPS_STATIONARY_INTERVAL seconds from the last fix; while moving the
    normal cadence applies. The saving comes from not running the GPS
    monitor (~15-20 s of powered radio) nor the history POST."""
    last_fix_ts = 0.0
    while True:
        stationary_speed = _cfg_float("STATIONARY_SPEED_KN", STATIONARY_SPEED_KN)
        stationary_interval = max(30, _cfg("GPS_STATIONARY_INTERVAL", GPS_STATIONARY_INTERVAL))
        gps = _state.get("gps") or {}
        stationary = (gps.get("valid")
                      and (gps.get("speed_kn") or 99) < stationary_speed)
        now = time.time()
        elapsed = now - last_fix_ts
        if stationary and elapsed < stationary_interval:
# still stationary: re-check every 60 s until the interval expires
            time.sleep(min(60, max(5, stationary_interval - elapsed)))
            continue
        fetch_gps()
        if (_state.get("gps") or {}).get("valid"):
            last_fix_ts = time.time()
        time.sleep(max(60, _cfg("GPS_POLL_SECONDS", GPS_POLL_SECONDS)))


def _gatt_post(path, body):
    r = requests.post(KNOT_GATT + path, auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                      json=body, timeout=40)
    r.raise_for_status()
    return r.json()


def _gatt_get(path):
    r = requests.get(KNOT_GATT + path, auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                     timeout=20)
    r.raise_for_status()
    return r.json()


def fetch_bm6_gatt():
    """Reads real-time data from the BM6 over GATT (RouterOS >= 7.12, central role).

    Keeps the connection persistent: the BM6 sends real-time notifications on
    fff4 only while connected with an active subscription. Reuses an existing
    connection; on the first pass connect + subscribe + write of the command.
    """
    global _bm6_keep
    try:
        conns = _gatt_get("")
        _mac_l = BM6_MAC.lower()
# resolves the peripheral NAME: on RouterOS
# connections the name field may be the device name, not the MAC.
# The full peripheral dump (10.8 KB, every BLE device in range!) is only
# needed for this: cache the name and re-read only when the connection
# lookup fails with the cached name (device renamed / table changed).
        global _bm6_dev_name, _bm6_dev_id
        dev_name = _bm6_dev_name
        conn = None
        if dev_name:
            conn = next((c for c in conns
                        if _mac_l in (c.get("name") or "").lower()
                        or _mac_l in (c.get("pdev") or "").lower()
                        or (dev_name and dev_name in (c.get("name") or "").lower())), None)
        if not dev_name or not conn:
            r0 = requests.get(KNOT_URL, auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS), timeout=15)
            r0.raise_for_status()
            dev = next((d for d in r0.json()
                        if d.get("address", "").upper() == BM6_MAC and d.get("persist") == "true"), None)
            if not dev:
                log.warning("GATT: BM6 non presente nella tabella KNOT")
                return
            dev_name = (dev.get("name") or "").lower()
            _bm6_dev_name = dev_name
            _bm6_dev_id = dev.get(".id") or ""
            conn = next((c for c in conns
                        if _mac_l in (c.get("name") or "").lower()
                        or _mac_l in (c.get("pdev") or "").lower()
                        or (dev_name and dev_name in (c.get("name") or "").lower())), None)
        conn = next((c for c in conns
                     if _mac_l in (c.get("name") or "").lower()
                     or _mac_l in (c.get("pdev") or "").lower()
                     or (dev_name and dev_name in (c.get("name") or "").lower())), None)
        if not conn:
# not connected: connect (some KNOTs want the MAC, others the .id)
            try:
                _gatt_post("/connect", {"pdev": BM6_MAC})
            except Exception:
                if _bm6_dev_id:
                    try:
                        _gatt_post("/connect", {"pdev": _bm6_dev_id})
                    except Exception:
                        pass   # already connected with another identifier: retry the match
            time.sleep(2)
            conns = _gatt_get("")
            conn = next((c for c in conns
                         if _mac_l in (c.get("name") or "").lower()
                         or _mac_l in (c.get("pdev") or "").lower()
                         or (dev_name and dev_name in (c.get("name") or "").lower())), None)
            if not conn:
                log.warning("GATT: connect BM6 riuscito ma connessione assente")
                return
        pdev = conn.get("pdev") or conn["name"]
# (re)enables notifications and re-issues the real-time command: idempotent
        _gatt_post("/subscribe", {"pdev": pdev, "uuid": "fff4"})
        _gatt_post("/write", {"pdev": pdev, "uuid": "fff3", "data-hex": BM6_GATT_CMD})
        time.sleep(3)
        raw = requests.get(KNOT_GATT + "/async-data",
                           auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS), timeout=20)
        raw.raise_for_status()
        text = raw.content.decode("utf-8", "replace")
        import re as _re
# BM6 notifications (fff4): decrypt, keep the last valid one with voltage
        last = None
        for entry in _re.findall(r"\{[^{}]*\}", text):
            if '"uuid":"fff4"' not in entry:
                continue
            mh = _re.search(r'"data-hex":"([0-9A-Fa-f]+)"', entry)
            if not mh or len(mh.group(1)) < 32:
                continue
            try:
                dec = aes_cbc_decrypt(bytes.fromhex(mh.group(1)[:32]), BM6_KEY).hex()
            except Exception:
                continue
            if dec.startswith("d15507"):
                b = bytes.fromhex(dec)
                if ((b[7] << 8) | b[8]) > 0:
                    last = b
        if last is not None:
            temp = -last[4] if last[3] == 1 else last[4]
            state = last[5]
            soc = last[6]
            volt = ((last[7] << 8) | last[8]) / 100.0
            now = datetime.now().strftime("%H:%M:%S")
            _bm6_keep["voltage_gatt"] = {"value": round(volt, 2), "seen": now,
                                         "seen_iso": datetime.now().isoformat(timespec="seconds")}
            for k, v in (("soc", soc), ("temperature", temp),
                        ("state", BM6_STATES.get(state, "Unknown (%d)" % state)),
                        ("state_code", state)):
                _bm6_keep[k] = {"value": v, "seen": now, "src": "gatt"}
            log.info("BM6 GATT: %.2fV %s°C SoC %s%% stato %s", volt, temp, soc,
                     BM6_STATES.get(state, state))
        else:
            log.info("BM6 GATT: nessuna notifica con voltaggio nel buffer")
    except Exception as exc:
        log.warning("GATT BM6 fallito: %s", exc)


def fetch_bl917():
    """Queries the ZhiJinPower cloud for BL917 data.

    No authentication: only the MAC. If the controller was never registered
    through the app, the cloud answers with empty data → 'registered': False.
    """
    try:
        import asyncio
        import websockets

        async def _fetch():
            async with websockets.connect(BL917_WS, open_timeout=10) as ws:
                try:
                    await asyncio.wait_for(ws.recv(), timeout=8)   # welcome
                except asyncio.TimeoutError:
                    pass
                out = {}
                for action in ("getMachinInfoOne", "getMachinInfoTwo"):
                    await ws.send(json.dumps({"Action": action, "mac": BL917_MAC}))
                    r = await asyncio.wait_for(ws.recv(), timeout=15)
                    d = json.loads(r)
                    for p in d.get("data", []):
                        out[p.get("unikey")] = p.get("value")
                return out

        data = asyncio.run(_fetch())
        if not data:
            log.info("BL917: cloud senza dati (controller spento o non registrato)")
            _state["mppt"] = {
                "model": "BL917", "registered": False,
                "note": "Controller not registered on the ZhiJinPower cloud: "
                        "open the ZhiJinPower app once with the controller powered on.",
            }
            return
# voltage sanity check (12 V nominal)
        vbat = data.get("dianya")
        try:
            vbat = float(vbat)
        except (TypeError, ValueError):
            vbat = None
        _state["mppt"] = {
            "model": "BL917", "registered": True,
            "v_bat": vbat,
            "i_charge": data.get("cddl"),
            "i_load": data.get("fddl"),
            "temperature": (lambda t: round(t + BL917_TEMP_OFFSET) if isinstance(t, (int, float)) else t)(
                data.get("temperature")),
            "solar_active": data.get("solar_status") == 1,
            "load_active": data.get("work_status") == 1,
            "total_kwh": data.get("total_power"),
            "battery_type": {"1": "Lithium", "2": "Gel", "3": "Lead-acid",
                             "6": "LiFePO4"}.get(str(data.get("battery_type")), None),
            "charge_mode": {0: "Manual", 1: "Auto", 2: "Timed", 3: "Straight out"}.get(
                data.get("output_mode"), None),
            "raw": {k: v for k, v in data.items() if k in
                    ("dianya", "cddl", "fddl", "temperature", "total_power")},
        }
        log.info("BL917: V=%s I_c=%s T=%s kWh=%s", vbat, data.get("cddl"),
                 data.get("temperature"), data.get("total_power"))
    except Exception as exc:
        log.warning("Lettura BL917 fallita: %s", exc)


def bl917_loop():
    while True:
        fetch_bl917()
        time.sleep(BL917_POLL_SECONDS)


def gatt_loop():
    while True:
        fetch_bm6_gatt()
        time.sleep(max(60, _cfg("GATT_POLL_SECONDS", GATT_POLL_SECONDS)))


def fetch_lte():
    """Reads the KNOT LTE signal quality (fast, non-blocking request).

    Uses the cached LTE interface .id (re-read only after a failure, e.g.
    after a KNOT reboot) and queries the monitor for RSRP/RSRQ/SINR/RSSI.
    """
    global _lte_if_id
    try:
        global _lte_if_id
        lte_id = _lte_if_id
        if not lte_id:
            r = requests.get(
                f"http://{KNOT_HOST}/rest/interface/lte",
                auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                timeout=10,
            )
            r.raise_for_status()
            rows = r.json()
            if not rows:
                _state["lte"] = None
                return
            lte_id = rows[0][".id"]
            _lte_if_id = lte_id
        r = requests.post(
            KNOT_LTE_URL,
            auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
            json={".id": lte_id, "once": ""},
            timeout=15,
        )
        r.raise_for_status()
        m = r.json()[0]

        def _num(key):
            try:
                return float(str(m.get(key, "")).split()[0])
            except (ValueError, IndexError):
                return None

        rsrp = _num("rsrp")
        # Soglie RSRP LTE (dBm): > -80 ottimo, > -95 buono, > -110 sufficiente
        if rsrp is None:
            quality, quality_class = "n/a", "idle"
        elif rsrp >= -80:
            quality, quality_class = "Excellent", "ok"
        elif rsrp >= -95:
            quality, quality_class = "Good", "ok"
        elif rsrp >= -110:
            quality, quality_class = "Weak", "warn"
        else:
            quality, quality_class = "Poor", "bad"

        _state["lte"] = {
            "operator": m.get("current-operator", "—"),
            "band": (m.get("primary-band") or "—").split("@")[0],
            "band_detail": m.get("primary-band", "—"),
            "rsrp": rsrp,
            "rsrq": _num("rsrq"),
            "sinr": _num("sinr"),
            "rssi": _num("rssi"),
            "roaming": m.get("roaming") == "true",
            "cellid": m.get("current-cellid", "—"),
            "quality": quality,
            "quality_class": quality_class,
            "session_uptime": m.get("session-uptime", "—"),
        }
    except Exception as exc:
        log.warning("Lettura LTE fallita: %s", exc)
        _state["lte"] = None
        # the cached .id may be stale (KNOT reboot): force a re-read next time
        _lte_if_id = ""


def fetch_knot_status():
    """WireGuard tunnel and KNOT status (for the "Knot status" card).

    Reads the peer's last-handshake towards the relay and the router uptime:
    if the handshake is older than KNOT_TUNNEL_STALE_S seconds the tunnel is
    considered down (dashboard alarm). rx/tx counters and current endpoint
    for remote diagnostics.
    """
    try:
        r = requests.get(
            f"http://{KNOT_HOST}/rest/interface/wireguard/peers",
            auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
            timeout=10,
        )
        r.raise_for_status()
        peers = r.json()
        if not peers:
            _state["knot_status"] = None
            return
        p = peers[0]

        def _to_secs(s):
            total = 0
            for num, unit in re.findall(r"(\d+)([smhdw])", str(s or "")):
                total += int(num) * {"s": 1, "m": 60, "h": 3600,
                                     "d": 86400, "w": 604800}[unit]
            return total

        hs_age = _to_secs(p.get("last-handshake"))
        r2 = requests.get(
            f"http://{KNOT_HOST}/rest/system/resource",
            auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
            timeout=10,
        )
        res = r2.json()
        # board serial number: static, read once per process lifetime
        global _knot_serial
        if _knot_serial is None:
            try:
                r3 = requests.get(
                    f"http://{KNOT_HOST}/rest/system/routerboard",
                    auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                    timeout=10)
                _knot_serial = r3.json().get("serial-number", "") or ""
            except Exception:
                _knot_serial = ""
        # SIM info: ICCID is static per SIM - read once per process.
        # Operator/band change but are already fetched by fetch_lte.
        global _knot_iccid
        if _knot_iccid is None:
            try:
                r4 = requests.post(
                    f"http://{KNOT_HOST}/rest/interface/lte/monitor",
                    json={"numbers": "lte1", "once": ""},
                    auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                    timeout=15)
                m = (r4.json() or [{}])[0]
                _knot_iccid = m.get("iccid") or ""
            except Exception:
                _knot_iccid = ""
        iccid = _knot_iccid or None
        lte_state = _state.get("lte") or {}
        operator = lte_state.get("operator") or None
        band = lte_state.get("band") or None
        uptime = res.get("uptime", "")
        try:
            cpu_load = int(res.get("cpu-load", 0))
        except (TypeError, ValueError):
            cpu_load = None
        try:
            free_mem = int(res.get("free-memory", 0))
            total_mem = int(res.get("total-memory", 0))
        except (TypeError, ValueError):
            free_mem = total_mem = None
        try:
            free_hdd = int(res.get("free-hdd-space", 0))
            total_hdd = int(res.get("total-hdd-space", 0))
        except (TypeError, ValueError):
            free_hdd = total_hdd = None
        _state["knot_status"] = {
            "handshake_age_s": hs_age,
            "handshake_raw": p.get("last-handshake", ""),
            "tunnel_up": hs_age is not None and hs_age <= KNOT_TUNNEL_STALE_S,
            "stale_after_s": KNOT_TUNNEL_STALE_S,
            "rx_bytes": int(p.get("rx", 0) or 0),
            "tx_bytes": int(p.get("tx", 0) or 0),
            "endpoint": p.get("current-endpoint-address", ""),
            "uptime": uptime,
            "version": res.get("version", ""),
            "cpu_load": cpu_load,
            "serial": _knot_serial,
            "iccid": iccid,
            "operator": operator,
            "band": band,
            "free_memory": free_mem,
            "total_memory": total_mem,
            "free_hdd": free_hdd,
            "total_hdd": total_hdd,
        }
    except Exception as exc:
        log.warning("Knot status fallito: %s", exc)
        _state["knot_status"] = None


def fetch_devices():
    """Fetches the peripheral devices from the KNOT (persist=true only).

    With an active BLE selection (Settings page) it fetches only the selected
    devices via per-device GETs (MAC->.id cache, periodic re-discovery),
    cutting the poll's tunnel traffic by ~70% vs the full dump.
    """
    global VICTRON_ADV_KEY, _ble_id_cache, _ble_id_cache_ts
    try:
        selected = _selected_ble_macs()
        devices = None
        if selected:
# periodic .id re-discovery (they change on KNOT reboot)
            now = time.time()
            if now - _ble_id_cache_ts > _BLE_ID_RESCAN or \
                    not all(m in _ble_id_cache for m in selected):
                r = requests.get(
                    KNOT_URL,
                    auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                    timeout=10,
                )
                r.raise_for_status()
                _ble_id_cache = {d.get("address", "").upper(): d[".id"]
                                 for d in r.json() if d.get(".id")}
                _ble_id_cache_ts = now
            devices = []
            for m in selected:
                dev_id = _ble_id_cache.get(m)
                if not dev_id:
                    continue    # not (anymore) seen by the KNOT
                r = requests.get(
                    f"{KNOT_URL}/{dev_id}",
                    auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                    timeout=10,
                )
                if r.status_code == 200:
                    devices.append(r.json())
# per-device GETs do not carry the persist field: selected devices
# are by definition the wanted ones
            by_mac = {d.get("address", "").upper(): d for d in devices}
        else:
            r = requests.get(
                KNOT_URL,
                auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
                timeout=10,
            )
            r.raise_for_status()
            devices = [d for d in r.json() if d.get("persist") == "true"]
            by_mac = {d.get("address", "").upper(): d for d in devices}
        if BM6_MAC in by_mac:
            _state["bm6"] = _bm6_retain(parse_bm6(by_mac[BM6_MAC]))
        else:
            _state["bm6"] = None
# with BL917 enabled the MPPT data arrives from the cloud thread:
# do not overwrite it with the BLE parser (same MAC, same device)
        if not BL917_ENABLED:
            _state["mppt"] = parse_mppt(by_mac[MPPT_MAC]) if MPPT_MAC in by_mac else None
        # Victron SmartSolar: advertisement cifrato, decodifica diretta.
# The KNOT may not have it in the persistent table: search ALL seen
# devices for the 0x02E1 manufacturer-data marker.
        vdevs = _victron_devices()
        _state["victron_devices"] = []
        for vcfg in vdevs:
            dev = by_mac.get(vcfg["mac"])
            if not dev:
                _state["victron_devices"].append(
                    {"mac": vcfg["mac"], "error": "not seen by the KNOT"})
                continue
            key = vcfg["key"]
            parsed = parse_victron(dev, key) if key else {"error": "advertisement key not set"}
            if (parsed.get("error") == "advertisement key mismatch (key-check byte)"
                    and vcfg["serial"] and vcfg["puk"]):
# try to derive the key from serial+PUK and lock in the valid one
                for cand in _victron_derive_key(vcfg["serial"], vcfg["puk"]):
                    try:
                        trial = parse_victron(dev, cand)
                    except Exception:
                        continue
                    if not trial.get("error"):
                        log.info("Victron %s: key derived from serial+PUK",
                                 vcfg["mac"])
                        parsed = trial
                        _victron_store_key(vcfg["mac"], cand)
                        break
            _state["victron_devices"].append(parsed)
        # legacy single-device field kept for the MPPT card
        _state["victron"] = next(
            (p for p in _state["victron_devices"]
             if p.get("model") == "SmartSolar" and not p.get("error")), None) \
            if _state["victron_devices"] else None
        _state["source_ok"] = True
        _state["error"] = None
    except Exception as exc:
        log.error("Polling KNOT fallito: %s", exc)
        _state["source_ok"] = False
        _state["error"] = str(exc)
    finally:
        _state["last_poll"] = datetime.now().strftime("%H:%M:%S")
        _state["updated"] = datetime.now().isoformat(timespec="seconds")
        # timezone label shown next to every clock time in the UI
        _state["tz_label"] = datetime.now().astimezone().strftime("UTC%z")


def track_outage(tunnel_up):
    """Records coverage gaps (tunnel down) into the outages table.

    Opens a row when the tunnel goes down, closes it when it comes back.
    An outage still open at midnight keeps running until recovery.
    """
    try:
        con = _solar_db()
        now = datetime.now()
        row = con.execute(
            "SELECT id, start FROM outages WHERE end IS NULL "
            "ORDER BY id DESC LIMIT 1").fetchone()
        if not tunnel_up and row is None:
            con.execute(
                "INSERT INTO outages (day, start) VALUES (?, ?)",
                (now.date().isoformat(), now.isoformat(timespec="seconds")))
            con.commit()
            log.info("Coverage gap started at %s", now.strftime("%H:%M:%S"))
        elif tunnel_up and row is not None:
            start = datetime.fromisoformat(row[1])
            con.execute(
                "UPDATE outages SET end = ?, duration_s = ? WHERE id = ?",
                (now.isoformat(timespec="seconds"),
                 int((now - start).total_seconds()), row[0]))
            con.commit()
            log.info("Coverage gap ended: %s s", int((now - start).total_seconds()))
        con.close()
    except Exception as exc:
        log.warning("Outage tracking failed: %s", exc)


def track_lte_resets(rows):
    """Records LTE resets from the KNOT log rows as short outages.

    The KNOT logs 'lte1 forced reconfiguration...' (lte,error) when the link
    drops and 'lte1 IPv4: ...' (lte,info) when it is back. These gaps are
    1-2 minutes long - shorter than the poll cadence - so the tunnel-based
    tracker would miss them. Deduplicated on start time across downloads.
    """
    try:
        events = []
        for row in rows:
            msg = row.get("message", "")
            t = row.get("time", "")
            if "forced reconfiguration" in msg:
                events.append((t, msg, "start"))
            elif msg.startswith("lte1 IPv4"):
                events.append((t, msg, "end"))
        if not events:
            return
        con = _solar_db()
        known = {r[0] for r in con.execute(
            "SELECT start FROM outages WHERE source = 'lte'")}
        open_start = None
        for t, msg, kind in events:
            if kind == "start":
                if t not in known:
                    day = t[:10] if len(t) >= 10 else datetime.now().date().isoformat()
                    con.execute(
                        "INSERT INTO outages (day, start, source) VALUES (?, ?, 'lte')",
                        (day, t))
                    known.add(t)
                    log.info("LTE reset recorded at %s", t)
                open_start = t
            elif kind == "end" and open_start is not None:
                try:
                    start_dt = datetime.fromisoformat(open_start)
                    end_dt = datetime.fromisoformat(t)
                    duration = int((end_dt - start_dt).total_seconds())
                    if duration < 0:
                        duration = 0
                except ValueError:
                    duration = None
                if duration is not None:
                    con.execute(
                        "UPDATE outages SET end = ?, duration_s = ? "
                        "WHERE start = ? AND source = 'lte' AND end IS NULL",
                        (t, duration, open_start))
                open_start = None
        con.commit()
        con.close()
    except Exception as exc:
        log.warning("LTE reset tracking failed: %s", exc)


def outage_summary():
    """Today's and yesterday's outage count + total seconds, last 7 days."""
    try:
        con = _solar_db()
        out = {"today": {"count": 0, "seconds": 0},
               "yesterday": {"count": 0, "seconds": 0}, "week": []}
        today = datetime.now().date()
        for i, label in ((0, "today"), (1, "yesterday")):
            day = (today - timedelta(days=i)).isoformat()
            row = con.execute(
                "SELECT COUNT(*), COALESCE(SUM(duration_s), 0) FROM outages "
                "WHERE day = ?", (day,)).fetchone()
            out[label] = {"count": row[0], "seconds": int(row[1] or 0)}
        # last 7 days for the mini history
        for i in range(6, -1, -1):
            day = (today - timedelta(days=i)).isoformat()
            row = con.execute(
                "SELECT COUNT(*), COALESCE(SUM(duration_s), 0) FROM outages "
                "WHERE day = ?", (day,)).fetchone()
            out["week"].append({"day": day, "count": row[0],
                                "seconds": int(row[1] or 0)})
        # last completed gap
        row = con.execute("SELECT start, duration_s FROM outages "
                          "WHERE end IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            out["last"] = {"start": row[0], "duration_s": int(row[1] or 0),
                           "today": row[0][:10] == today.isoformat()}
        # currently open gap?
        row = con.execute("SELECT start FROM outages WHERE end IS NULL "
                         "ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            out["open_since"] = row[0]
        con.close()
        return out
    except Exception as exc:
        log.warning("Outage summary failed: %s", exc)
        return {"today": {"count": 0, "seconds": 0},
                "yesterday": {"count": 0, "seconds": 0}, "week": [],
                "error": str(exc)}


def poll_loop():
    global _knot_tunnel_was_up
    while True:
        fetch_devices()
        log_solar_sample()
        log_load_sample()
        fetch_lte()
        fetch_knot_status()
        # replay KNOT-side buffered GPS points only when the tunnel is alive;
        # force a read right after a coverage gap (tunnel came back up)
        tunnel_up = (_state.get("knot_status") or {}).get("tunnel_up")
        track_outage(bool(tunnel_up))
        if tunnel_up:
            replay_gps_buffer(force=not _knot_tunnel_was_up)
        _knot_tunnel_was_up = bool(tunnel_up)
        time.sleep(_poll_seconds())


# --------------------------------------------------------------------------
# Interfaccia web (Flask)
# --------------------------------------------------------------------------
app = Flask(__name__)

# alternative URL prefix for the dashboard (default: /nautilus)
URL_PREFIX_ALIAS = os.environ.get("URL_PREFIX_ALIAS") or "/nautilus"
# boat name shown in the dashboard
BOAT_NAME = os.environ.get("BOAT_NAME", "Nautilus")
VERSION = "1.35.0"


@app.route("/api/data")
@app.route("/nautilus/api/data")
@app.route(URL_PREFIX_ALIAS + "/api/data")
def api_data():
    _state["version"] = VERSION
    _state["data_usage"] = data_usage_summary()
    _state["outages"] = outage_summary()
    return jsonify(_state)


@app.route("/")
@app.route("/nautilus/")
@app.route("/nautilus")
@app.route(URL_PREFIX_ALIAS + "/")
@app.route(URL_PREFIX_ALIAS)
def dashboard():
    return (DASHBOARD_HTML
            .replace("{{BOAT}}", BOAT_NAME)
            .replace("__DU_POLL_MIN__", str(max(1, DATA_USAGE_POLL_SECONDS // 60))))


# --------------------------------------------------------------------------
# Boat track history route (positions stored in the conticini DB)
# --------------------------------------------------------------------------

@app.route("/api/boat/track-history")
@app.route("/nautilus/api/boat/track-history")
@app.route(URL_PREFIX_ALIAS + "/api/boat/track-history")
def api_track_history():
    """Boat track history (proxy to the conticini history backend).

    Filters: ?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD  or  ?last=N
    """
    if not INTERNAL_TOKEN:
        return jsonify({"error": "track history not configured (INTERNAL_TOKEN missing)"}), 503
    qs = request.query_string.decode()
    try:
        r = requests.get(CONTICINI_BASE + "/internal/boat/track-history" + ("?" + qs if qs else ""),
                         headers=_conticini_headers(), timeout=15)
        return jsonify(r.json()), r.status_code
    except Exception as exc:
        log.warning("track-history (proxy conticini): %s", exc)
        return jsonify({"error": "track history unavailable"}), 503


@app.route("/api/boat/track.kml")
@app.route("/nautilus/api/boat/track.kml")
@app.route(URL_PREFIX_ALIAS + "/api/boat/track.kml")
def api_track_kml():
    """Track history as KML for Google Earth (same filters as track-history).

    Live track renders as a blue LineString, buffered 'no coverage' points
    as an orange one, so gaps while out of coverage are visible in Earth.
    """
    if not INTERNAL_TOKEN:
        return jsonify({"error": "track history not configured"}), 503
    qs = request.query_string.decode()
    try:
        r = requests.get(CONTICINI_BASE + "/internal/boat/track-history"
                         + ("?" + qs if qs else ""),
                         headers=_conticini_headers(), timeout=15)
        points = (r.json() or {}).get("points", [])
    except Exception as exc:
        log.warning("track.kml (proxy conticini): %s", exc)
        return jsonify({"error": "track history unavailable"}), 503

    def _placemark(name, color_kml, coords):
        return ("<Placemark><name>%s</name><Style><LineStyle>"
                "<color>%s</color><width>3</width></LineStyle></Style>"
                "<LineString><tessellate>1</tessellate><coordinates>%s"
                "</coordinates></LineString></Placemark>"
                % (name, color_kml, " ".join(coords)))

    # KML colors are aabbggrr
    live_coords, buffer_coords = [], []
    for p in points:
        coord = "%.6f,%.6f" % (p["longitude"], p["latitude"])
        live_coords.append(coord)
        if p.get("source") == "buffer":
            buffer_coords.append(coord)
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<kml xmlns="http://www.opengis.net/kml/2.2">',
             "<Document><name>%s track</name>" % BOAT_NAME]
    if live_coords:
        parts.append(_placemark("Track (live)", "ff38bdf8", live_coords))
    if buffer_coords:
        parts.append(_placemark("No-coverage points", "fffc9a2f", buffer_coords))
    parts.append("</Document></kml>")
    body = "\n".join(parts)
    return Response(body, mimetype="application/vnd.google-earth.kml+xml",
                    headers={"Content-Disposition":
                             "attachment; filename=track.kml"})


@app.route("/api/solar/daily")
@app.route("/nautilus/api/solar/daily")
@app.route(URL_PREFIX_ALIAS + "/api/solar/daily")
def api_solar_daily():
    """Curve di produzione solare: oggi, ieri e previsione (bucket 30 min)."""
    try:
        return jsonify(solar_daily())
    except Exception as exc:
        log.warning("solar daily: %s", exc)
        return jsonify({"error": "solar history unavailable"}), 503

@app.route("/api/load/daily")
@app.route("/nautilus/api/load/daily")
@app.route(URL_PREFIX_ALIAS + "/api/load/daily")
def api_load_daily():
    """Consumption curves: today, yesterday and forecast (30-min buckets)."""
    try:
        return jsonify(load_daily())
    except Exception as exc:
        log.warning("load daily: %s", exc)
        return jsonify({"error": "load history unavailable"}), 503


@app.route("/api/knot/logs")
@app.route("/nautilus/api/knot/logs")
@app.route(URL_PREFIX_ALIAS + "/api/knot/logs")
def api_knot_logs():
    """KNOT log archives (see replay_gps_buffer: every /rest/log download is
    archived on the server).

    GET without params: list of archived files with size/count.
    ?file=<name>: content of one archive (raw JSON rows, capped).
    ?gbuf: last N GBUF lines from data/gpsbuf-archive.log (?gbuf=50 default,
    max 500), newest last.
    """
    try:
        if "gbuf" in request.args:
            try:
                n = min(500, max(1, int(request.args.get("gbuf", 50))))
            except ValueError:
                n = 50
            out = []
            if os.path.exists(GPSBUF_ARCHIVE):
                with open(GPSBUF_ARCHIVE, "r") as f:
                    lines = [l for l in f.read().splitlines() if l.strip()]
                for l in lines[-n:]:
                    try:
                        out.append(json.loads(l))
                    except ValueError:
                        continue
            return jsonify({"count": len(out), "lines": out})
        if "file" in request.args:
            name = os.path.basename(request.args.get("file", ""))
            if not name or not name.endswith(".json"):
                return jsonify({"error": "invalid file"}), 400
            path = os.path.join(os.path.dirname(GPSBUF_ARCHIVE),
                                "knot-log-archive", name)
            if not os.path.isfile(path):
                return jsonify({"error": "not found"}), 404
            with open(path, "r") as f:
                rows = json.load(f)
            return jsonify({"file": name, "count": len(rows), "rows": rows})
        rawdir = os.path.join(os.path.dirname(GPSBUF_ARCHIVE),
                              "knot-log-archive")
        files = []
        if os.path.isdir(rawdir):
            for fn in sorted(os.listdir(rawdir), reverse=True):
                p = os.path.join(rawdir, fn)
                if fn.endswith(".json") and os.path.isfile(p):
                    files.append({"file": fn,
                                  "size": os.path.getsize(p),
                                  "mtime": datetime.fromtimestamp(
                                      os.path.getmtime(p)).isoformat(
                                          timespec="seconds")})
        return jsonify({"count": len(files), "files": files})
    except Exception as exc:
        log.warning("knot logs api: %s", exc)
        return jsonify({"error": "unavailable"}), 503


@app.route("/api/settings")
@app.route("/nautilus/api/settings")
@app.route(URL_PREFIX_ALIAS + "/api/settings")
def api_settings_get():
    return jsonify(_cfg_snapshot())


@app.route("/api/ble/devices")
@app.route("/nautilus/api/ble/devices")
@app.route(URL_PREFIX_ALIAS + "/api/ble/devices")
def api_ble_devices():
    """List of ALL BLE devices seen by the KNOT, for the Settings selection.

    Also refreshes the MAC->.id cache used by per-device GETs. A device
    appears here even if not persistent (that is the page's purpose).
    """
    global _ble_id_cache, _ble_id_cache_ts
    try:
        r = requests.get(
            KNOT_URL,
            auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS),
            timeout=10,
        )
        r.raise_for_status()
        rows = r.json()
        _ble_id_cache = {d.get("address", "").upper(): d[".id"]
                         for d in rows if d.get(".id")}
        _ble_id_cache_ts = time.time()
        out = []
        notes = _ble_notes()
        for d in rows:
            mac = d.get("address", "")
            try:
                rssi = int(str(d.get("rssi", "-999") or "-999"))
            except ValueError:
                rssi = -999
            out.append({
                "id": d.get(".id"),
                "mac": mac,
                "name": d.get("name", "") or "",
                "note": notes.get(mac.upper(), ""),
                "persist": d.get("persist") == "true",
                "rssi": rssi if rssi != -999 else None,
                "last_seen": d.get("last-seen", ""),
            })
# sort order: descending RSSI (strongest signal first), devices no longer
# transmitting (missing rssi) last, then by name
        out.sort(key=lambda x: (-(x["rssi"] if x["rssi"] is not None else -999),
                                str(x["name"]).lower()))
        return jsonify({"devices": out,
                        "selected": _selected_ble_macs() or []})
    except Exception as exc:
        return jsonify({"error": "KNOT unreachable: %s" % exc}), 503


@app.route("/api/settings", methods=["POST"])
@app.route("/nautilus/api/settings", methods=["POST"])
@app.route(URL_PREFIX_ALIAS + "/api/settings", methods=["POST"])
def api_settings_post():
    """Runtime override of poll parameters (Settings tab).
    Out-of-range values are rejected; null clears the override."""
    body = request.get_json(silent=True) or {}
    limits = {
        "POLL_SECONDS": (60, 3600),
        "POLL_SECONDS_NIGHT": (0, 3600),
        "GPS_POLL_SECONDS": (60, 3600),
        "GATT_POLL_SECONDS": (60, 3600),
        "GPSBUF_POLL_SECONDS": (60, 86400),
        "GPSBUF_RETENTION_DAYS": (0, 3650),
        "GBUF_WRITE_SECONDS": (60, 3600),
        "STATIONARY_SPEED_KN": (0.0, 20.0),
        "GPS_STATIONARY_INTERVAL": (30, 7200),
        "SOLAR_HISTORY_DAYS": (1, 30),
        "NIGHT_START": (0, 23),
        "NIGHT_END": (0, 23),
    }
    for k, v in body.items():
        if k == "VICTRON_DEVICES":
# list of {mac, key, serial, puk} - editable in Settings, null clears
            import re as _vre
            if v is None or v == []:
                _runtime_cfg.pop("VICTRON_DEVICES", None)
            elif isinstance(v, list) and v:
                clean = []
                for it in v:
                    if not isinstance(it, dict) or not it.get("mac"):
                        return jsonify({"error": "VICTRON_DEVICES: mac required"}), 400
                    mac = str(it["mac"]).upper()
                    if not _vre.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", mac):
                        return jsonify({"error": "VICTRON_DEVICES: invalid MAC " + mac}), 400
                    clean.append({
                        "mac": mac,
                        "key": str(it.get("key", "") or "").lower()[:40],
                        "serial": str(it.get("serial", "") or "")[:30],
                        "puk": str(it.get("puk", "") or "")[:30],
                        "bt_pin": str(it.get("bt_pin", "") or "")[:12],
                        "part_number": str(it.get("part_number", "") or "")[:40],
                    })
                _runtime_cfg["VICTRON_DEVICES"] = json.dumps(clean)
            else:
                return jsonify({"error": "VICTRON_DEVICES must be a list"}), 400
            log.info("Victron devices aggiornati: %s",
                     [d["mac"] for d in json.loads(_runtime_cfg["VICTRON_DEVICES"])])
            _runtime_cfg_save()
            continue
        if k == "BLE_NOTES":
# notes/names per MAC: {MAC: text} dict, null clears
            if v is None or v == {}:
                _runtime_cfg.pop("BLE_NOTES", None)
            elif isinstance(v, dict) and all(isinstance(m, str) for m in v.keys()):
                _runtime_cfg["BLE_NOTES"] = json.dumps(
                    {m.upper(): str(t)[:40] for m, t in v.items() if t})
            else:
                return jsonify({"error": "BLE_NOTES must be an object MAC-to-note"}), 400
            log.info("Note BLE aggiornate: %s", _runtime_cfg.get("BLE_NOTES"))
            _runtime_cfg_save()
            continue
        if k == "BLE_DEVICES":
            # lista di MAC selezionati; null/[] = nessuna selezione (dump pieno)
            if v is None or (isinstance(v, list) and not v):
                _runtime_cfg.pop("BLE_DEVICES", None)
            elif isinstance(v, list) and all(isinstance(m, str) for m in v) and v:
                import re as _re
                if not all(_re.fullmatch(r"[0-9A-Fa-f:]{2,20}", m) for m in v):
                    return jsonify({"error": "BLE_DEVICES: invalid MAC"}), 400
                _runtime_cfg["BLE_DEVICES"] = json.dumps(
                    [m.upper() for m in v])
            else:
                return jsonify({"error": "BLE_DEVICES must be a list of MACs"}), 400
            log.info("Selezione BLE aggiornata: %s",
                     _runtime_cfg.get("BLE_DEVICES", "(nessuna)"))
            _runtime_cfg_save()
            continue
        if k not in limits:
            return jsonify({"error": "unknown setting: " + k}), 400
        if v is None:
            _runtime_cfg.pop(k, None)
            continue
        try:
            num = float(v)
        except (TypeError, ValueError):
            return jsonify({"error": k + " must be a number"}), 400
        lo, hi = limits[k]
        if num == 0 and k == "POLL_SECONDS_NIGHT":
            pass    # 0 = night mode disattivata
        elif not (lo <= num <= hi):
            return jsonify({"error": k + f" must be between {lo} and {hi}"}), 400
        if k != "STATIONARY_SPEED_KN":
            if num != int(num):
                return jsonify({"error": k + " must be an integer"}), 400
            _runtime_cfg[k] = str(int(num))
        else:
            _runtime_cfg[k] = str(num)
    log.info("Runtime settings aggiornate: %s", _runtime_cfg)
    _runtime_cfg_save()
    # Push the KNOT-side GBUF write interval when it changed
    if "GBUF_WRITE_SECONDS" in body and body["GBUF_WRITE_SECONDS"] is not None:
        threading.Thread(target=apply_gbuf_interval,
                        args=(int(_cfg("GBUF_WRITE_SECONDS", GBUF_WRITE_SECONDS)),),
                        daemon=True).start()
    return jsonify(_cfg_snapshot())


@app.route("/stats")
@app.route("/nautilus/api/stats/monthly-curve")
@app.route(URL_PREFIX_ALIAS + "/api/stats/monthly-curve")
def api_stats_monthly_curve():
    """Average daily solar production curves per month."""
    try:
        return jsonify(_monthly_curves())
    except Exception as exc:
        log.warning("stats monthly-curve: %s", exc)
        return jsonify({"error": "stats unavailable"}), 503


@app.route("/nautilus/api/stats/totals")
@app.route(URL_PREFIX_ALIAS + "/api/stats/totals")
def api_stats_totals():
    """Monthly and yearly totals of production and consumption (kWh)."""
    try:
        return jsonify(_totals())
    except Exception as exc:
        log.warning("stats totals: %s", exc)
        return jsonify({"error": "stats unavailable"}), 503


@app.route("/knot-logs")
@app.route("/nautilus/knot-logs")
@app.route(URL_PREFIX_ALIAS + "/knot-logs")
def knot_logs_page():
    tz = datetime.now().astimezone().utcoffset()
    tz_h = int(tz.total_seconds() // 3600) if tz else 0
    tz_label = f"UTC{tz_h:+d}" if tz_h else "UTC"
    return (KNOT_LOGS_HTML
            .replace("{{BOAT}}", BOAT_NAME)
            .replace("{{TZ}}", tz_label))


@app.route("/track")
@app.route("/nautilus/track")
@app.route(URL_PREFIX_ALIAS + "/track")
def track_page():
    return TRACK_HTML.replace("{{BOAT}}", BOAT_NAME)

@app.route("/stats")
@app.route("/nautilus/stats")
@app.route(URL_PREFIX_ALIAS + "/stats")
def stats_page():
    return STATS_HTML.replace("{{BOAT}}", BOAT_NAME)

@app.route("/settings")
@app.route("/nautilus/settings")
@app.route(URL_PREFIX_ALIAS + "/settings")
def settings_page():
    return SETTINGS_HTML.replace("{{BOAT}}", BOAT_NAME)


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230f172a'/%3E%3Cg stroke='%2338bdf8' stroke-width='5' stroke-linecap='round' fill='none'%3E%3Ccircle cx='32' cy='15' r='6'/%3E%3Cline x1='32' y1='21' x2='32' y2='52'/%3E%3Cline x1='20' y1='30' x2='44' y2='30'/%3E%3Cpath d='M 14 40 C 14 55, 50 55, 50 40'/%3E%3Cline x1='14' y1='40' x2='20' y2='44'/%3E%3Cline x1='50' y1='40' x2='44' y2='44'/%3E%3C/g%3E%3C/svg%3E">
<title>Nautilus Telemetry</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: #0f172a; color: #e2e8f0;
    font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
    min-height: 100vh; padding: 24px;
  }
  header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
  h1 { font-size: 1.5rem; color: #38bdf8; letter-spacing: .5px; }
  #status { font-size: .8rem; color: #94a3b8; }
  #status.err { color: #f87171; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; }
  .card {
    background: #1e293b; border: 1px solid #334155; border-radius: 14px;
    padding: 22px; box-shadow: 0 4px 14px rgba(0,0,0,.35);
  }
  .card h2 { font-size: 1.05rem; font-weight: 600; color: #f1f5f9; display: flex;
             justify-content: space-between; align-items: center; gap: 8px; }
  .card h2 small { color: #64748b; font-weight: 400; font-size: .72rem; }
  .chip { font-size: .68rem; padding: 3px 9px; border-radius: 999px; font-weight: 600; }
  .chip.ok   { background: #064e3b; color: #34d399; }
  .chip.warn { background: #451a03; color: #fbbf24; }
  .chip.bad  { background: #7f1d1d; color: #f87171; }
  .chip.idle { background: #1e3a5f; color: #7dd3fc; }
  .main-val { font-size: 2.6rem; font-weight: 700; color: #38bdf8; margin: 10px 0 2px; }
  .main-val small { font-size: 1rem; color: #64748b; font-weight: 400; }
  .metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 16px; }
  .metric { background: #0f172a; border-radius: 10px; padding: 10px 12px; }
  .metric .k { font-size: .66rem; color: #64748b; text-transform: uppercase; letter-spacing: .5px; }
  .metric .v { font-size: 1.15rem; font-weight: 600; color: #f1f5f9; margin-top: 2px; }
  .foot { margin-top: 16px; font-size: .72rem; color: #475569; word-break: break-all; }
  .foot .row { margin-top: 3px; }
  .note { margin-top: 14px; font-size: .74rem; color: #94a3b8; background: #0f172a;
          border-left: 3px solid #334155; padding: 8px 10px; border-radius: 6px; }
  .bar { height: 7px; background: #0f172a; border-radius: 4px; margin-top: 14px; overflow: hidden; }
  .bar > div { height: 100%; background: linear-gradient(90deg,#22c55e,#38bdf8); border-radius: 4px; }
  .map-wrap { margin-top: 14px; border-radius: 10px; overflow: hidden; border: 1px solid #334155; }
  .map-wrap iframe, .map-wrap #map { display: block; width: 100%; height: 320px; border: 0; filter: saturate(.85) brightness(.9); }
  .map-toggle { display: flex; gap: 8px; margin-top: 14px; }
  .map-toggle button {
    font: inherit; font-size: .74rem; padding: 5px 12px; border-radius: 8px;
    border: 1px solid #334155; background: #0f172a; color: #94a3b8; cursor: pointer;
  }
  .map-toggle button.active { background: #1e3a5f; color: #7dd3fc; border-color: #38bdf8; }
  .boat-icon { display: flex; align-items: center; justify-content: center; font-size: 22px;
               filter: drop-shadow(0 2px 3px rgba(0,0,0,.6)); background: none; border: 0; }
  .ver { font-size: .7rem; color: #475569; align-self: center; }
  .gmaps-link { display: inline-block; margin-top: 10px; font-size: .78rem; color: #38bdf8;
                 text-decoration: none; border: 1px solid #334155; padding: 5px 10px; border-radius: 8px; }
  .gmaps-link:hover { background: #0f172a; }
  @media (max-width: 480px) { body { padding: 12px; } .main-val { font-size: 2.1rem; } }
</style>
</head>
<body>
<header>
  <h1>⚓ Nautilus Telemetry</h1>
  <span id="status">loading…</span>
  <span class="ver" id="version"></span>
  <a href="track" style="font-size:.78rem;color:#38bdf8;text-decoration:none;border:1px solid #334155;padding:5px 10px;border-radius:8px;background:#1e293b">Track history →</a>
  <a href="stats" style="font-size:.78rem;color:#38bdf8;text-decoration:none;border:1px solid #334155;padding:5px 10px;border-radius:8px;background:#1e293b">Stats →</a>
  <a href="settings" style="font-size:.78rem;color:#38bdf8;text-decoration:none;border:1px solid #334155;padding:5px 10px;border-radius:8px;background:#1e293b">Settings →</a>
</header>
<div class="grid">
  <div class="card" id="bm6"></div>
  <div class="card" id="mppt"></div>
  <div class="card" id="shunt" style="display:none"></div>
  <div class="card" id="gps"></div>
  <div class="card" id="lte"></div>
  <div class="card" id="solar"></div>
  <div class="card" id="load"></div>
  <div class="card" id="data-usage"></div>
  <div class="card" id="knot-status"></div>
</div>
<script>
function esc(s) { return String(s ?? "—").replace(/[&<>"]/g, c => ({"&":"&"+"#38;","<":"&"+"#60;",">":"&"+"#62;",'"':"&"+"#34;"}[c])); }
function chipClass(v) { if (v == null) return "idle"; return v > 12.8 || (v > 24 && v < 26) || (v > 48 && v < 55) ? "ok" : (v > 10.5 && v < 13) || v > 40 ? "warn" : "bad"; }

async function refresh() {
  let d;
  try {
    d = await (await fetch("api/data")).json();
  } catch (e) {
    document.getElementById("status").textContent = "endpoint unreachable";
    document.getElementById("status").className = "err";
    return;
  }
  const st = document.getElementById("status");
  st.className = d.source_ok ? "" : "err";
  st.textContent = (d.source_ok ? "KNOT online" : "KNOT offline") +
    " · updated " + (d.last_poll || "—") + " " + (d.tz_label || "");
  document.getElementById("version").textContent = d.version ? "v" + d.version : "";

  // ---- BM6 ----
  const b = d.bm6;
  const bm6 = document.getElementById("bm6");
  if (!b) {
    bm6.innerHTML = "<h2>BM6-{{BOAT}}</h2><div class='note'>Device not seen by the KNOT.</div>";
  } else {
    const cls = chipClass(b.voltage);
    // SoC and state shown: when available, the estimate from the battery profile (soc_est);
    // the BM6 firmware SoC/state is calibrated for automotive lead-acid batteries and
    // reports nonsense on LiFePO4 (12% on a full battery, "low voltage" at 13.6V).
    const soc = b.soc_est != null ? b.soc_est : b.soc;
    let stTxt;
    if (b.soc_est != null) {
      stTxt = b.state_code === 2 ? "Charging" : (b.soc_est >= 20 ? "OK" : "Low voltage");
    } else {
      stTxt = b.state ? b.state : "n/a";
    }
    const vTxt = b.voltage != null ? b.voltage.toFixed(2) : "—";
    // BM6 signal: green while the last GATT read is fresh, red when the sensor
    // has stopped transmitting (see gatt_age_s from the backend)
    let sigChip = "";
    if (b.signal_ok === true) {
      sigChip = " <span class='chip ok'>signal OK</span>";
    } else if (b.signal_ok === false) {
      const ageMin = b.gatt_age_s != null ? Math.round(b.gatt_age_s / 60) : "—";
      sigChip = " <span class='chip bad'>SIGNAL LOST · last data " + ageMin + " min ago</span>";
    }
    const vNote = b.voltage == null
      ? "<div class='note'>Voltage not yet read via GATT: connecting to the BM6…</div>"
      : (b.voltage_source === "gatt"
          ? "<div class='note'>Measured via GATT (direct sensor read every 2 min): iBeacon advertisement = beacon ID only; adv frame temperature/SoC unreliable.</div>"
          : "");
    bm6.innerHTML = `
      <h2>🔋 BM6-{{BOAT}} <span class="chip ${cls}">${b.voltage != null ? b.voltage.toFixed(2) + " V" : "n/a"}</span>${sigChip}</h2>
      <div class="main-val">${vTxt} <small>V</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">SoC${b.soc_est != null ? " (est.)" : ""}</div><div class="v">${b.soc_est != null ? esc(b.soc_est) : (b.soc != null ? esc(b.soc) : "—")} %</div></div>
        <div class="metric"><div class="k">CPU temperature</div><div class="v">${b.temperature != null ? esc(b.temperature) + " °C" : "—"}</div></div>
        <div class="metric"><div class="k">State</div><div class="v" style="font-size:.9rem">${esc(stTxt)}</div></div>
        <div class="metric"><div class="k">RSSI</div><div class="v">${esc(b.rssi)} dBm</div></div>
      </div>
      ${soc != null ? `<div class="bar"><div style="width:${Math.min(100, soc)}%"></div></div>` : ""}
      ${vNote}
      <div class="foot">
        <div class="row">MAC: ${esc(b.mac)}</div>
        <div class="row">UUID: ${esc(b.uuid)}</div>
        <div class="row">Major/Minor: ${esc(b.major)} / ${esc(b.minor)} · Last seen: ${esc(b.last_seen)}</div>
        ${b.frame_voltage ? `<div class="row">Voltage from encrypted frame: ${b.frame_voltage.toFixed(2)} V</div>` : ""}
        <div class="row">Frames: ${b.frames && b.frames.length ? b.frames.join(", ") : "none"}${b.cached_fields_seen ? " · encrypted data seen at " + esc(b.cached_fields_seen) : ""}</div>
        ${b.soc_est != null && b.soc != null ? `<div class="row">SoC reported by sensor: ${esc(b.soc)}% (firmware calibrated for lead-acid: may be unreliable for LiFePO4)</div>` : ""}
      </div>`;
  }

  // ---- MPPT ----
  const m = d.mppt;
  const v = d.victron;
  const mppt = document.getElementById("mppt");
  if (v && v.model === "SmartSolar") {
    if (v.error) {
      mppt.innerHTML = `
      <h2>☀️ SmartSolar MPPT 75/15 <span class="chip bad">error</span></h2>
      <div class="note">${esc(v.error)}</div>
      <div class="foot">${v.mac ? `<div class="row">MAC: ${esc(v.mac)} · Last seen: ${esc(v.last_seen)}</div>` : ""}</div>`;
    } else {
      mppt.innerHTML = `
      <h2>☀️ SmartSolar MPPT 75/15 <span class="chip ${v.solar_power_w > 0 ? "ok" : "idle"}">${v.solar_power_w > 0 ? v.solar_power_w + " W" : "night"}</span></h2>
      <div class="main-val">${v.v_bat != null ? v.v_bat.toFixed(2) : "—"} <small>V battery</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">Charge state</div><div class="v" style="font-size:.9rem">${esc(v.charge_state)}</div></div>
        <div class="metric"><div class="k">Charge current</div><div class="v">${esc(v.i_charge)} A</div></div>
        <div class="metric"><div class="k">Solar power</div><div class="v">${esc(v.solar_power_w)} W</div></div>
        <div class="metric"><div class="k">Load current</div><div class="v">${esc(v.i_load)} A</div></div>
        <div class="metric"><div class="k">Yield today</div><div class="v">${esc(v.yield_today_wh)} Wh</div></div>
        <div class="metric"><div class="k">RSSI</div><div class="v">${esc(v.rssi)} dBm</div></div>
      </div>
      <div class="foot"><div class="row">MAC: ${esc(v.mac)} · Last seen: ${esc(v.last_seen)} · data via encrypted BLE advertisement</div></div>`;
    }
  }
  // ---- SmartShunt (battery monitor via encrypted adv) ----
  const shunt = document.getElementById("shunt");
  if (shunt) {
    const vd = (d.victron_devices || []).filter(p => p.model === "SmartShunt" || /shunt|monitor/i.test(p.error || "") || (!p.error && p.readout_kind === "battery-monitor"));
    if (!vd.length) {
      shunt.style.display = "none";
    } else {
      shunt.style.display = "";
      const p = vd[0];
      if (p.error) {
        shunt.innerHTML = `
        <h2>⚡ SmartShunt <span class="chip bad">error</span></h2>
        <div class="note">${esc(p.error)}${p.mac ? " · " + esc(p.mac) : ""}</div>`;
      } else {
        shunt.innerHTML = `
        <h2>⚡ SmartShunt <span class="chip ${p.i_bat > 0.3 ? "ok" : p.i_bat < -0.3 ? "bad" : "idle"}">${p.i_bat > 0 ? "+" : ""}${p.i_bat != null ? p.i_bat.toFixed(1) : "—"} A</span></h2>
        <div class="main-val">${p.v_bat != null ? p.v_bat.toFixed(2) : "—"} <small>V battery</small></div>
        <div class="metrics">
          <div class="metric"><div class="k">State of charge</div><div class="v">${p.soc_pct != null ? p.soc_pct.toFixed(0) : "—"} %</div></div>
          <div class="metric"><div class="k">Battery current</div><div class="v">${p.i_bat != null ? p.i_bat.toFixed(1) : "—"} A</div></div>
          <div class="metric"><div class="k">Consumed</div><div class="v">${p.consumed_ah != null ? p.consumed_ah.toFixed(2) : "—"} Ah</div></div>
          <div class="metric"><div class="k">RSSI</div><div class="v">${esc(p.rssi)} dBm</div></div>
        </div>
        <div class="foot"><div class="row">MAC: ${esc(p.mac)} · Last seen: ${esc(p.last_seen)} · data via encrypted BLE advertisement</div></div>`;
      }
    }
  } else if (!m) {
    mppt.innerHTML = "<h2>☀️ MPPT</h2><div class='note'>Device not seen.</div>";
  } else if (m.model === "BL917") {
    if (!m.registered) {
      mppt.innerHTML = `
      <h2>☀️ MPPT BL917 <span class="chip idle">cloud</span></h2>
      <div class="note">${esc(m.note)}</div>`;
    } else {
      mppt.innerHTML = `
      <h2>☀️ MPPT BL917 <span class="chip ${m.solar_active ? "ok" : "idle"}">${m.solar_active ? "panel active" : "night"}</span></h2>
      <div class="main-val">${m.v_bat != null ? m.v_bat : "—"} <small>V battery</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">Charge current</div><div class="v">${esc(m.i_charge ?? "—")} A</div></div>
        <div class="metric"><div class="k">Load current</div><div class="v">${esc(m.i_load ?? "—")} A</div></div>
        <div class="metric"><div class="k">Temperature</div><div class="v">${esc(m.temperature ?? "—")} °C</div></div>
        <div class="metric"><div class="k">Total</div><div class="v">${esc(m.total_kwh ?? "—")} kWh</div></div>
        <div class="metric"><div class="k">Battery type</div><div class="v" style="font-size:.9rem">${esc(m.battery_type ?? "—")}</div></div>
        <div class="metric"><div class="k">Mode</div><div class="v" style="font-size:.9rem">${esc(m.charge_mode ?? "—")}</div></div>
      </div>
      <div class="foot"><div class="row">Data via ZhiJinPower cloud (the BL917 has no direct BLE)</div></div>`;
    }
  } else if (m.telemetry) {
    mppt.innerHTML = `
      <h2>☀️ MPPT <span class="chip ok">${m.watt} W</span></h2>
      <div class="main-val">${m.watt} <small>W</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">PV voltage</div><div class="v">${m.v_pv} V</div></div>
        <div class="metric"><div class="k">Battery voltage</div><div class="v">${m.v_bat} V</div></div>
        <div class="metric"><div class="k">Charge current</div><div class="v">${m.c_charge} A</div></div>
        <div class="metric"><div class="k">RSSI</div><div class="v">${esc(m.rssi)} dBm</div></div>
      </div>
      <div class="foot"><div class="row">Last seen: ${esc(m.last_seen)}</div><div class="row">${esc(m.raw)}</div></div>`;
  } else {
    mppt.innerHTML = `
      <h2>☀️ MPPT <span class="chip idle">listening</span></h2>
      <div class="main-val">— <small>V</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">Device</div><div class="v" style="font-size:.85rem">${esc(m.adv_name || m.name)}</div></div>
        <div class="metric"><div class="k">RSSI</div><div class="v">${esc(m.rssi)} dBm</div></div>
      </div>
      <div class="note">The MPPT advertises only MAC and name (${esc(m.adv_name || "BT-PQCC2430")}):
      the Modbus registers (V<sub>pv</sub>, V<sub>bat</sub>, current) can only be read
      through a GATT connection on the 0xFFE0 UART service, which the MikroTik KNOT does not forward.
      The parser stays active and will decode the registers as soon as they appear in the payload.</div>
      <div class="foot">
        <div class="row">MAC: ${esc(m.mac)} · Last seen: ${esc(m.last_seen)}</div>
        <div class="row">${esc(m.raw)}</div>
      </div>`;
  }

  // ---- GPS / mappa ----
  const g = d.gps;
  window._lastGps = g;
  const gpsEl = document.getElementById("gps");
  if (!g) {
    gpsEl.innerHTML = "<h2>📍 Position <span class='chip idle'>waiting</span></h2>" +
      "<div class='note'>KNOT GPS not yet read…</div>";
  } else {
    const lat = g.latitude, lon = g.longitude;
    const gmaps = "https://maps.google.com/?q=" + lat + "," + lon;
    const gearth = "https://earth.google.com/web/search/" + lat + "," + lon;
    if (!window._nautilusInit) {
      // primo rendering: costruisco la card una volta sola, la mappa resta viva
      window._nautilusInit = true;
      gpsEl.innerHTML = `
        <h2>📍 {{BOAT}} <span class="chip ${g.valid ? "ok" : "warn"}" id="gps-chip">${g.valid ? "fix OK" : "no fix"}</span></h2>
        <div class="metrics">
          <div class="metric"><div class="k">Latitude</div><div class="v" id="gps-lat">${lat.toFixed(6)}</div></div>
          <div class="metric"><div class="k">Longitude</div><div class="v" id="gps-lon">${lon.toFixed(6)}</div></div>
          <div class="metric"><div class="k">Speed</div><div class="v" id="gps-speed">${g.speed_kn.toFixed(1)} <small>kn</small></div></div>
          <div class="metric"><div class="k">Course</div><div class="v" id="gps-bearing">${g.true_bearing.toFixed(1)}°</div></div>
          <div class="metric"><div class="k">Satellites</div><div class="v" id="gps-sat">${esc(g.satellites)}</div></div>
          <div class="metric"><div class="k">Altitude</div><div class="v" id="gps-alt">${g.altitude_m.toFixed(0)} m</div></div>
        </div>
        <div class="map-toggle">
          <button id="btn-nautical" class="active" onclick="window._showMap('nautical')">Nautical chart</button>
          <button id="btn-gmaps" onclick="window._showMap('gmaps')">Google Maps</button>
        </div>
        <div class="map-wrap">
          <a id="kml-export" class="gmaps-link" href="api/boat/track.kml" download="track.kml" style="display:inline-block;margin-bottom:10px">Export KML for Google Earth \u2197</a><div id="map"></div>
          <iframe id="gmap-frame" loading="lazy" style="display:none"
            src="about:blank"></iframe>
        </div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <a class="gmaps-link" id="gmaps-link" href="${gmaps}" target="_blank" rel="noopener">Open in Google Maps ↗</a>
          <a class="gmaps-link" id="gearth-link" href="${gearth}" target="_blank" rel="noopener">Open in Google Earth 3D ↗</a>
        </div>
        <div class="foot"><div class="row">GPS fix at <span id="gps-fixtime">${esc(g.fix_time)}</span> ${esc(d.tz_label || "")} (KNOT time)</div></div>`;
      window._nautilusMap = L.map("map", { zoomControl: true });
      // base OpenStreetMap + overlay nautico OpenSeaMap (seamarks: boe, fari, secche…)
      var osmAttr = "&co" + "py; OpenStreetMap";
      L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 19, attribution: osmAttr }).addTo(window._nautilusMap);
      L.tileLayer("https://tiles.openseamap.org/seamark/{z}/{x}/{y}.png", {
        maxZoom: 18, attribution: "OpenSeaMap" }).addTo(window._nautilusMap);
      window._nautilusBoat = L.marker([lat, lon], {
        icon: L.divIcon({ className: "boat-icon", html: "⛵", iconSize: [26, 26], iconAnchor: [13, 13] })
      }).addTo(window._nautilusMap);
      window._nautilusMap.setView([lat, lon], 15);
      // smetti di seguire la barca appena l'utente muove la mappa
      window._nautilusMap.on("dragstart", () => { window._nautilusFollow = false; });
    } else {
      // subsequent updates: only values are touched, the map stays as is
      document.getElementById("gps-chip").className = "chip " + (g.valid ? "ok" : "warn");
      document.getElementById("gps-chip").textContent = g.valid ? "fix OK" : "no fix";
      document.getElementById("gps-lat").textContent = lat.toFixed(6);
      document.getElementById("gps-lon").textContent = lon.toFixed(6);
      document.getElementById("gps-speed").innerHTML = g.speed_kn.toFixed(1) + " <small>kn</small>";
      document.getElementById("gps-bearing").textContent = g.true_bearing.toFixed(1) + "°";
      document.getElementById("gps-sat").textContent = g.satellites;
      document.getElementById("gps-alt").textContent = g.altitude_m.toFixed(0) + " m";
      document.getElementById("gps-fixtime").textContent = g.fix_time || "—";
      document.getElementById("gmaps-link").href = gmaps;
      document.getElementById("gearth-link").href = gearth;
      window._nautilusBoat.setLatLng([lat, lon]);
      if (window._nautilusFollow) window._nautilusMap.panTo([lat, lon]);
    }
  }

  // ---- LTE ----
  const l = d.lte;
  const lteEl = document.getElementById("lte");
  if (!l) {
    lteEl.innerHTML = "<h2>📶 Cellular <span class='chip idle'>n/a</span></h2>" +
      "<div class='note'>KNOT LTE signal not yet read…</div>";
  } else {
    const fmt = (v, u) => v != null ? v + " " + u : "—";
    lteEl.innerHTML = `
      <h2>📶 Cellular <span class="chip ${l.quality_class}">${esc(l.quality)}</span></h2>
      <div class="main-val">${l.rsrp != null ? l.rsrp : "—"} <small>dBm RSRP</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">Operator</div><div class="v" style="font-size:.9rem">${esc(l.operator)}${l.roaming ? " (roaming)" : ""}</div></div>
        <div class="metric"><div class="k">Band</div><div class="v">${esc(l.band)}</div></div>
        <div class="metric"><div class="k">RSRQ</div><div class="v">${fmt(l.rsrq, "dB")}</div></div>
        <div class="metric"><div class="k">SINR</div><div class="v">${fmt(l.sinr, "dB")}</div></div>
        <div class="metric"><div class="k">RSSI</div><div class="v">${fmt(l.rssi, "dBm")}</div></div>
        <div class="metric"><div class="k">Session</div><div class="v" style="font-size:.9rem">${esc(l.session_uptime)}</div></div>
      </div>
      <div class="foot"><div class="row">Cell ID: ${esc(l.cellid)} · ${esc(l.band_detail)}</div></div>`;
  }

  // ---- Data usage (SIM) ----
  const du = d.data_usage;
  const duEl = document.getElementById("data-usage");
  if (!du) {
    duEl.innerHTML = "<h2>📶 Data usage <span class='chip idle'>n/a</span></h2>" +
      "<div class='note'>No data yet — counters start after the first samples…</div>";
  } else {
    const bar = Math.min(100, du.pct);
    duEl.innerHTML = `
      <h2>📶 Data usage <span class="chip ${du.alert_class}">${du.pct}% of budget</span></h2>
      <div class="main-val">${du.used_mb} <small>MB of ${du.budget_mb} MB this month</small></div>
      <div style="background:#334155;border-radius:6px;height:10px;margin:10px 0">
        <div style="background:${du.alert_class === "ok" ? "#38bdf8" : du.alert_class === "warn" ? "#f59e0b" : "#ef4444"};border-radius:6px;height:10px;width:${bar}%"></div>
      </div>
      <div class="metrics">
        <div class="metric"><div class="k">Avg / day</div><div class="v">${du.avg_mb_day} MB</div></div>
        <div class="metric"><div class="k">Projected month-end</div><div class="v">${du.projected_mb} MB</div></div>
        <div class="metric"><div class="k">Days sampled</div><div class="v">${du.days_with_data}</div></div>
      </div>
      <div class="foot"><div class="row">WireGuard tunnel counters (SIM traffic) · sampled every __DU_POLL_MIN__ min · counters and stats reset at the start of each month</div></div>`;
  }

  // ---- Knot status ----
  const ks = d.knot_status;
  const ksEl = document.getElementById("knot-status");
  if (!ks) {
    ksEl.innerHTML = "<h2>&#128225; Knot status <span class='chip idle'>n/a</span></h2>" +
      "<div class='note'>KNOT not reachable — no tunnel data…</div>";
  } else {
    const ageMin = ks.handshake_age_s != null ? Math.round(ks.handshake_age_s / 60) : null;
    const chip = ks.tunnel_up
      ? "<span class='chip ok'>tunnel up</span>"
      : "<span class='chip bad'>TUNNEL DOWN</span>";
    const fmtB = b => b >= 1073741824 ? (b/1073741824).toFixed(1) + " GiB"
      : b >= 1048576 ? (b/1048576).toFixed(1) + " MiB" : (b/1024).toFixed(0) + " KiB";
    ksEl.innerHTML = `
      <h2>&#128225; Knot status ${chip}</h2>
      <div class="main-val">${ageMin != null ? ageMin : "—"} <small>min since last handshake</small></div>
      <div class="metrics">
        <div class="metric"><div class="k">KNOT uptime</div><div class="v" style="font-size:.9rem">${esc(ks.uptime || "—")}</div></div>
        <div class="metric"><div class="k">Endpoint</div><div class="v" style="font-size:.9rem">${esc(ks.endpoint || "—")}</div></div>
        <div class="metric"><div class="k">Tunnel rx</div><div class="v">${fmtB(ks.rx_bytes)}</div></div>
        <div class="metric"><div class="k">Tunnel tx</div><div class="v">${fmtB(ks.tx_bytes)}</div></div>
      </div>
      ${ks.cpu_load != null ? `
      <div class="metrics">
        <div class="metric"><div class="k">RouterOS</div><div class="v" style="font-size:.9rem">${esc(ks.version || "—")}</div></div>
        <div class="metric"><div class="k">CPU load</div><div class="v">${ks.cpu_load}%</div></div>
        <div class="metric"><div class="k">Memory free</div><div class="v">${ks.free_memory != null ? fmtB(ks.free_memory) : "—"} <small>of ${ks.total_memory != null ? fmtB(ks.total_memory) : "—"}</small></div></div>
        <div class="metric"><div class="k">Disk free</div><div class="v">${ks.free_hdd != null ? fmtB(ks.free_hdd) : "—"} <small>of ${ks.total_hdd != null ? fmtB(ks.total_hdd) : "—"}</small></div></div>
      </div>` : ""}
      ${d.outages ? (() => {
        const o = d.outages;
        const fmtDur = s => s >= 3600 ? Math.floor(s/3600) + "h " + Math.round(s%3600/60) + "m"
          : s >= 60 ? Math.round(s/60) + "m" : s + "s";
        const open = o.open_since
          ? ` · <span style="color:#f87171">gap open since ${esc(o.open_since.slice(11,16))}</span>` : "";
        return `
      <div class="metrics">
        <div class="metric"><div class="k">Coverage gaps today</div><div class="v">${o.today.count}${open}</div></div>
        <div class="metric"><div class="k">Total offline today</div><div class="v">${fmtDur(o.today.seconds)}</div></div>
        <div class="metric"><div class="k">Last gap</div><div class="v" style="font-size:.9rem">${o.last ? (o.last.today ? "" : esc(o.last.start.slice(8,10)) + "/" + esc(o.last.start.slice(5,7)) + " ") + esc(o.last.start.slice(11,16)) + " · " + fmtDur(o.last.duration_s) : "—"}</div></div>
      </div>`; })() : ""}
      <div class="foot">
        <div class="row">Serial No.: ${esc(ks.serial || "—")}</div>
        <div class="row">ICCID: ${esc(ks.iccid || "—")}${ks.operator ? " · " + esc(ks.operator) : ""}${ks.band ? " · " + esc(ks.band.split(" ")[0]) : ""}</div>
        <div class="row">
        ${ks.tunnel_up
          ? "Handshake fresh, watchdog idle"
          : "No handshake for " + (ageMin != null ? ageMin + " min" : "unknown") + " — KNOT-side watchdog should react (LTE reset, then reboot)"}
        · <a href="knot-logs" style="color:#38bdf8">KNOT logs</a>
      </div></div>`;
  }
}

window._showMap = function(mode) {
  const m = document.getElementById("map");
  const f = document.getElementById("gmap-frame");
  if (m) m.style.display = mode === "nautical" ? "" : "none";
  if (f) {
    if (mode === "gmaps") {
      if (f.src === "about:blank" || !f.src || f.src.endsWith("about:blank")) {
        const g = window._lastGps;
        if (g) f.src = "https://maps.google.com/maps?q=" + g.latitude + "," + g.longitude + "&z=15&output=embed";
      }
      f.style.display = "";
    } else {
      f.style.display = "none";
    }
  }
  const bn = document.getElementById("btn-nautical");
  const bg = document.getElementById("btn-gmaps");
  if (bn) bn.classList.toggle("active", mode === "nautical");
  if (bg) bg.classList.toggle("active", mode === "gmaps");
  if (mode === "nautical" && window._nautilusMap) window._nautilusMap.invalidateSize();
};
refresh();
setInterval(refresh, 5000);

// ---- Power graphs (solar production / current used) ----
function powerPath(curve, x0, y0, w, h, maxW) {
  if (!curve || !curve.length) return "";
  return curve.map(p => {
    const px = x0 + (p[0] / 24) * w;
    const py = y0 + h - Math.min(p[1], maxW) / maxW * h;
    return px.toFixed(1) + "," + py.toFixed(1);
  }).join(" ");
}
function powerSvg(d, color, colorDim) {
  const W = 720, H = 200, x0 = 34, y0 = 10, gw = W - 44, gh = H - 34;
  const all = (d.today || []).concat(d.yesterday || [], d.forecast || []);
  const maxW = Math.max(10, ...all.map(p => p[1]));
  const yticks = [0, Math.round(maxW / 2), Math.round(maxW)];
  let svg = "<svg viewBox='0 0 " + W + " " + H + "' style='width:100%;height:auto'>";
  svg += "<line x1='" + x0 + "' y1='" + (y0 + gh) + "' x2='" + (x0 + gw) + "' y2='" + (y0 + gh) + "' stroke='#334155'/>";
  for (let hh = 0; hh <= 24; hh += 4) {
    const px = x0 + hh / 24 * gw;
    svg += "<line x1='" + px + "' y1='" + y0 + "' x2='" + px + "' y2='" + (y0 + gh) + "' stroke='#1e293b'/>";
    svg += "<text x='" + px + "' y='" + (H - 6) + "' fill='#475569' font-size='10' text-anchor='middle'>" + hh + "h</text>";
  }
  yticks.forEach((v, i) => {
    const py = y0 + gh - (i / (yticks.length - 1)) * gh;
    svg += "<text x='" + (x0 - 4) + "' y='" + (py + 3) + "' fill='#475569' font-size='10' text-anchor='end'>" + v + "</text>";
  });
  svg += "<text x='" + (x0 - 4) + "' y='" + (y0 + 3) + "' fill='#475569' font-size='10' text-anchor='end'>W</text>";
  if (d.yesterday && d.yesterday.length)
    svg += "<polyline fill='none' stroke='" + colorDim + "' stroke-width='1.5' points='" + powerPath(d.yesterday, x0, y0, gw, gh, maxW) + "'/>";
  if (d.forecast && d.forecast.length)
    svg += "<polyline fill='none' stroke='#38bdf8' stroke-width='1.5' stroke-dasharray='5,4' points='" + powerPath(d.forecast, x0, y0, gw, gh, maxW) + "'/>";
  if (d.today && d.today.length) {
    const pts = powerPath(d.today, x0, y0, gw, gh, maxW).split(" ");
    const c256 = color.replace("#", "");
    svg += "<polygon fill='rgba(245,158,11,.15)' points='" + (x0 + "," + (y0 + gh) + " " + pts.join(" ") + " " + (x0 + gw) + "," + (y0 + gh)) + "'/>";
    svg += "<polyline fill='none' stroke='" + color + "' stroke-width='2' points='" + pts.join(" ") + "'/>";
  }
  svg += "</svg>";
  return svg;
}
async function refreshPower(cardId, apiPath, title, color, colorDim, whLabel, emptyNote) {
  const card = document.getElementById(cardId);
  let d;
  try { d = await (await fetch(apiPath)).json(); }
  catch (e) {
    card.innerHTML = "<h2>" + title + "</h2><div class='note'>history unavailable</div>";
    return;
  }
  if (d.error) {
    card.innerHTML = "<h2>" + title + "</h2><div class='note'>" + esc(d.error) + "</div>";
    return;
  }
  if (!(d.today && d.today.length) && !(d.yesterday && d.yesterday.length)) {
    card.innerHTML = "<h2>" + title + "</h2><div class='note'>" + emptyNote + "</div>";
    return;
  }
  card.innerHTML = "<h2>" + title + " <span class='chip ok'>\u2248 " + (d.today_wh || 0) + " " + whLabel + " today</span></h2>"
    + "<div style='display:flex;gap:14px;font-size:.72rem;color:#94a3b8;margin:4px 0 6px'>"
    + "<span><span style='color:" + color + "'>&#9679;</span> today</span>"
    + (d.yesterday_wh ? "<span><span style='color:" + colorDim + "'>&#9679;</span> yesterday (" + d.yesterday_wh + " " + whLabel + ")</span>" : "")
    + (d.forecast ? "<span><span style='color:#38bdf8'>&#9679;</span> forecast (" + d.history_days + "d avg)</span>" : "")
    + "</div>" + powerSvg(d, color, colorDim);
}
function refreshSolar() {
  refreshPower("solar", "api/solar/daily", "\u2600\ufe0f Solar production",
    "#f59e0b", "#64748b", "Wh",
    "No samples yet: the graph fills in as the MPPT reports power (needs MPPT registers, BL917 or Victron data).");
}
function refreshLoad() {
  refreshPower("load", "api/load/daily", "\u26a1 Current used",
    "#a78bfa", "#64748b", "Wh",
    "No samples yet: load current is recorded from Victron or BL917 load output data.");
}
refreshSolar();
refreshLoad();
setInterval(refreshSolar, 60000);
setInterval(refreshLoad, 60000);
</script>
</body>
</html>
"""

STATS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Energy stats · Nautilus</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f172a; color: #e2e8f0; font-family: "Segoe UI", system-ui, sans-serif;
         min-height: 100vh; padding: 20px; }
  header { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 18px; }
  h1 { font-size: 1.3rem; color: #38bdf8; letter-spacing: .5px; }
  a.back { color: #7dd3fc; font-size: .82rem; text-decoration: none; border: 1px solid #334155;
           padding: 5px 10px; border-radius: 8px; background: #1e293b; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
          padding: 18px; margin-bottom: 20px; overflow-x: auto; }
  .card h2 { font-size: 1.05rem; font-weight: 600; color: #f1f5f9; margin-bottom: 10px; }
  table { border-collapse: collapse; width: 100%; font-size: .88rem; }
  th, td { padding: 7px 12px; text-align: left; border-bottom: 1px solid #334155; }
  th { color: #64748b; font-size: .7rem; text-transform: uppercase; letter-spacing: .5px; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .pos { color: #f59e0b; } .neg { color: #a78bfa; } .net { color: #34d399; }
  .bars { display: flex; flex-direction: column; gap: 6px; min-width: 420px; }
  .brow { display: grid; grid-template-columns: 84px 1fr 84px; align-items: center; gap: 8px;
          font-size: .78rem; color: #94a3b8; }
  .track { height: 14px; background: #0f172a; border-radius: 7px; overflow: hidden;
           display: flex; border: 1px solid #334155; }
  .seg-solar { background: #f59e0b; } .seg-load { background: #a78bfa; }
  .note { color: #64748b; font-size: .75rem; margin-top: 10px; }
  .legend { display: flex; flex-wrap: wrap; gap: 14px; margin-top: 10px; font-size: .78rem; color: #94a3b8; }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .legend i { width: 18px; height: 4px; border-radius: 2px; display: inline-block; }
  .mcharts { display: grid; grid-template-columns: repeat(auto-fit, minmax(380px, 1fr)); gap: 14px; }
  .mchart { background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 12px; }
  .mchart h3 { font-size: .82rem; font-weight: 600; color: #f1f5f9; display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .mchart h3 i { width: 14px; height: 4px; border-radius: 2px; display: inline-block; }
</style>
</head>
<body>
<header>
  <h1>&#9889; Energy stats</h1>
  <a class="back" href="./">&#8592; Dashboard</a>
</header>
<div class="card">
  <h2>&#2600;&#65039; Solar production vs &#128506; current used — by month (Wh)</h2>
  <div class="bars" id="months"></div>
</div>
<div class="card">
  <h2>By year (kWh)</h2>
  <table id="years"><thead><tr><th>Year</th><th class="num">Produced (solar)</th>
  <th class="num">Consumed (load)</th><th class="num">Net</th></tr></thead><tbody></tbody></table>
</div>
<div class="card">
  <h2>By month (Wh)</h2>
  <table id="tbl"><thead><tr><th>Month</th><th class="num">Produced</th>
  <th class="num">Consumed</th><th class="num">Net</th></tr></thead><tbody></tbody></table>
</div>
<div class="card">
  <h2>&#9728;&#65039; Average solar day — per month</h2>
  <div id="daycurve" class="mcharts"></div>
  <p class="note">Mean power per 30-min slot across all days of each month (W). Same scale on every chart, so months compare directly.</p>
</div>
<script>
function esc(s) { return String(s ?? "\u2014").replace(/[&<>"]/g, c => ({"&":"&#38;","<":"&#60;",">":"&#62;",'"':"&#34;"}[c])); }
function fmt(k) { return k == null ? "\u2014" : Number(k).toFixed(2); }
function fmtWh(k) { return k == null ? "\u2014" : Math.round(k * 1000).toLocaleString("en-US") + " Wh"; }
async function load() {
  let d;
  try { d = await (await fetch("api/stats/totals")).json(); }
  catch (e) { document.getElementById("months").innerHTML = "<div class='note'>unavailable</div>"; return; }
  if (d.error) { document.getElementById("months").innerHTML = "<div class='note'>" + esc(d.error) + "</div>"; return; }
  const sm = {}, lm = {};
  (d.solar.monthly || []).forEach(m => sm[m.month] = m.kwh);
  (d.load.monthly || []).forEach(m => lm[m.month] = m.kwh);
  const months = [...new Set([...Object.keys(sm), ...Object.keys(lm)])].sort();
  const maxV = Math.max(0.1, ...months.map(m => Math.max(sm[m] || 0, lm[m] || 0)));
  document.getElementById("months").innerHTML = months.map(m => {
    const sv = sm[m] || 0, lv = lm[m] || 0;
    return "<div class='brow'><span>" + esc(m) + "</span>"
      + "<div class='track'>"
      + "<div class='seg-solar' style='width:" + (sv / maxV * 50).toFixed(1) + "%'></div>"
      + "<div class='seg-load' style='width:" + (lv / maxV * 50).toFixed(1) + "%'></div>"
      + "</div>"
      + "<span class='pos'>" + fmtWh(sv) + " / <span class='neg'>" + fmtWh(lv) + "</span></span></div>";
  }).join("") || "<div class='note'>No data yet.</div>";
  const sy = {}, ly = {};
  (d.solar.yearly || []).forEach(y => sy[y.year] = y.kwh);
  (d.load.yearly || []).forEach(y => ly[y.year] = y.kwh);
  const years = [...new Set([...Object.keys(sy), ...Object.keys(ly)])].sort();
  document.querySelector("#years tbody").innerHTML = years.map(y => {
    const sv = sy[y] || 0, lv = ly[y] || 0, net = sv - lv;
    return "<tr><td>" + esc(y) + "</td><td class='num pos'>" + fmt(sv) + "</td>"
      + "<td class='num neg'>" + fmt(lv) + "</td>"
      + "<td class='num net'>" + (net >= 0 ? "+" : "") + fmt(net) + "</td></tr>";
  }).join("") || "<tr><td colspan='4' class='note'>No data yet.</td></tr>";
  document.querySelector("#tbl tbody").innerHTML = months.map(m => {
    const sv = sm[m] || 0, lv = lm[m] || 0, net = sv - lv;
    return "<tr><td>" + esc(m) + "</td><td class='num pos'>" + fmtWh(sv) + "</td>"
      + "<td class='num neg'>" + fmtWh(lv) + "</td>"
      + "<td class='num net'>" + (net >= 0 ? "+" : "\u2212") + fmtWh(Math.abs(net)) + "</td></tr>";
  }).join("");
}
const PALETTE = ["#f59e0b","#38bdf8","#a78bfa","#34d399","#f87171","#fbbf24","#7dd3fc","#c084fc"];
function monthSvg(curve, color) {
  const W = 420, H = 150, P = 34;
  const iw = W - P - 8, ih = H - P - 20;
  const x = h => P + h / 24 * iw;
  const y = (w, maxW) => P + ih - w / maxW * ih;
  let p = "";
  curve.forEach(([h, w]) => { p += (p ? " L" : "M") + x(h).toFixed(1) + " " + y(w, MONTH_MAXW).toFixed(1); });
  let g = "<svg viewBox='0 0 " + W + " " + H + "' style='width:100%;height:auto'>";
  for (let h = 0; h <= 24; h += 2)
    g += "<line x1='" + x(h) + "' y1='" + P + "' x2='" + x(h) + "' y2='" + (P + ih) + "' stroke='#334155' stroke-width='1'/>"
       + "<text x='" + x(h) + "' y='" + (P + ih + 13) + "' fill='#64748b' font-size='10' text-anchor='middle'>" + h + "h</text>";
  for (let w = 0; w <= MONTH_MAXW; w += MONTH_STEP) {
    const wy = Math.round(y(w, MONTH_MAXW) * 10) / 10;
    g += "<line x1='" + P + "' y1='" + wy + "' x2='" + (P + iw) + "' y2='" + wy + "' stroke='#334155' stroke-width='1'/>"
       + "<text x='" + (P - 5) + "' y='" + (wy + 3) + "' fill='#64748b' font-size='10' text-anchor='end'>" + w + "</text>";
  }
  g += "<path d='" + p + "' fill='none' stroke='" + color + "' stroke-width='2' stroke-linejoin='round'/></svg>";
  return g;
}
let MONTH_MAXW = 10, MONTH_STEP = 5;
async function loadCurves() {
  let d;
  try { d = await (await fetch("api/stats/monthly-curve")).json(); }
  catch (e) { return; }
  const el = document.getElementById("daycurve");
  if (d.error) return;
  if (!d.months || !d.months.length) { el.innerHTML = "<div class='note'>No data yet.</div>"; return; }
  MONTH_MAXW = Math.max(10, ...d.months.map(m => m.peak_w));
  MONTH_STEP = Math.max(5, Math.round(MONTH_MAXW / 3 / 5) * 5);
  el.innerHTML = d.months.map((m, k) => {
    const c = PALETTE[k % PALETTE.length];
    return "<div class='mchart'><h3><i style='background:" + c + "'></i>" + esc(m.month)
      + " · " + fmtWh(m.total_wh / 1000) + " (" + m.days + "d, peak " + m.peak_w + " W)</h3>"
      + monthSvg(m.curve, c) + "</div>";
  }).join("");
}
loadCurves();
load();
</script>
</body>
</html>
"""


SETTINGS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Settings · Nautilus</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f172a; color: #e2e8f0; font-family: "Segoe UI", system-ui, sans-serif;
         min-height: 100vh; padding: 20px; max-width: 720px; margin: 0 auto; }
  header { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 18px; }
  h1 { font-size: 1.3rem; color: #38bdf8; letter-spacing: .5px; }
  a.back { color: #7dd3fc; font-size: .82rem; text-decoration: none; border: 1px solid #334155;
           padding: 5px 10px; border-radius: 8px; background: #1e293b; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
          padding: 18px; margin-bottom: 18px; }
  .card h2 { font-size: 1rem; font-weight: 600; color: #f1f5f9; margin-bottom: 4px; }
  .card p.hint { color: #64748b; font-size: .72rem; margin-bottom: 14px; }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 12px;
         padding: 10px 0; border-bottom: 1px solid #334155; }
  .row:last-child { border-bottom: 0; }
  .row label { font-size: .85rem; }
  .row label small { display: block; color: #64748b; font-size: .7rem; margin-top: 2px; }
  .row input { width: 110px; background: #0f172a; color: #e2e8f0; border: 1px solid #334155;
               border-radius: 8px; padding: 7px 10px; font-size: .85rem; text-align: right; }
  .row .unit { color: #64748b; font-size: .75rem; width: 46px; }
  .btn { background: #1d4ed8; color: #fff; border: 0; border-radius: 8px; padding: 10px 22px;
         font-size: .85rem; cursor: pointer; margin-top: 6px; }
  .btn:hover { background: #2563eb; }
  .btn.reset { background: #334155; margin-left: 10px; }
  .msg { margin-top: 12px; font-size: .8rem; min-height: 1.2em; }
  .msg.ok { color: #34d399; } .msg.err { color: #f87171; }
</style>
</head>
<body>
<header>
  <h1>&#9881;&#65039; Settings</h1>
  <a class="back" href="./">&#8592; Dashboard</a>
</header>

<div class="card">
  <h2>Polling intervals</h2>
  <p class="hint">Runtime overrides (seconds). Changes apply within one cycle, without restarting the container, and are saved to disk: they survive a container restart. "Reset all" restores the .env values.</p>
  <div class="row">
    <label>BLE / LTE poll<small>main data poll cycle (solar &amp; load samples included)</small></label>
    <span><input id="POLL_SECONDS" type="number" min="60" max="3600"><span class="unit">s</span></span>
  </div>
  <div class="row">
    <label>Night poll<small>used between NIGHT_START and NIGHT_END; 0 = night mode off</small></label>
    <span><input id="POLL_SECONDS_NIGHT" type="number" min="60" max="3600"><span class="unit">s</span></span>
  </div>
  <div class="row">
    <label>Night window<small>night mode active from hour... to hour... (local time)</small></label>
    <span><input id="NIGHT_START" type="number" min="0" max="23" style="width:60px"><span class="unit">to</span>
    <input id="NIGHT_END" type="number" min="0" max="23" style="width:60px"><span class="unit">h</span></span>
  </div>
  <div class="row">
    <label>GPS poll (moving)<small>blocking GPS monitor call to the KNOT while the boat moves</small></label>
    <span><input id="GPS_POLL_SECONDS" type="number" min="60" max="3600"><span class="unit">s</span></span>
  </div>
  <div class="row">
    <label>BM6 GATT poll<small>real voltage read via persistent GATT connection</small></label>
    <span><input id="GATT_POLL_SECONDS" type="number" min="60" max="3600"><span class="unit">s</span></span>
  </div>
  <div class="row">
    <label>KNOT log download<small>every N s a full KNOT log snapshot is saved server-side (right after a coverage gap too)</small></label>
    <span><input id="GPSBUF_POLL_SECONDS" type="number" min="60" max="86400"><span class="unit">s</span></span>
  </div>
  <div class="row">
    <label>Log archive retention<small>delete saved KNOT logs older than this (0 = keep forever)</small></label>
    <span><input id="GPSBUF_RETENTION_DAYS" type="number" min="0" max="3650"><span class="unit">days</span></span>
  </div>
  <div class="row">
    <label>GBUF write interval<small>how often the KNOT records its GPS position in the log (applied on the KNOT right away)</small></label>
    <span><input id="GBUF_WRITE_SECONDS" type="number" min="60" max="3600"><span class="unit">s</span></span>
  </div>
</div>

<div class="card">
  <h2>Adaptive GPS (stationary)</h2>
  <p class="hint">While the boat is stationary the GPS call is skipped entirely.</p>
  <div class="row">
    <label>Stationary threshold<small>below this speed the boat counts as stationary</small></label>
    <span><input id="STATIONARY_SPEED_KN" type="number" step="0.1" min="0" max="20"><span class="unit">kn</span></span>
  </div>
  <div class="row">
    <label>Stationary GPS interval<small>seconds between GPS calls while stationary</small></label>
    <span><input id="GPS_STATIONARY_INTERVAL" type="number" min="30" max="7200"><span class="unit">s</span></span>
  </div>
</div>

<div class="card">
  <h2>Forecast</h2>
  <div class="row">
    <label>Solar/load forecast history<small>how many past days feed the forecast average</small></label>
    <span><input id="SOLAR_HISTORY_DAYS" type="number" min="1" max="30"><span class="unit">days</span></span>
  </div>
</div>

<div class="card">
  <h2>BLE devices</h2>
  <p class="hint">All BLE devices seen by the KNOT. Select only the ones you need: with an active selection the poll fetches just those devices (~70% less tunnel traffic for the BLE poll). The selection is saved on disk and survives restarts. Without a selection the poll fetches all persistent devices with a single full scan.</p>
  <div id="ble-list" style="margin-top:10px">
    <p class="hint" style="margin:0">Loading device list…</p>
  </div>
  <button class="btn" style="margin-top:12px" onclick="saveBle()">Save selection</button>
</div>

<div class="card">
  <h2>Victron devices</h2>
  <p class="hint">Encrypted Victron BLE advertisements (SmartSolar, SmartShunt). Click a device to view and edit its data; the encryption key comes from VictronConnect (Product Info &rarr; Instant Readout). Alternatively fill serial + PUK: the key is derived and locked in automatically on the first successful decode. Values are saved on disk and survive restarts.</p>
  <div id="vic-list" style="margin-top:10px"></div>
  <div class="row" style="margin-top:8px">
    <button class="btn" onclick="vicOpen(-1)">+ Add device</button>
  </div>

  <div id="vic-modal" style="display:none;position:fixed;inset:0;background:#0009;z-index:50;align-items:center;justify-content:center" onclick="if(event.target===this)vicClose()">
    <div style="background:#1e293b;border:1px solid #33415580;border-radius:12px;padding:18px;width:min(560px,92vw);max-height:88vh;overflow:auto">
      <h3 style="margin:0 0 12px" id="vic-modal-title">Victron device</h3>
      <div style="display:grid;grid-template-columns:130px 1fr;gap:8px;align-items:center">
        <label style="font-size:.75rem;color:#94a3b8">MAC</label>
        <input id="vm-mac" placeholder="e.g. F1:8A:86:DB:86:9E">
        <label style="font-size:.75rem;color:#94a3b8">Part number</label>
        <input id="vm-pn" placeholder="e.g. SHU050150200">
        <label style="font-size:.75rem;color:#94a3b8">Encryption key</label>
        <input id="vm-key" placeholder="VictronConnect \u2192 Product Info \u2192 Instant Readout (hex)">
        <label style="font-size:.75rem;color:#94a3b8">Serial</label>
        <input id="vm-serial" placeholder="e.g. HQ2602MZCRU">
        <label style="font-size:.75rem;color:#94a3b8">PUK</label>
        <input id="vm-puk" placeholder="e.g. BEA10864E821">
        <label style="font-size:.75rem;color:#94a3b8">BT PIN</label>
        <input id="vm-pin" placeholder="pairing PIN (VictronConnect)">
      </div>
      <div class="row" style="margin-top:14px;justify-content:flex-end">
        <button class="btn" style="margin-right:8px" onclick="vicClose()">Cancel</button>
        <button class="btn" onclick="vicSaveFromModal()">Save device</button>
      </div>
    </div>
  </div>
</div>
  <button class="btn reset" style="margin-top:12px" onclick="clearBle()">Clear selection</button>
</div>

<button class="btn" onclick="save()">Save</button>
<button class="btn reset" onclick="resetAll()">Reset all</button>
<div class="msg" id="msg"></div>

<script>
function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; }
const FIELDS = ["POLL_SECONDS", "POLL_SECONDS_NIGHT", "NIGHT_START", "NIGHT_END",
  "GPS_POLL_SECONDS", "GATT_POLL_SECONDS", "GPSBUF_POLL_SECONDS",
  "GPSBUF_RETENTION_DAYS", "GBUF_WRITE_SECONDS",
  "STATIONARY_SPEED_KN",
  "GPS_STATIONARY_INTERVAL", "SOLAR_HISTORY_DAYS"];
async function load() {
  const d = await (await fetch("api/settings")).json();
  FIELDS.forEach(f => { if (d[f] !== undefined) document.getElementById(f).value = d[f]; });
  _vicNotes = d.BLE_NOTES || {};
  vicRender(d.VICTRON_DEVICES || []);
}

let _vicDevs = [];
let _vicNotes = {};

function vicRender(devs) {
  _vicDevs = devs || [];
  const box = document.getElementById("vic-list");
  if (!_vicDevs.length) {
    box.innerHTML = "<p class='hint' style='margin:0'>No Victron devices configured. Click \u201c+ Add device\u201d to add one.</p>";
    return;
  }
  box.innerHTML = _vicDevs.map((d, i) => `
  <div onclick="vicOpen(${i})" style="display:flex;justify-content:space-between;align-items:center;gap:10px;border:1px solid #33415580;border-radius:8px;padding:10px 12px;margin-bottom:8px;cursor:pointer">
    <div>
      <div style="font-weight:600">${esc(vicTitle(d))}</div>
      <div style="font-size:.75rem;color:#94a3b8">${esc(d.mac)}${d.serial ? " \u00b7 " + esc(d.serial) : ""}${d.key ? " \u00b7 key \u2713" : " \u00b7 no key"}</div>
    </div>
    <div style="display:flex;gap:6px;align-items:center">
      <button class="btn" title="remove" onclick="event.stopPropagation();vicRemove(${i})">\u2715</button>
    </div>
  </div>`).join("");
}

function vicTitle(d) {
  const note = (_vicNotes || {})[(d.mac || "").toUpperCase()];
  return note || d.part_number || "Victron device";
}

function vicOpen(i) {
  const d = i >= 0 ? _vicDevs[i] : {};
  document.getElementById("vic-modal-title").textContent = (i >= 0 ? "Edit " : "New ") + vicTitle(d);
  document.getElementById("vm-mac").value = d.mac || "";
  document.getElementById("vm-pn").value = d.part_number || "";
  document.getElementById("vm-key").value = d.key || "";
  document.getElementById("vm-serial").value = d.serial || "";
  document.getElementById("vm-puk").value = d.puk || "";
  document.getElementById("vm-pin").value = d.bt_pin || "";
  document.getElementById("vic-modal").style.display = "flex";
  document.getElementById("vic-modal").dataset.editIndex = i;
}

function vicClose() {
  document.getElementById("vic-modal").style.display = "none";
}

function vicRemove(i) {
  const d = _vicDevs[i] || {};
  const name = (_vicNotes || {})[(d.mac || "").toUpperCase()] || d.part_number || d.mac || "this device";
  if (!confirm("Remove " + name + " from the Victron devices?")) return;
  _vicDevs.splice(i, 1);
  vicPost();
}

function vicSaveFromModal() {
  const i = parseInt(document.getElementById("vic-modal").dataset.editIndex, 10);
  const d = {
    mac: document.getElementById("vm-mac").value.trim(),
    part_number: document.getElementById("vm-pn").value.trim(),
    key: document.getElementById("vm-key").value.trim(),
    serial: document.getElementById("vm-serial").value.trim(),
    puk: document.getElementById("vm-puk").value.trim(),
    bt_pin: document.getElementById("vm-pin").value.trim(),
  };
  if (!d.mac) { alert("MAC is required"); return; }
  if (i >= 0) _vicDevs[i] = d; else _vicDevs.push(d);
  vicPost();
  vicClose();
}

async function vicPost() {
  const msg = document.getElementById("msg");
  const r = await fetch("api/settings", { method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({VICTRON_DEVICES: _vicDevs.length ? _vicDevs : null}) });
  const d = await r.json();
  if (r.ok) { msg.className = "msg ok"; msg.textContent = "Victron devices saved \u2713"; vicRender(d.VICTRON_DEVICES || []); }
  else { msg.className = "msg err"; msg.textContent = d.error || "error"; }
}
async function save() {
  const msg = document.getElementById("msg");
  const body = {};
  FIELDS.forEach(f => {
    const v = document.getElementById(f).value;
    if (v !== "") body[f] = Number(v);
  });
  const r = await fetch("api/settings", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) });
  const d = await r.json();
  if (r.ok) { msg.className = "msg ok"; msg.textContent = "Saved \u2713"; load(); }
  else { msg.className = "msg err"; msg.textContent = d.error || "error"; }
}
async function resetAll() {
  const body = {}; FIELDS.forEach(f => body[f] = null);
  body["BLE_DEVICES"] = null;
  body["VICTRON_DEVICES"] = null;
  const r = await fetch("api/settings", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) });
  const msg = document.getElementById("msg");
  if (r.ok) { msg.className = "msg ok"; msg.textContent = "Reset to .env values \u2713"; load(); loadBle(); }
  else { msg.className = "msg err"; msg.textContent = "error"; }
}

// ---- BLE device selection ----
async function loadBle() {
  const box = document.getElementById("ble-list");
  try {
    const d = await (await fetch("api/ble/devices")).json();
    if (d.error) { box.innerHTML = "<p class='hint' style='margin:0;color:#f87171'>" + d.error + "</p>"; return; }
    const sel = new Set(d.selected || []);
    if (!d.devices.length) { box.innerHTML = "<p class='hint' style='margin:0'>No BLE devices seen by the KNOT yet.</p>"; return; }
    box.innerHTML = d.devices.map(function(dev) {
      const checked = sel.has(dev.mac.toUpperCase()) ? " checked" : "";
      const tag = dev.persist ? " <span style='color:#34d399;font-size:.68rem'>&#9679; persistent</span>" : "";
      const rssi = dev.rssi != null ? dev.rssi + " dBm" : "no signal";
      return "<label style='display:block;padding:7px 0;border-bottom:1px solid #334155;cursor:pointer'>" +
        "<span style='display:flex;align-items:center;gap:10px'>" +
        "<input type='checkbox' class='ble-chk' value='" + dev.mac + "'" + checked + ">" +
        "<span style='flex:1'><b style='font-size:.8rem'>" + (dev.name || "(unnamed)") + "</b>" + tag +
        "<br><small style='color:#64748b;font-size:.68rem'>" + dev.mac + " · " + rssi + "</small></span>" +
        "</span>" +
        "<span style='display:flex;align-items:center;gap:10px;margin-top:5px'>" +
        "<span style='width:16px'></span>" +
        "<input type='text' class='ble-note' data-mac='" + dev.mac + "' value='" + String(dev.note || "").replace(/'/g, "&#39;") + "'" +
        " placeholder='note (used as the device title in the Victron list)' maxlength='40' style='flex:1;background:#0f172a;color:#e2e8f0;border:1px solid #334155;border-radius:6px;padding:5px 8px;font-size:.78rem'></span></label>";
    }).join("");
  } catch (e) {
    box.innerHTML = "<p class='hint' style='margin:0;color:#f87171'>KNOT unreachable</p>";
  }
}
async function saveBle() {
  const msg = document.getElementById("msg");
  const macs = Array.from(document.querySelectorAll(".ble-chk:checked")).map(c => c.value);
  const notes = {};
  document.querySelectorAll(".ble-note").forEach(i => { if (i.value.trim()) notes[i.dataset.mac] = i.value.trim(); });
  const r = await fetch("api/settings", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ BLE_DEVICES: macs, BLE_NOTES: notes }) });
  if (r.ok) { msg.className = "msg ok"; msg.textContent = macs.length ? "Selection saved: " + macs.length + " device(s) \u2713" : "Selection cleared \u2713"; }
  else { const d = await r.json(); msg.className = "msg err"; msg.textContent = d.error || "error"; }
}
async function clearBle() {
  const msg = document.getElementById("msg");
  const r = await fetch("api/settings", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({ BLE_DEVICES: null }) });
  if (r.ok) { msg.className = "msg ok"; msg.textContent = "Selection cleared \u2713"; loadBle(); }
  else { msg.className = "msg err"; msg.textContent = "error"; }
}
load();
loadBle();
</script>
</body>
</html>
"""


TRACK_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230f172a'/%3E%3Cg stroke='%2338bdf8' stroke-width='5' stroke-linecap='round' fill='none'%3E%3Ccircle cx='32' cy='15' r='6'/%3E%3Cline x1='32' y1='21' x2='32' y2='52'/%3E%3Cline x1='20' y1='30' x2='44' y2='30'/%3E%3Cpath d='M 14 40 C 14 55, 50 55, 50 40'/%3E%3Cline x1='14' y1='40' x2='20' y2='44'/%3E%3Cline x1='50' y1='40' x2='44' y2='44'/%3E%3C/g%3E%3C/svg%3E">
<title>Track history · Nautilus</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f172a; color: #e2e8f0; font-family: "Segoe UI", system-ui, sans-serif;
         min-height: 100vh; padding: 20px; }
  header { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 14px; }
  h1 { font-size: 1.3rem; color: #38bdf8; letter-spacing: .5px; }
  a.back { color: #7dd3fc; font-size: .82rem; text-decoration: none; border: 1px solid #334155;
           padding: 5px 10px; border-radius: 8px; background: #1e293b; }
  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: end; margin-bottom: 14px;
              background: #1e293b; padding: 14px; border-radius: 12px; border: 1px solid #334155; }
  .controls label { display: block; font-size: .66rem; color: #64748b; text-transform: uppercase;
                    letter-spacing: .5px; margin-bottom: 4px; }
  .controls input, .controls select { font: inherit; font-size: .85rem; padding: 6px 8px;
           border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; }
  .controls button { font: inherit; font-size: .85rem; padding: 7px 16px; border-radius: 8px;
           border: 0; background: #2563eb; color: #fff; cursor: pointer; }
  .controls button:hover { background: #1d4ed8; }
  #summary { font-size: .78rem; color: #94a3b8; margin-left: auto; align-self: center; }
  #map { height: calc(100vh - 210px); min-height: 400px; border-radius: 12px;
         border: 1px solid #334155; }
  .leaflet-tooltip { background: #1e293b !important; color: #e2e8f0 !important;
                     border: 1px solid #38bdf8 !important; border-radius: 8px;
                     font-size: .78rem; box-shadow: 0 4px 10px rgba(0,0,0,.5); }
  .leaflet-tooltip b { color: #38bdf8; }
</style>
</head>
<body>
<header>
  <h1>⚓ Track history</h1>
  <a class="back" href="./">&#8592; Dashboard</a>
</header>
<div class="controls">
  <div><label>From</label><input type="date" id="d-from"></div>
  <div><label>To</label><input type="date" id="d-to"></div>
  <div><label>Or last</label>
    <select id="d-last">
      <option value="">— use dates —</option>
      <option value="100">100 points</option>
      <option value="500" selected>500 points</option>
      <option value="2000">2000 points</option>
      <option value="5000">5000 points</option>
    </select></div>
  <button onclick="loadTrack()">Show</button>
  <span id="summary">loading…</span>
</div>
<div id="map"></div>
<script>
const COMPASS = ["N","NNE","NE","ENE","E","ESE","SE","SSE","S","SSW","SW","WSW","W","WNW","NW","NNW"];
function compass(deg) {
  if (deg == null || isNaN(deg)) return "—";
  return COMPASS[Math.round((((deg % 360) + 360) % 360) / 22.5) % 16] + " (" + Math.round(deg) + "°)";
}
function fmtTs(ts) { return ts ? ts.replace("T", " at ") : "—"; }

const map = L.map("map");
var osmAttr = "&co" + "py; OpenStreetMap";
L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
            { maxZoom: 19, attribution: osmAttr }).addTo(map);
L.tileLayer("https://tiles.openseamap.org/seamark/{z}/{x}/{y}.png",
            { maxZoom: 18, attribution: "OpenSeaMap" }).addTo(map);
const trackLayer = L.layerGroup().addTo(map);

async function loadTrack() {
  const last = document.getElementById("d-last").value;
  let url = "api/boat/track-history?";
  if (last) {
    url += "last=" + last;
  } else {
    const f = document.getElementById("d-from").value;
    const t = document.getElementById("d-to").value;
    if (f) url += "start_date=" + f + "&";
    if (t) url += "end_date=" + t;
  }
  trackLayer.clearLayers();
  const summary = document.getElementById("summary");
    const kmlBtn = document.getElementById("kml-export");
    if (kmlBtn) kmlBtn.href = "api/boat/track.kml?" + new URLSearchParams({start_date: document.getElementById("start-date").value, end_date: document.getElementById("end-date").value}).toString();
  summary.textContent = "loading…";
  try {
    const d = await (await fetch(url)).json();
    if (d.error) { summary.textContent = "Error: " + d.error; return; }
    const pts = d.points || [];
    if (!pts.length) { summary.textContent = "0 points — no positions in the period"; return; }
    summary.textContent = pts.length + " points";
    const latlngs = pts.map(p => [p.latitude, p.longitude]);
    L.polyline(latlngs, { color: "#38bdf8", weight: 3, opacity: .85 }).addTo(trackLayer);
    pts.forEach((p, i) => {
      const isFirst = i === 0, isLast = i === pts.length - 1;
      const buf = p.source === "buffer";
      const m = L.circleMarker([p.latitude, p.longitude], {
        radius: isFirst || isLast ? 6 : (buf ? 4.5 : 3.5),
        color: isFirst ? "#22c55e" : isLast ? "#f59e0b" : buf ? "#fb923c" : "#38bdf8",
        weight: 2, fillOpacity: .9,
        dashArray: buf ? "3,3" : null
      }).addTo(trackLayer);
      m.bindTooltip(
        "<b>" + (isFirst ? "Start" : isLast ? "Arrival" : "Point " + (i + 1)) + "</b>" +
        (buf ? " <span style='color:#fb923c'>· no coverage</span>" : "") + "<br>" +
        fmtTs(p.timestamp) + "<br>" +
        "Speed: " + (p.speed != null ? p.speed.toFixed(1) + " kn" : "n/a") + "<br>" +
        "Course: " + compass(p.heading),
        { direction: "top", offset: [-2, -6] }
      );
    });
    // legend when buffered points are present
    if (pts.some(p => p.source === "buffer")) {
      const lg = L.control({ position: "bottomright" });
      lg.onAdd = function() {
        const d = L.DomUtil.create("div", "legend");
        d.style.cssText = "background:#1e293bE6;padding:8px 12px;border-radius:8px;font-size:.75rem;color:#e2e8f0";
        d.innerHTML = "<span style='color:#38bdf8'>●</span> live · <span style='color:#fb923c'>◌</span> recovered (no coverage)";
        return d;
      };
      lg.addTo(map);
    }
    map.fitBounds(L.latLngBounds(latlngs).pad(0.15));
  } catch (e) {
    summary.textContent = "endpoint unreachable";
  }
}
loadTrack();
</script>
</body>
</html>
"""

KNOT_LOGS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230f172a'/%3E%3Cg stroke='%2338bdf8' stroke-width='5' stroke-linecap='round' fill='none'%3E%3Ccircle cx='32' cy='15' r='6'/%3E%3Cline x1='32' y1='21' x2='32' y2='52'/%3E%3Cline x1='20' y1='30' x2='44' y2='30'/%3E%3Cpath d='M 14 40 C 14 55, 50 55, 50 40'/%3E%3Cline x1='14' y1='40' x2='20' y2='44'/%3E%3Cline x1='50' y1='40' x2='44' y2='44'/%3E%3C/g%3E%3C/svg%3E">
<title>KNOT logs · {{BOAT}}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f172a; color: #e2e8f0; font-family: "Segoe UI", system-ui, sans-serif;
         min-height: 100vh; padding: 20px; }
  header { display: flex; align-items: baseline; gap: 14px; flex-wrap: wrap; margin-bottom: 14px; }
  h1 { font-size: 1.3rem; color: #38bdf8; letter-spacing: .5px; }
  a.back { color: #7dd3fc; font-size: .82rem; text-decoration: none; border: 1px solid #334155;
           padding: 5px 10px; border-radius: 8px; background: #1e293b; }
  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: end; margin-bottom: 14px;
              background: #1e293b; padding: 14px; border-radius: 12px; border: 1px solid #334155; }
  .controls label { display: block; font-size: .66rem; color: #64748b; text-transform: uppercase;
                    letter-spacing: .5px; margin-bottom: 4px; }
  .controls select, .controls input { font: inherit; font-size: .85rem; padding: 6px 8px;
           border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: #e2e8f0; }
  .controls .grp { display: flex; flex-direction: column; }
  .hint { color: #64748b; font-size: .75rem; margin-bottom: 12px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: .8rem; }
  th { text-align: left; color: #64748b; font-size: .66rem; text-transform: uppercase;
       letter-spacing: .5px; padding: 10px 12px; border-bottom: 1px solid #334155; }
  td { padding: 7px 12px; border-bottom: 1px solid #172033; vertical-align: top;
       font-family: ui-monospace, Consolas, monospace; }
  td.time { white-space: nowrap; color: #94a3b8; }
  td.topics { white-space: nowrap; color: #64748b; }
  tr.warn td { background: #2a2302; }
  tr.warn td.topics { color: #f59e0b; }
  tr.err td { background: #2d0a0a; }
  tr.err td.topics { color: #ef4444; }
  .pill { display: inline-block; font-size: .68rem; padding: 2px 9px; border-radius: 999px;
          background: #1e3a5f; color: #7dd3fc; }
  .count { color: #64748b; font-size: .78rem; margin: 10px 2px; }
</style>
</head>
<body>
<header>
  <h1>&#128225; KNOT logs · {{BOAT}}</h1>
  <a class="back" href="./">&#8592; Dashboard</a>
</header>
<div class="controls">
  <div class="grp">
    <label>Archive (every log download)</label>
    <select id="file"></select>
  </div>
  <div class="grp">
    <label>Filter text</label>
    <input id="q" placeholder="es. error, reboot, lte…">
  </div>
  <div class="grp">
    <label>Show</label>
    <select id="lvl">
      <option value="all">all rows</option>
      <option value="warn">warnings + errors only</option>
      <option value="err">errors only</option>
    </select>
  </div>
</div>
<p class="hint">Each archive is a full snapshot of the KNOT system log, saved server-side
every "KNOT log download" seconds (Settings) and right after a coverage gap.
Rows appear newest-first here.
All times are local ({{TZ}}).</p>
<div class="card">
  <table id="tbl">
    <thead><tr><th>Time ({{TZ}})</th><th>Topics</th><th>Message</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
<p class="count" id="count"></p>
<script>
const esc = s => { const d = document.createElement("div"); d.textContent = s == null ? "" : String(s); return d.innerHTML; };
let ROWS = [];
const fmtSize = b => b >= 1048576 ? (b/1048576).toFixed(1) + " MB" : (b/1024).toFixed(0) + " KB";

async function loadFiles(sel) {
  const d = await (await fetch("api/knot/logs")).json();
  const f = document.getElementById("file");
  const tz = "{{TZ}}";
  f.innerHTML = (d.files || []).map(x =>
    `<option value="${x.file}">${x.file.slice(6, 8)}/${x.file.slice(4, 6)} ${x.file.slice(9, 11)}:${x.file.slice(11, 13)}:${x.file.slice(13, 15)} ${tz} · ${fmtSize(x.size)}</option>`).join("");
  if (sel) f.value = sel;
  if (f.value) loadRows(f.value);
}

async function loadRows(name) {
  const d = await (await fetch("api/knot/logs?file=" + encodeURIComponent(name))).json();
  ROWS = (d.rows || []).slice().reverse();   // newest first
  render();
}

function render() {
  const q = document.getElementById("q").value.trim().toLowerCase();
  const lvl = document.getElementById("lvl").value;
  const rows = ROWS.filter(r => {
    if (q && !((r.message || "") + " " + (r.topics || "")).toLowerCase().includes(q)) return false;
    const t = (r.topics || "");
    if (lvl === "warn" && !(t.includes("warning") || t.includes("error"))) return false;
    if (lvl === "err" && !t.includes("error")) return false;
    return true;
  });
  const tb = document.querySelector("#tbl tbody");
  tb.innerHTML = rows.map(r => {
    const t = (r.topics || "");
    const cls = t.includes("error") ? "err" : (t.includes("warning") ? "warn" : "");
    return `<tr class="${cls}"><td class="time">${esc(r.time || "")}</td>` +
      `<td class="topics">${esc(t)}</td><td>${esc(r.message || "")}</td></tr>`;
  }).join("") || `<tr><td colspan="3" style="color:#64748b;padding:16px">No rows match.</td></tr>`;
  document.getElementById("count").textContent =
    `${rows.length} of ${ROWS.length} rows shown`;
}

document.getElementById("file").addEventListener("change", e => loadRows(e.target.value));
document.getElementById("q").addEventListener("input", render);
document.getElementById("lvl").addEventListener("change", render);
loadFiles();
</script>
</body>
</html>
"""

BL917_ENABLED = os.environ.get("BL917_ENABLED", "0") == "1"

if __name__ == "__main__":
    _runtime_cfg_load()             # override persistenti (Settings)
    fetch_devices()                    # primo giro immediato
    fetch_lte()                         # segnale LTE immediato
    if BL917_ENABLED:                   # MPPT BL917 via cloud
        fetch_bl917()
        threading.Thread(target=bl917_loop, daemon=True).start()
    threading.Thread(target=poll_loop, daemon=True).start()
    threading.Thread(target=data_usage_loop, daemon=True).start()
    threading.Thread(target=gps_loop, daemon=True).start()
    threading.Thread(target=gatt_loop, daemon=True).start()
    log.info("nautilus-telemetry in ascolto su :8080 (poll KNOT ogni %ds)", POLL_SECONDS)
    app.run(host="0.0.0.0", port=8080)
