#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nautilus-telemetry — dashboard BLE per sensori inoltrati dal MikroTik KNOT via WireGuard.

Supported devices (configured via environment variables, see docs/MANUAL.md):
  * Leagend BM6 battery monitor (BLE advertisements + GATT)
  * Power Queen / Lumiax BT-PQCC2430 MPPT solar charger (BLE advertisements)
  * BL917 MPPT via ZhiJinPower cloud (optional)
  * Victron SmartSolar MPPT (encrypted Instant Readout advertisements, optional)

Decodifica basata sui progetti open-source:
  * BM6:  https://github.com/JeffWDH/bm6-battery-monitor
          https://www.tarball.ca/posts/reverse-engineering-the-bm6-ble-battery-monitor/
          https://github.com/Rafciq/BM6 (layout frame real-time)
  * MPPT: https://github.com/rahulthakoor/solarlife-mppt-ble-client
          https://github.com/subDesTagesMitExtraKaese/solarlife-mppt-ble-client

Formati osservati sui frame reali (verificato empiricamente su 3 dispositivi):

  BM6 iBeacon (Apple):
    02 01 06 1A FF 4C 00 02 15 <UUID(16)> <major(2 BE)> <minor(2 BE)> <tx@1m>
    major/minor = ID statici del beacon (funzione "vehicle finder"), NON la tensione:
    verificato empiricamente (major costante per ore, valore 4428 fisso).

  BM6 frame cifrato (service data 0xFFF0, 16 byte AES-128-CBC, IV nullo):
    AD "03 02 F0 FF 11 FF" + 16 byte cifrati. Dopo decifratura:
      byte 0..5   MAC del dispositivo
      byte 6      tipo frame (05 osservato)
      byte 7      temperatura (°C)
      byte 8      SoC (%)
      byte 9      segno temperatura (00 = +, 01 = −)
      byte 10     stato (00=OK, 01=tensione bassa, 02=in carica, altro=sconosciuto)
      byte 11-12  tensione BE/100 (non sempre popolata: 0x0000 se assente)

  MPPT BT-PQCC2430 (adv):
    03 03 E0 FF   → servizio UART 0xFFE0 (canale Modbus RTU via BLE GATT)
    09 FF 5A 58 <MAC> 0C   → manufacturer data ("ZX" + MAC)
    0C 09 "BT-PQCC2430"   → nome locale
    L'advertisement NON contiene i registri Modbus (V_pv/V_bat/I_bat si
    leggono solo con connessione GATT, che il KNOT non inoltra): il parser
    Modbus resta attivo con sanity-check nel caso i dati arrivassero.

Dipendenze: solo flask + requests (AES implementato in puro Python).
Il parser Victron usa pycryptodome (AES-CTR, se disponibile).
"""

import base64
import json
import logging
import os
import re
import threading
import time
from datetime import datetime

import requests
from flask import Flask, jsonify, request

# --------------------------------------------------------------------------
# Configurazione (tutto parametrico via environment, vedi docs/MANUAL.md)
# --------------------------------------------------------------------------
KNOT_HOST = os.environ.get("KNOT_HOST", "")
KNOT_USER = os.environ.get("KNOT_USER", "")
KNOT_PASS = os.environ.get("KNOT_PASS", "")
KNOT_URL = f"http://{KNOT_HOST}/rest/iot/bluetooth/peripheral-devices"
KNOT_GPS_URL = f"http://{KNOT_HOST}/rest/system/gps/monitor"
KNOT_LTE_URL = f"http://{KNOT_HOST}/rest/interface/lte/monitor"
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "60"))
# Poll ridotto di notte (orario locale; 0 = disattivato, si usa sempre POLL_SECONDS)
NIGHT_START = int(os.environ.get("NIGHT_START", "22"))
NIGHT_END = int(os.environ.get("NIGHT_END", "7"))
POLL_SECONDS_NIGHT = int(os.environ.get("POLL_SECONDS_NIGHT", "0"))
GPS_POLL_SECONDS = 120   # il monitor GPS è bloccante (~15-20s): cadenza dedicata

# Intervallo di reporting adattivo: se la barca è ferma (speed < soglia) la
# costosa chiamata GPS al KNOT viene saltata finché non sono trascorsi
# GPS_STATIONARY_INTERVAL secondi dall'ultimo fix valido (risparmio consumi).
STATIONARY_SPEED_KN = float(os.environ.get("STATIONARY_SPEED_KN", "0.5"))
GPS_STATIONARY_INTERVAL = int(os.environ.get("GPS_STATIONARY_INTERVAL", "600"))

# Storico produzione solare (SQLite locale; dir montata come volume).
SOLAR_DB = os.environ.get("SOLAR_DB", "data/nautilus.db")

# MAC addresses of the BLE sensors (required)
BM6_MAC = os.environ.get("BM6_MAC", "").upper()
MPPT_MAC = os.environ.get("MPPT_MAC", "").upper()

# Chiave AES-128 BM6 (JeffWDH/bm6-battery-monitor): "leagend\xff\xfe0100009"
BM6_KEY = bytes([108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57])
BM6_ADV_MARKER = "0302f0ff11ff"   # AD: UUID servizio 0xFFF0 + 0x11 0xFF + blocco AES

MPPT_SERVICE_UART = "0303e0ff"    # AD: lista UUID 16-bit con 0xFFE0 (canale Modbus)

BM6_STATES = {0: "OK", 1: "Low voltage", 2: "Charging"}

# Stima SoC dalla tensione a riposo (come fa l'app BM6 col profilo batteria).
# Il SoC interno del firmware BM6 è tarato su batterie auto 12V piombo-acido e
# riporta valori senza senso su LiFePO4; con BM6_BATTERY_TYPE settato mostriamo
# anche la stima ricavata dalla tensione. Solo indicativa: in carica/scarica la
# tensione è spostata rispetto al valore a riposo.
BM6_SOC_CURVES = {
    "lifepo4": [  # (V, SoC%) 12V LiFePO4 a riposo (piatta nel mezzo: stima grossolana)
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

# Correzione temperatura (°C, sommata al valore del sensore): il chip del BM6
# si auto-riscalda e la sua temperatura interna sta sopra quella ambiente
# (l'app BM6 applica una calibrazione equivalente). Esempio: -18 per un chip
# che a 20 °C ambiente legge 38 °C.
BM6_TEMP_OFFSET = float(os.environ.get("BM6_TEMP_OFFSET", "0"))


def estimate_soc(voltage, btype=None):
    """Interpola il SoC dalla tensione a riposo secondo la curva del tipo batteria."""
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

# GATT via REST (RouterOS >= 7.12): lettura voltaggio reale dal BM6.
# Il comando "d15507..." cifrato AES è costante (chiave BM6, IV nullo) —
# verificato identico a quello usato dal repo JeffWDH e dal post tarball.ca.
KNOT_GATT = f"http://{KNOT_HOST}/rest/iot/bluetooth/connections"
BM6_GATT_CMD = "697ea0b5d54cf024e794772355554114"   # encrypt("d15507" + 00*10)
GATT_POLL_SECONDS = 120   # cadenza dedicata (connect+read ~15-20s)

# --------------------------------------------------------------------------
# BL917 MPPT: i dati vivono sul cloud ZhiJinPower (ws://device.gz529.com)
# e si leggono via websocket usando solo il MAC. Nessun GATT disponibile.
# --------------------------------------------------------------------------
BL917_WS = os.environ.get("BL917_WS", "ws://device.gz529.com/")
BL917_MAC = os.environ.get("BL917_MAC", "")
BL917_POLL_SECONDS = 300   # 5 min: il cloud è lento, inutile martellarlo

# Correzione temperatura BL917 (°C, sommata al valore dal cloud): come per il
# BM6, il sensore misura il chip interno, non l'aria. 0 = nessuna correzione.
BL917_TEMP_OFFSET = float(os.environ.get("BL917_TEMP_OFFSET", "0"))

# --------------------------------------------------------------------------
# Victron SmartSolar MPPT: dati via advertisement "Instant
# Readout" cifrati AES-128-CTR. Protocollo: manufacturer data 0x02E1,
# payload 0x10 <model_id LE16> <readout_type> <iv LE16> <encrypted>.
# La chiave si legge in VictronConnect (Product Info → Instant Readout
# Details) oppure va derivata; il primo byte cifrato è un key-check byte
# (deve coincidere col primo byte della chiave).
# --------------------------------------------------------------------------
VICTRON_MAC = os.environ.get("VICTRON_MAC", "").upper()
VICTRON_ADV_KEY = os.environ.get("VICTRON_ADV_KEY", "").lower()
VICTRON_SERIAL = os.environ.get("VICTRON_SERIAL", "")
VICTRON_PUK = os.environ.get("VICTRON_PUK", "")
VICTRON_MARKER = "ffe10210"    # AD type FF + company 0x02E1 (LE) + prefix 0x10

VIC_CHARGE_STATES = {0: "Off", 1: "Low power", 2: "Fault", 3: "Bulk",
                     4: "Absorption", 5: "Float", 6: "Storage",
                     7: "Equalize (manual)", 9: "Inverting", 11: "Power supply",
                     245: "Starting up", 246: "Repeated absorption",
                     247: "Recondition", 248: "Battery safe", 249: "Active",
                     252: "External control"}


def _victron_ctr_decrypt(key, iv, data):
    """AES-128-CTR con contatore little-endian (come victron-ble/pycryptodome)."""
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    ctr = Counter.new(128, initial_value=iv, little_endian=True)
    return AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(data + b"\x00" * (-len(data) % 16))


def _victron_derive_key(serial, puk):
    """Candidati di derivazione chiave da seriale+PUK (da validare col
    key-check byte del primo frame: se non matcha, nessuno è corretto)."""
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
    """Decodifica l'advertisement Instant Readout di un caricabatterie Victron.

    Ritorna dict con i dati del solar charger, o con 'error' se la chiave
    non è valida (key-check byte mismatch).
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
        data = bytes.fromhex(payload[:40])
    except ValueError:
        out["error"] = "malformed advertisement"
        return out
    # layout victron-ble: prefix(2: 10 02) model(LE16) readout(1) iv(LE16) enc(check+12)
    if len(data) < 19:
        out["error"] = "advertisement too short"
        return out
    model_id = data[1] | (data[2] << 8)
    readout_type = data[3]
    iv = data[4] | (data[5] << 8)
    enc = data[6:19]
    key = bytes.fromhex(adv_key)
    if enc[0] != key[0]:
        out["error"] = "advertisement key mismatch (key-check byte)"
        return out
    dec = _victron_ctr_decrypt(key, iv, enc[1:])
    b = dec[:12]
    def _s16(v): return v - 0x10000 if v & 0x8000 else v
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
        # 9 bit little-endian a partire dal byte 10
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


def save_position(gps):
    """Invia il fix valido a conticini (che fa la deduplica < 25 m)."""
    if not gps or not gps.get("valid") or not INTERNAL_TOKEN:
        return False
    try:
        r = requests.post(CONTICINI_BASE + "/internal/boat/position",
                          headers=_conticini_headers(),
                          json={"timestamp": gps.get("fix_time_iso"),
                                "latitude": gps["latitude"],
                                "longitude": gps["longitude"],
                                "speed": gps.get("speed_kn"),
                                "heading": gps.get("true_bearing"),
                                "satellites": gps.get("satellites"),
                                "altitude_m": gps.get("altitude_m")},
                          timeout=10)
        r.raise_for_status()
        return r.json().get("saved", False)
    except Exception as exc:
        log.warning("Invio posizione a conticini fallito: %s", exc)
        return False

# --------------------------------------------------------------------------
# Storico produzione solare: campiona la potenza del pannello a ogni poll
# (60 s) su SQLite locale, la espone via API e costruisce una previsione
# dalla media delle curve dei giorni precedenti.
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
    con.commit()
    return con


def log_solar_sample():
    """Registra un campione di potenza solare (W) dalla fonte disponibile."""
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
    """Registra un campione di consumo (W): i_load * v_bat dalla fonte disponibile."""
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


def _samples_daily(table):
    """Curve 30-min di una tabella di campioni: oggi, ieri, previsione."""
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
    """Curve di consumo: oggi, ieri e previsione (bucket 30 min)."""
    return _samples_daily("load_samples")


def _totals():
    """Totali per mese e per anno di produzione e consumo (kWh)."""
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


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nautilus-telemetry")

# --------------------------------------------------------------------------
# AES-128 in puro Python (solo decrypt, per non aggiungere dipendenze)
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
    """Moltiplicazione in GF(2^8) (per InvMixColumns)."""
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
        for r in range(1, 4):                    # riga r: rotazione a destra di r
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
    """AES-128-CBC decrypt (senza padding)."""
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
    """Decodifica il dispositivo BM6: iBeacon (voltaggio) + frame cifrato."""
    out = {
        "name": dev.get("name", "BM6"),
        "mac": dev.get("address", ""),
        "voltage": None,          # V (da iBeacon major/100)
        "major": None,
        "minor": None,
        "uuid": None,
        "soc": None,              # % (frame cifrato)
        "temperature": None,      # °C (frame cifrato)
        "state_code": None,
        "state": None,            # testo
        "frame_voltage": None,     # V dal frame cifrato (se popolata)
        "rssi": dev.get("rssi"),
        "last_seen": (dev.get("last-seen") or "").split(" ")[-1],
        "raw_adv": dev.get("last-data"),
        "frames": [],
    }

    # --- iBeacon: ID beacon ("vehicle finder"), NON la tensione ---
    # Verificato empiricamente: major costante per ore (4428) e valore impossibile
    # per una batteria 12V — non e' una misura. La tensione arriva solo dal campo
    # del frame cifrato (byte 11-12), che spesso vale 0x0000 (non popolato).
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
                        # byte con segno (two's complement, es. 0xF1 → −15 °C)
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
    """Decodifica il MPPT Power Queen/Lumiax (registri Modbus via BLE 0xFFE0).

    L'advertisement contiene solo servizio 0xFFE0 + nome. I registri Modbus RTU
    (V_pv, V_bat, I_charge — progetto solarlife-mppt-ble-client) arrivano solo
    via connessione GATT, che il MikroTik KNON non inoltra: il parser resta
    attivo con sanity-check nel caso i dati fossero presenti nel payload.
    """
    out = {
        "name": dev.get("name", "MPPT"),
        "mac": dev.get("address", ""),
        "v_pv": None, "v_bat": None, "c_charge": None, "watt": None,
        "adv_name": None,
        "telemetry": False,       # True se registri Modbus decodificati
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
    # il nome è preceduto da AD con length; cerca pattern length 0x0C 09
    if "0c0942542d5051" in raw:  # 0C 09 "BT-PQ"
        try:
            start = raw.index("0c09") + 4
            length = int(raw[raw.index("0c09"):raw.index("0c09") + 2], 16) - 1
            out["adv_name"] = bytes.fromhex(raw[start:start + length * 2]).decode("ascii", "replace")
        except Exception:
            pass

    # Registri Modbus incapsulati (se un domani presenti nel last-data):
    # byte 0..1 BE /10 = V_pv, byte 2..3 BE /10 = V_bat, byte 4..5 BE /10 = I_carica.
    # Il payload Modbus NON inizia con gli AD standard (02 01 06 ...): lo cerchiamo
    # solo in un blocco esadecimale "nudo" di almeno 6 byte con valori plausibili.
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
# Polling del KNOT
# --------------------------------------------------------------------------
# Override a runtime (tab Settings):vincolati ai limiti di sicurezza
_runtime_cfg = {}    # es. {"POLL_SECONDS": "120"}

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
        "STATIONARY_SPEED_KN": _cfg_float("STATIONARY_SPEED_KN", STATIONARY_SPEED_KN),
        "GPS_STATIONARY_INTERVAL": max(30, _cfg("GPS_STATIONARY_INTERVAL", GPS_STATIONARY_INTERVAL)),
        "solar_history_days": max(1, _cfg("SOLAR_HISTORY_DAYS", 7)),
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
    "gps_ok": False,
    "error": None,
}
# Ritenzione valori letti solo da alcuni frame (il KNOT espone l'ultimo adv
# ricevuto: il BM6 alterna iBeacon e frame cifrato)
_bm6_keep = {}


def _bm6_retain(parsed):
    """Mantiene SoC/temperatura/stato dell'ultimo frame cifrato valido."""
    global _bm6_keep
    now = datetime.now().strftime("%H:%M:%S")
    for key in ("soc", "temperature", "state", "state_code", "frame_voltage"):
        kept = _bm6_keep.get(key)
        if kept and kept.get("src") == "gatt":
            # il GATT è la misura diretta del sensore: l'adv non sovrascrive
            parsed[key] = kept["value"]
            continue
        v = parsed.get(key)
        if v is not None:
            _bm6_keep[key] = {"value": v, "seen": now}
        elif kept:
            parsed[key] = kept["value"]
    if _bm6_keep:
        parsed["cached_fields_seen"] = _bm6_keep.get("soc", {}).get("seen", now)
    # voltaggio: la lettura GATT (reale) ha la precedenza su tutto;
    # altrimenti frame cifrato, altrimenti niente (il major NON è la tensione)
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
    # segnale BM6: età dell'ultima lettura GATT (None = mai letto).
    # > 5 min = il sensore non trasmette più (KNOT offline, BM6 spento o
    # occupato da un'altra connessione BLE).
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
    """Legge il GPS del KNOT (comando bloccante: chiamato dal thread dedicato)."""
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
                # timestamp locale completo per lo storico (ora del container = ora barca)
                "fix_time_iso": datetime.now().isoformat(timespec="seconds"),
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
    """Poll GPS adattivo: da fermo (ultimo fix sotto la soglia di velocità)
    salta del tutto la chiamata bloccante al KNOT fino a
    GPS_STATIONARY_INTERVAL secondi dall'ultimo fix; in movimento usa la
    cadenza normale. Il risparmio sta nel non fare il monitor GPS (~15-20 s
    di radio accesa) e la POST allo storico."""
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
            # resta fermo: ri-controlla ogni 60 s finché non scade l'intervallo
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
    """Legge i dati reali dal BM6 via GATT (RouterOS >= 7.12, ruolo central).

    Mantiene la connessione persistente: il BM6 invia notifiche real-time su
    fff4 solo finché resta connesso con subscription attiva. Se la connessione
    esiste già la riusa; al primo giro connect + subscribe + write del comando.
    """
    global _bm6_keep
    try:
        conns = _gatt_get("")
        _mac_l = BM6_MAC.lower()
        # risolve il NOME del peripheral: sulle connessioni
        # RouterOS il campo name può essere il nome dispositivo, non il MAC
        r0 = requests.get(KNOT_URL, auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS), timeout=15)
        r0.raise_for_status()
        dev = next((d for d in r0.json()
                    if d.get("address", "").upper() == BM6_MAC and d.get("persist") == "true"), None)
        if not dev:
            log.warning("GATT: BM6 non presente nella tabella KNOT")
            return
        dev_name = (dev.get("name") or "").lower()
        conn = next((c for c in conns
                     if _mac_l in (c.get("name") or "").lower()
                     or _mac_l in (c.get("pdev") or "").lower()
                     or (dev_name and dev_name in (c.get("name") or "").lower())), None)
        if not conn:
            # non connesso: connect (alcuni KNOT vogliono il MAC, altri il .id)
            try:
                _gatt_post("/connect", {"pdev": BM6_MAC})
            except Exception:
                try:
                    _gatt_post("/connect", {"pdev": dev[".id"]})
                except Exception:
                    pass   # già connesso con altro identificativo: riprova il match
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
        # (re)attiva le notifiche e rilancia il comando real-time: idempotente
        _gatt_post("/subscribe", {"pdev": pdev, "uuid": "fff4"})
        _gatt_post("/write", {"pdev": pdev, "uuid": "fff3", "data-hex": BM6_GATT_CMD})
        time.sleep(3)
        raw = requests.get(KNOT_GATT + "/async-data",
                           auth=requests.auth.HTTPBasicAuth(KNOT_USER, KNOT_PASS), timeout=20)
        raw.raise_for_status()
        text = raw.content.decode("utf-8", "replace")
        import re as _re
        # notifiche del BM6 (fff4): decifra, tieni l'ultima valida con voltaggio
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
    """Interroga il cloud ZhiJinPower per i dati del BL917.

    Nessuna autenticazione: solo il MAC. Se il controller non è mai stato
    registrato via app, il cloud risponde con data vuote → 'registered': False.
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
        # sanity check sul voltaggio (12 V nominali)
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
    """Legge la qualità del segnale LTE del KNOT (richiesta rapida, non bloccante).

    Prima recupera l'.id dell'interfaccia LTE (può cambiare dopo un reboot),
    poi chiede il monitor con i valori RSRP/RSRQ/SINR/RSSI.
    """
    try:
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


def fetch_devices():
    """Scarica i peripheral-devices dal KNOT (solo persist=true)."""
    global VICTRON_ADV_KEY
    try:
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
        # con BL917 abilitato i dati MPPT arrivano dal thread cloud:
        # non sovrascriverli col parser BLE (il MAC è lo stesso dispositivo)
        if not BL917_ENABLED:
            _state["mppt"] = parse_mppt(by_mac[MPPT_MAC]) if MPPT_MAC in by_mac else None
        # Victron SmartSolar: advertisement cifrato, decodifica diretta.
        # Il KNOT potrebbe non averlo in tabella persistente: cerca tra TUTTI i
        # dispositivi visti quello col marker del manufacturer data 0x02E1.
        if VICTRON_SERIAL or VICTRON_MAC:
            dev = (by_mac.get(VICTRON_MAC) if VICTRON_MAC else None)
            if dev is None:
                dev = next((d for d in r.json()
                            if VICTRON_MARKER in (d.get("last-data") or "").lower()), None)
            if dev:
                key = VICTRON_ADV_KEY
                parsed = parse_victron(dev, key) if key else {"error": "VICTRON_ADV_KEY not configured"}
                if parsed.get("error") == "advertisement key mismatch (key-check byte)" \
                        and VICTRON_SERIAL and VICTRON_PUK:
                    # prova a derivare la chiave da seriale+PUK e blocca quella valida
                    for cand in _victron_derive_key(VICTRON_SERIAL, VICTRON_PUK):
                        try:
                            trial = parse_victron(dev, cand)
                        except Exception:
                            continue
                        if not trial.get("error"):
                            log.info("Victron: chiave derivata da seriale+PUK: %s", cand)
                            VICTRON_ADV_KEY = cand
                            parsed = trial
                            break
                _state["victron"] = parsed
            else:
                _state["victron"] = {"error": "Victron device not seen by the KNOT"}
        _state["source_ok"] = True
        _state["error"] = None
    except Exception as exc:
        log.error("Polling KNOT fallito: %s", exc)
        _state["source_ok"] = False
        _state["error"] = str(exc)
    finally:
        _state["last_poll"] = datetime.now().strftime("%H:%M:%S")
        _state["updated"] = datetime.now().isoformat(timespec="seconds")


def poll_loop():
    while True:
        fetch_devices()
        log_solar_sample()
        log_load_sample()
        fetch_lte()
        time.sleep(_poll_seconds())


# --------------------------------------------------------------------------
# Interfaccia web (Flask)
# --------------------------------------------------------------------------
app = Flask(__name__)

# prefisso URL alternativo per la dashboard (default: /nautilus)
URL_PREFIX_ALIAS = os.environ.get("URL_PREFIX_ALIAS") or "/nautilus"
# nome barca mostrato nella dashboard
BOAT_NAME = os.environ.get("BOAT_NAME", "Nautilus")
VERSION = "1.13.0"


@app.route("/api/data")
@app.route("/nautilus/api/data")
@app.route(URL_PREFIX_ALIAS + "/api/data")
def api_data():
    _state["version"] = VERSION
    return jsonify(_state)


@app.route("/")
@app.route("/nautilus/")
@app.route("/nautilus")
@app.route(URL_PREFIX_ALIAS + "/")
@app.route(URL_PREFIX_ALIAS)
def dashboard():
    return DASHBOARD_HTML.replace("{{BOAT}}", BOAT_NAME)


# --------------------------------------------------------------------------
# Rotta storica della barca (posizioni salvate nel DB conticini)
# --------------------------------------------------------------------------

@app.route("/api/boat/track-history")
@app.route("/nautilus/api/boat/track-history")
@app.route(URL_PREFIX_ALIAS + "/api/boat/track-history")
def api_track_history():
    """Cronologia dei punti della barca (proxy verso lo storico in conticini).

    Filtri: ?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD  oppure  ?last=N
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
    """Curve di consumo: oggi, ieri e previsione (bucket 30 min)."""
    try:
        return jsonify(load_daily())
    except Exception as exc:
        log.warning("load daily: %s", exc)
        return jsonify({"error": "load history unavailable"}), 503


@app.route("/api/settings")
@app.route("/nautilus/api/settings")
@app.route(URL_PREFIX_ALIAS + "/api/settings")
def api_settings_get():
    return jsonify(_cfg_snapshot())


@app.route("/api/settings", methods=["POST"])
@app.route("/nautilus/api/settings", methods=["POST"])
@app.route(URL_PREFIX_ALIAS + "/api/settings", methods=["POST"])
def api_settings_post():
    """Override a runtime dei parametri di poll (tab Settings).
    Valori fuori dai limiti vengono rifiutati; null azzera l'override."""
    body = request.get_json(silent=True) or {}
    limits = {
        "POLL_SECONDS": (60, 3600),
        "POLL_SECONDS_NIGHT": (0, 3600),
        "GPS_POLL_SECONDS": (60, 3600),
        "GATT_POLL_SECONDS": (60, 3600),
        "STATIONARY_SPEED_KN": (0.0, 20.0),
        "GPS_STATIONARY_INTERVAL": (30, 7200),
        "SOLAR_HISTORY_DAYS": (1, 30),
        "NIGHT_START": (0, 23),
        "NIGHT_END": (0, 23),
    }
    for k, v in body.items():
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
    return jsonify(_cfg_snapshot())


@app.route("/stats")
@app.route("/nautilus/api/stats/totals")
@app.route(URL_PREFIX_ALIAS + "/api/stats/totals")
def api_stats_totals():
    """Totali per mese e anno di produzione e consumo (kWh)."""
    try:
        return jsonify(_totals())
    except Exception as exc:
        log.warning("stats totals: %s", exc)
        return jsonify({"error": "stats unavailable"}), 503


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
  <div class="card" id="gps"></div>
  <div class="card" id="lte"></div>
  <div class="card" id="solar"></div>
  <div class="card" id="load"></div>
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
    " · updated " + (d.last_poll || "—");
  document.getElementById("version").textContent = d.version ? "v" + d.version : "";

  // ---- BM6 ----
  const b = d.bm6;
  const bm6 = document.getElementById("bm6");
  if (!b) {
    bm6.innerHTML = "<h2>BM6-{{BOAT}}</h2><div class='note'>Device not seen by the KNOT.</div>";
  } else {
    const cls = chipClass(b.voltage);
    // SoC e stato mostrati: se disponibile la stima dal profilo batteria (soc_est),
    // il SoC/stato del firmware BM6 è tarato su batterie auto piombo-acido e su
    // LiFePO4 riporta assurdità (12% con batteria carica, "Tensione bassa" a 13.6V).
    const soc = b.soc_est != null ? b.soc_est : b.soc;
    let stTxt;
    if (b.soc_est != null) {
      stTxt = b.state_code === 2 ? "Charging" : (b.soc_est >= 20 ? "OK" : "Low voltage");
    } else {
      stTxt = b.state ? b.state : "n/a";
    }
    const vTxt = b.voltage != null ? b.voltage.toFixed(2) : "—";
    // segnale BM6: verde se l'ultima lettura GATT è fresca, rosso se il sensore
    // non trasmette più (vedi gatt_age_s dal backend)
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
          <div id="map"></div>
          <iframe id="gmap-frame" loading="lazy" style="display:none"
            src="about:blank"></iframe>
        </div>
        <a class="gmaps-link" id="gmaps-link" href="${gmaps}" target="_blank" rel="noopener">Open in Google Maps ↗</a>
        <div class="foot"><div class="row">GPS fix at <span id="gps-fixtime">${esc(g.fix_time)}</span> (KNOT time)</div></div>`;
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
      // aggiornamenti successivi: tocco solo i valori, la mappa resta com'è
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
</style>
</head>
<body>
<header>
  <h1>&#9889; Energy stats</h1>
  <a class="back" href="./">&#8592; Dashboard</a>
</header>
<div class="card">
  <h2>&#2600;&#65039; Solar production vs &#128506; current used — by month (kWh)</h2>
  <div class="bars" id="months"></div>
</div>
<div class="card">
  <h2>By year (kWh)</h2>
  <table id="years"><thead><tr><th>Year</th><th class="num">Produced (solar)</th>
  <th class="num">Consumed (load)</th><th class="num">Net</th></tr></thead><tbody></tbody></table>
</div>
<div class="card">
  <h2>By month (kWh)</h2>
  <table id="tbl"><thead><tr><th>Month</th><th class="num">Produced</th>
  <th class="num">Consumed</th><th class="num">Net</th></tr></thead><tbody></tbody></table>
</div>
<script>
function esc(s) { return String(s ?? "\u2014").replace(/[&<>"]/g, c => ({"&":"&#38;","<":"&#60;",">":"&#62;",'"':"&#34;"}[c])); }
function fmt(k) { return k == null ? "\u2014" : Number(k).toFixed(2); }
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
      + "<span class='pos'>" + fmt(sv) + " / <span class='neg'>" + fmt(lv) + "</span></span></div>";
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
    return "<tr><td>" + esc(m) + "</td><td class='num pos'>" + fmt(sv) + "</td>"
      + "<td class='num neg'>" + fmt(lv) + "</td>"
      + "<td class='num net'>" + (net >= 0 ? "+" : "") + fmt(net) + "</td></tr>";
  }).join("");
}
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
  <p class="hint">Runtime overrides (seconds). Changes apply within one cycle, without restarting the container. "Reset all" restores the .env values.</p>
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

<button class="btn" onclick="save()">Save</button>
<button class="btn reset" onclick="resetAll()">Reset all</button>
<div class="msg" id="msg"></div>

<script>
const FIELDS = ["POLL_SECONDS", "POLL_SECONDS_NIGHT", "NIGHT_START", "NIGHT_END",
  "GPS_POLL_SECONDS", "GATT_POLL_SECONDS", "STATIONARY_SPEED_KN",
  "GPS_STATIONARY_INTERVAL", "SOLAR_HISTORY_DAYS"];
async function load() {
  const d = await (await fetch("api/settings")).json();
  FIELDS.forEach(f => { if (d[f] !== undefined) document.getElementById(f).value = d[f]; });
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
  const r = await fetch("api/settings", { method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body) });
  const msg = document.getElementById("msg");
  if (r.ok) { msg.className = "msg ok"; msg.textContent = "Reset to .env values \u2713"; load(); }
  else { msg.className = "msg err"; msg.textContent = "error"; }
}
load();
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
  <a class="back" href="..">← Dashboard</a>
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
      const m = L.circleMarker([p.latitude, p.longitude], {
        radius: isFirst || isLast ? 6 : 3.5,
        color: isFirst ? "#22c55e" : isLast ? "#f59e0b" : "#38bdf8",
        weight: 2, fillOpacity: .9
      }).addTo(trackLayer);
      m.bindTooltip(
        "<b>" + (isFirst ? "Start" : isLast ? "Arrival" : "Point " + (i + 1)) + "</b><br>" +
        fmtTs(p.timestamp) + "<br>" +
        "Speed: " + (p.speed != null ? p.speed.toFixed(1) + " kn" : "n/a") + "<br>" +
        "Course: " + compass(p.heading),
        { direction: "top", offset: [-2, -6] }
      );
    });
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

BL917_ENABLED = os.environ.get("BL917_ENABLED", "0") == "1"

if __name__ == "__main__":
    fetch_devices()                    # primo giro immediato
    fetch_lte()                         # segnale LTE immediato
    if BL917_ENABLED:                   # MPPT BL917 via cloud
        fetch_bl917()
        threading.Thread(target=bl917_loop, daemon=True).start()
    threading.Thread(target=poll_loop, daemon=True).start()
    threading.Thread(target=gps_loop, daemon=True).start()
    threading.Thread(target=gatt_loop, daemon=True).start()
    log.info("nautilus-telemetry in ascolto su :8080 (poll KNOT ogni %ds)", POLL_SECONDS)
    app.run(host="0.0.0.0", port=8080)
