import unittest
from unittest.mock import Mock, patch

import app as telemetry


def response(payload, status=200):
    result = Mock(status_code=status)
    result.json.return_value = payload
    result.text = str(payload)
    result.raise_for_status.return_value = None
    return result


class BleDeviceManagementTests(unittest.TestCase):
    def setUp(self):
        self.client = telemetry.app.test_client()
        self.mac = "50:54:7B:24:A6:2A"
        self.row = {
            ".id": "*2ED",
            "address": self.mac,
            "name": "BM6-Cocchina",
            "persist": "true",
            "rssi": "-45",
            "last-seen": "2026-10-31 23:18:47",
        }

    @patch("app.requests.post")
    @patch("app.requests.get")
    def test_updates_knot_device_name(self, get, post):
        get.return_value = response([self.row])
        post.return_value = response([])

        result = self.client.post(
            f"/api/ble/devices/{self.mac}",
            json={"name": "BM6-Cocchina-new"},
        )

        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertEqual(result.get_json()["device"]["name"], "BM6-Cocchina-new")
        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertEqual(args[0], telemetry.KNOT_URL + "/set")
        self.assertEqual(
            kwargs["json"],
            {"numbers": "*2ED", "name": "BM6-Cocchina-new"},
        )

    @patch("app.requests.post")
    @patch("app.requests.get")
    def test_removes_knot_device_persistence(self, get, post):
        get.return_value = response([self.row])
        post.return_value = response([])

        result = self.client.post(
            f"/api/ble/devices/{self.mac}",
            json={"persist": False},
        )

        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertFalse(result.get_json()["device"]["persist"])
        post.assert_called_once()
        args, kwargs = post.call_args
        self.assertEqual(args[0], telemetry.KNOT_URL + "/set")
        self.assertEqual(
            kwargs["json"],
            {"numbers": "*2ED", "persist": "false"},
        )

    @patch("app.requests.post")
    @patch("app.requests.get")
    def test_rejects_non_boolean_persistence(self, get, post):
        get.return_value = response([self.row])
        post.return_value = response([])

        result = self.client.post(
            f"/api/ble/devices/{self.mac}",
            json={"persist": "false"},
        )

        self.assertEqual(result.status_code, 400)
        post.assert_not_called()

    @patch("app.requests.post")
    @patch("app.requests.get")
    def test_bm6_rename_invalidates_cached_gatt_name(self, get, post):
        get.return_value = response([self.row])
        post.return_value = response([])
        telemetry._bm6_dev_name = "BM6-Cocchina"

        result = self.client.post(
            f"/api/ble/devices/{self.mac}",
            json={"name": "BM6-Cocchina-new"},
        )

        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertIsNone(telemetry._bm6_dev_name)

    @patch("app.requests.post")
    @patch("app.requests.get")
    def test_rejects_malformed_mac_before_knot_request(self, get, post):
        malformed = (
            "not-a-mac",
            "50:54:7B:24:A6",
            "50:54:7B:24:A6:2A:00",
            "50:54:7B:24:A6:2G",
            "50-54-7B-24-A6-2A",
            "50:54:7B:24:A6:2A<script>",
        )
        for mac in malformed:
            with self.subTest(mac=mac):
                result = self.client.post(
                    f"/api/ble/devices/{mac}",
                    json={"persist": True},
                )
                self.assertEqual(result.status_code, 400)
        get.assert_not_called()
        post.assert_not_called()

    def test_settings_include_knot_management_controls(self):
        html = telemetry.SETTINGS_HTML
        for fragment in (
            "class='ble-name'",
            "bleSaveName",
            "bleSetPersist",
            "Make persistent",
            "Remove persistence",
        ):
            self.assertIn(fragment, html)
        self.assertLess(
            html.index('onclick="clearBle()"'),
            html.index("<h2>Victron devices</h2>"),
        )

    def test_ble_rows_escape_router_fields_without_inline_handlers(self):
        load_ble = telemetry.SETTINGS_HTML.split(
            "async function loadBle() {", 1
        )[1].split("async function bleUpdate", 1)[0]
        for fragment in ("${dev.mac}", "const rssi = dev.rssi", "onclick="):
            self.assertNotIn(fragment, load_ble)
        for fragment in (
            "esc(d.error)",
            "const mac = esc(dev.mac",
            "const rssi = esc(",
            "esc(dev.name",
            "esc(dev.note",
        ):
            self.assertIn(fragment, load_ble)
        self.assertEqual(load_ble.count('addEventListener("click"'), 2)

    def test_rejects_non_object_json(self):
        result = self.client.post(
            f"/api/ble/devices/{self.mac}",
            json=["name"],
        )

        self.assertEqual(result.status_code, 400)


if __name__ == "__main__":
    unittest.main()
