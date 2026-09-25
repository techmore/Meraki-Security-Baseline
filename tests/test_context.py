"""Tests for the report artifact loading boundary."""

import json

from reporting.context import load_report_data


def _write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def test_load_report_data_normalizes_clients_and_switch_ports(tmp_path):
    _write_json(tmp_path / "inventory_summary.json", {})
    _write_json(tmp_path / "devices_availabilities.json", [])
    _write_json(tmp_path / "switch_port_statuses.json", {
        "Q2SW-TEST": [{"portId": "1", "status": "Connected"}],
    })
    _write_json(tmp_path / "switch_port_configs.json", {
        "Q2SW-TEST": [{"portId": "1", "enabled": True}],
    })
    _write_json(tmp_path / "uplink_statuses.json", [])
    _write_json(tmp_path / "networks.json", [])
    _write_json(tmp_path / "security_baseline.json", {})
    _write_json(tmp_path / "wireless_clients.json", {
        "N_test": [{"mac": "aa:bb:cc:dd:ee:ff"}, "invalid row"],
    })

    context = load_report_data(str(tmp_path), str(tmp_path))

    assert context.data_quality_warnings == []
    assert context.wireless_clients == [{"mac": "aa:bb:cc:dd:ee:ff"}]
    assert context.switch_port_statuses == [
        {"portId": "1", "status": "Connected", "switchSerial": "Q2SW-TEST"}
    ]
    assert context.switch_port_configs == [
        {"portId": "1", "enabled": True, "switchSerial": "Q2SW-TEST"}
    ]
