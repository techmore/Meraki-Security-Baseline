"""Tests for meraki_backup.py helpers — cache logic, write_json, schema constants."""
import json
import os
import sys
import time
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import meraki_backup as mb
import meraki_client as mc


# ── _cache_is_fresh ───────────────────────────────────────────────────────────

class TestCacheIsFresh:
    def test_nonexistent_file_returns_false(self, tmp_path):
        assert mb._cache_is_fresh(str(tmp_path / "missing.json")) is False

    def test_fresh_valid_json_returns_true(self, tmp_path):
        p = tmp_path / "data.json"
        p.write_text(json.dumps({"key": "value"}))
        assert mb._cache_is_fresh(str(p), max_age_h=12) is True

    def test_force_returns_false_even_when_fresh(self, tmp_path):
        p = tmp_path / "data.json"
        p.write_text(json.dumps({}))
        assert mb._cache_is_fresh(str(p), max_age_h=12, force=True) is False

    def test_corrupt_json_returns_false(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json}")
        assert mb._cache_is_fresh(str(p), max_age_h=12) is False

    def test_old_file_returns_false(self, tmp_path):
        p = tmp_path / "old.json"
        p.write_text(json.dumps({"x": 1}))
        # Set mtime to 25 hours ago
        old_time = time.time() - (25 * 3600)
        os.utime(str(p), (old_time, old_time))
        assert mb._cache_is_fresh(str(p), max_age_h=24) is False

    def test_within_max_age_returns_true(self, tmp_path):
        p = tmp_path / "recent.json"
        p.write_text(json.dumps({"x": 1}))
        # Set mtime to 5 hours ago
        recent_time = time.time() - (5 * 3600)
        os.utime(str(p), (recent_time, recent_time))
        assert mb._cache_is_fresh(str(p), max_age_h=12) is True

    def test_error_envelope_is_not_fresh(self, tmp_path):
        p = tmp_path / "failed.json"
        p.write_text(json.dumps({"error": "HTTP 500 for test"}))
        assert mb._cache_is_fresh(str(p), max_age_h=12) is False

    def test_error_item_list_is_not_fresh(self, tmp_path):
        p = tmp_path / "failed-list.json"
        p.write_text(json.dumps([{"error": "HTTP 429 for test"}]))
        assert mb._cache_is_fresh(str(p), max_age_h=12) is False

    def test_failure_sidecar_invalidates_last_known_good_data(self, tmp_path):
        p = str(tmp_path / "data.json")
        mb._write_cache_success(p, {"value": "known-good"})
        mb._write_cache_error(p, "HTTP 503 for test", endpoint="/test")

        assert mb._cache_is_fresh(p, max_age_h=12) is False
        assert mb._load_json_file(p) == {"value": "known-good"}
        metadata = mb._load_json_file(mb._cache_error_path(p))
        assert metadata["status"] == "error"
        assert metadata["endpoint"] == "/test"

        mb._write_cache_success(p, {"value": "recovered"})
        assert mb._cache_is_fresh(p, max_age_h=12) is True
        assert not os.path.exists(mb._cache_error_path(p))


# ── write_json / _load_json_file ──────────────────────────────────────────────

class TestWriteAndLoad:
    def test_roundtrip(self, tmp_path):
        payload = {"hello": "world", "nums": [1, 2, 3]}
        p = str(tmp_path / "test.json")
        mb.write_json(p, payload)
        loaded = mb._load_json_file(p)
        assert loaded == payload

    def test_creates_file(self, tmp_path):
        p = str(tmp_path / "new.json")
        assert not os.path.exists(p)
        mb.write_json(p, {})
        assert os.path.exists(p)

    def test_write_json_omits_nested_sensitive_fields(self, tmp_path):
        payload = {
            "authMode": "psk",
            "psk": "do-not-persist",
            "nested": {"password": "also-do-not-persist", "key": "license-key"},
        }
        p = str(tmp_path / "redacted.json")

        mb.write_json(p, payload)

        loaded = mb._load_json_file(p)
        assert loaded == {
            "authMode": "psk",
            "nested": {"key": "license-key"},
        }


class TestGranularArtifacts:
    def test_artifact_path_is_namespaced(self, tmp_path):
        path = mb._artifact_path(str(tmp_path), "switches", "Q2XX-1/2", "port_statuses.json")
        assert path.endswith("switches/Q2XX-1_2/port_statuses.json")

    def test_granular_roundtrip(self, tmp_path):
        payload = {"hello": "world"}
        mb._write_granular_json(str(tmp_path), "networks", "N_123", "clients.json", payload)
        loaded = mb._read_granular_json(str(tmp_path), "networks", "N_123", "clients.json")
        assert loaded == payload

    def test_granular_cache_fresh_uses_underlying_file(self, tmp_path):
        mb._write_granular_json(str(tmp_path), "switches", "SW1", "lldp_cdp.json", {"x": 1})
        assert mb._granular_cache_fresh(str(tmp_path), "switches", "SW1", "lldp_cdp.json", max_age_h=12) is True

    def test_legacy_granular_ssid_cache_is_redacted_on_read(self, tmp_path):
        path = mb._artifact_path(str(tmp_path), "networks", "N_123", "wireless_ssids.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([{"name": "Staff", "authMode": "psk", "psk": "legacy-secret"}], f)

        loaded = mb._read_granular_json(str(tmp_path), "networks", "N_123", "wireless_ssids.json")

        assert loaded == [{"name": "Staff", "authMode": "psk"}]
        assert "legacy-secret" not in open(path, encoding="utf-8").read()


# ── Schema version constant ───────────────────────────────────────────────────

class TestSchemaVersion:
    def test_schema_version_is_int(self):
        assert isinstance(mb.BACKUP_SCHEMA_VERSION, int)

    def test_schema_version_positive(self):
        assert mb.BACKUP_SCHEMA_VERSION >= 1

    def test_pipeline_version_is_string(self):
        assert isinstance(mb.PIPELINE_VERSION, str)


class TestPagedGetRateLimit:
    def test_retry_after_header_is_honored(self, monkeypatch):
        sleeps = []
        calls = {"count": 0}

        def fake_get_json(url, api_key, timeout=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise mc.MerakiRequestError(
                    "HTTP 429 for test",
                    status=429,
                    headers={"Retry-After": "7"},
                )
            return {"data": [], "headers": {}, "status": 200}

        monkeypatch.setattr(mc, "get_json", fake_get_json)
        monkeypatch.setattr(mc.time, "sleep", lambda seconds: sleeps.append(seconds))

        result = mb.paged_get("/organizations", "test-key")
        assert result == []
        assert calls["count"] == 2
        assert sleeps[0] == 7

    def test_retry_after_falls_back_when_header_missing(self, monkeypatch):
        sleeps = []
        calls = {"count": 0}

        def fake_get_json(url, api_key, timeout=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise mc.MerakiRequestError("HTTP 429 for test", status=429)
            return {"data": [], "headers": {}, "status": 200}

        monkeypatch.setattr(mc, "get_json", fake_get_json)
        monkeypatch.setattr(mc.time, "sleep", lambda seconds: sleeps.append(seconds))

        result = mb.paged_get("/organizations", "test-key")
        assert result == []
        assert calls["count"] == 2
        assert sleeps[0] == 2


class TestSharedMerakiClient:
    def test_environment_settings_load_after_dotenv(self, monkeypatch, tmp_path):
        from meraki_env import load_env

        for name in ("MERAKI_API_BASE", "MERAKI_REQUEST_TIMEOUT", "MERAKI_MAX_RETRIES"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(mc, "_CONFIG", None)
        env_path = tmp_path / ".env"
        env_path.write_text(
            "MERAKI_API_BASE=https://meraki.test/api/v1\n"
            "MERAKI_REQUEST_TIMEOUT=11\n"
            "MERAKI_MAX_RETRIES=2\n",
            encoding="utf-8",
        )

        load_env(str(env_path))
        config = mc.configure_from_env()

        assert config.api_base == "https://meraki.test/api/v1"
        assert config.request_timeout == 11
        assert config.max_retries == 2
        assert mc.build_url("/organizations") == "https://meraki.test/api/v1/organizations"

        # load_env() intentionally writes into os.environ; clean these values
        # so later tests continue to exercise default configuration.
        for name in ("MERAKI_API_BASE", "MERAKI_REQUEST_TIMEOUT", "MERAKI_MAX_RETRIES"):
            os.environ.pop(name, None)
        mc._CONFIG = None

    def test_build_url_appends_query_params(self):
        url = mc.build_url("/organizations", {"perPage": 5, "foo": "bar"})
        assert url.startswith("https://api.meraki.com/api/v1/organizations?")
        assert "perPage=5" in url
        assert "foo=bar" in url

    def test_shared_paged_get_honors_retry_after(self, monkeypatch):
        sleeps = []
        calls = {"count": 0}

        def fake_get_json(url, api_key, timeout=None):
            calls["count"] += 1
            if calls["count"] == 1:
                raise mc.MerakiRequestError(
                    "HTTP 429 for test",
                    status=429,
                    headers={"Retry-After": "3"},
                )
            return {"data": [], "headers": {}, "status": 200}

        monkeypatch.setattr(mc, "get_json", fake_get_json)
        monkeypatch.setattr(mc.time, "sleep", lambda seconds: sleeps.append(seconds))

        result = mc.paged_get("/organizations", "test-key")
        assert result == []
        assert calls["count"] == 2
        assert sleeps[0] == 3


# ── summarize_availabilities ──────────────────────────────────────────────────

class TestSummarizeAvailabilities:
    def _make_devices(self, statuses):
        return [{"status": s, "productType": "switch", "serial": f"S{i}"}
                for i, s in enumerate(statuses)]

    def test_all_online(self):
        devs = self._make_devices(["online", "online", "online"])
        result = mb.summarize_availabilities(devs)
        assert result.get("offline_count") == 0
        assert result.get("total") == 3

    def test_one_offline(self):
        devs = self._make_devices(["online", "online", "offline"])
        result = mb.summarize_availabilities(devs)
        assert result.get("offline_count") == 1
        assert len(result.get("offline_devices", [])) == 1

    def test_empty_returns_dict(self):
        result = mb.summarize_availabilities([])
        assert isinstance(result, dict)


# ── summarize_inventory ───────────────────────────────────────────────────────

class TestSummarizeInventory:
    def test_counts_by_type(self):
        inventory = [
            {"productType": "appliance", "model": "MX68", "serial": "A"},
            {"productType": "switch", "model": "MS225", "serial": "B"},
            {"productType": "switch", "model": "MS225", "serial": "C"},
            {"productType": "wireless", "model": "MR46", "serial": "D"},
        ]
        result = mb.summarize_inventory(inventory)
        assert result["by_type"]["appliance"] == 1
        assert result["by_type"]["switch"] == 2
        assert result["by_type"]["wireless"] == 1

    def test_top_models_present(self):
        inventory = [
            {"productType": "switch", "model": "MS225", "serial": "A"},
            {"productType": "switch", "model": "MS225", "serial": "B"},
            {"productType": "wireless", "model": "MR46", "serial": "C"},
        ]
        result = mb.summarize_inventory(inventory)
        models = [m[0] for m in result.get("top_models", [])]
        assert "MS225" in models
