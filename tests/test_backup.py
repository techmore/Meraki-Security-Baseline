"""Tests for meraki_backup.py helpers — cache logic, write_json, schema constants."""
import json
import os
import sys
import time
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import meraki_backup as mb


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


# ── Schema version constant ───────────────────────────────────────────────────

class TestSchemaVersion:
    def test_schema_version_is_int(self):
        assert isinstance(mb.BACKUP_SCHEMA_VERSION, int)

    def test_schema_version_positive(self):
        assert mb.BACKUP_SCHEMA_VERSION >= 1

    def test_pipeline_version_is_string(self):
        assert isinstance(mb.PIPELINE_VERSION, str)


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
