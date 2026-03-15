from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
import importlib.util


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_program_config", "tools/validate_program_config.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class ProgramConfigValidationTests(unittest.TestCase):
    def test_valid_program_config(self) -> None:
        module = _load_validator()
        os.environ["TEST_HEADER"] = "value"
        data = """
programs:
  - name: test
    in_scope: ["example.com"]
    per_host_rpm: 10
    per_target_rpm: 5
    concurrency_per_host: 1
    allowed_hours: ["00:00-23:59"]
    required_headers:
      X-Test: "${TEST_HEADER}"
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "programs.yaml"
            path.write_text(data, encoding="utf-8")
            result = module.validate_programs(path)
            self.assertEqual(result, 0)
        os.environ.pop("TEST_HEADER", None)

    def test_invalid_program_config(self) -> None:
        module = _load_validator()
        data = """
programs:
  - name: bad
    required_headers:
      X-Test: ""
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "programs.yaml"
            path.write_text(data, encoding="utf-8")
            result = module.validate_programs(path)
            self.assertEqual(result, 1)


if __name__ == "__main__":
    unittest.main()
