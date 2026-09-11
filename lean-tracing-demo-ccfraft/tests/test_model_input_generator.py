"""Portable regeneration controls; only temporary copies are written."""

from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/generate_model_input_syntax.py"
SOURCE = ROOT / "Sparse/ModelInputSyntax.lean"
MARKER = b"-- Trace boundary."


class ModelInputGeneratorTests(unittest.TestCase):
    def invoke(self, arguments: list, expected: int, script: Path = HELPER):
        result = subprocess.run(
            [sys.executable, "-B", str(script), *map(str, arguments)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(
            result.returncode, expected,
            f"{arguments}\n{result.stdout}\n{result.stderr}",
        )
        return result

    def test_current_source_is_not_modified(self) -> None:
        before = SOURCE.read_bytes()
        modified = SOURCE.stat().st_mtime_ns
        self.invoke([], 0)
        self.invoke(["--check"], 0)
        self.assertEqual(SOURCE.read_bytes(), before)
        self.assertEqual(SOURCE.stat().st_mtime_ns, modified)

    def test_regeneration_preserves_manual_bytes_and_permissions(self) -> None:
        prefix, _, suffix = SOURCE.read_bytes().partition(MARKER)
        manual = suffix + b"\n-- manual sentinel\r\n#check Nat\t"
        good = prefix + MARKER + manual
        stale = b"-- stale generated prefix\n" + MARKER + manual
        with tempfile.TemporaryDirectory(prefix="model-input-generator-") as directory:
            target = Path(directory) / "copy with spaces.lean"
            target.write_bytes(stale)
            target.chmod(0o640)
            modified = target.stat().st_mtime_ns
            result = self.invoke(["--file", target, "--check"], 1)
            self.assertIn("stale", result.stderr)
            self.assertEqual(target.read_bytes(), stale)
            self.assertEqual(target.stat().st_mtime_ns, modified)
            self.invoke(["--file", target, "--write"], 0)
            self.assertEqual(target.read_bytes(), good)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            modified = target.stat().st_mtime_ns
            self.invoke(["--file", target, "--write"], 0)
            self.invoke(["--file", target, "--check"], 0)
            self.assertEqual(target.read_bytes(), good)
            self.assertEqual(target.stat().st_mtime_ns, modified)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_invalid_inputs_are_not_modified(self) -> None:
        invalid = {
            "missing": b"-- no boundary\n",
            "duplicate": MARKER + b"\n" + MARKER + b"\n",
            "embedded": b"prefix " + MARKER + b"\nmanual",
            "unterminated": b"prefix\n" + MARKER,
            "crlf-marker": b"prefix\n" + MARKER + b"\r\nmanual",
            "non-ascii-prefix": b"\xff\n" + MARKER + b"\nmanual",
            "non-ascii-suffix": b"prefix\n" + MARKER + b"\n\xff",
        }
        with tempfile.TemporaryDirectory(prefix="model-input-generator-invalid-") as directory:
            target = Path(directory) / "copy.lean"
            for label, data in invalid.items():
                for mode in ("--check", "--write"):
                    with self.subTest(input=label, mode=mode):
                        target.write_bytes(data)
                        modified = target.stat().st_mtime_ns
                        result = self.invoke(["--file", target, mode], 2)
                        self.assertIn("error:", result.stderr)
                        self.assertEqual(target.read_bytes(), data)
                        self.assertEqual(target.stat().st_mtime_ns, modified)
            missing = Path(directory) / "missing.lean"
            self.invoke(["--file", missing, "--write"], 2)
            self.assertFalse(missing.exists())
            self.invoke(["--file", target, "--check", "--write"], 2)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_default_path_uses_relocated_project(self) -> None:
        source = SOURCE.read_bytes()
        _, _, suffix = source.partition(MARKER)
        stale = b"-- stale\n" + MARKER + suffix
        with tempfile.TemporaryDirectory(prefix="model-input-generator-portable-") as directory:
            project = Path(directory)
            (project / "scripts").mkdir()
            (project / "Sparse").mkdir()
            script = project / "scripts/generate_model_input_syntax.py"
            script.write_bytes(HELPER.read_bytes())
            target = project / "Sparse/ModelInputSyntax.lean"
            target.write_bytes(stale)
            result = self.invoke([], 1, script)
            self.assertIn(str(target), result.stderr)
            self.assertEqual(target.read_bytes(), stale)
            self.invoke(["--write"], 0, script)
            self.invoke(["--check"], 0, script)
            self.assertEqual(target.read_bytes(), source)


if __name__ == "__main__":
    unittest.main()
