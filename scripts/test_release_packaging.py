#!/usr/bin/env python3
"""Regression tests for reproducible release archive construction."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


sys.dont_write_bytecode = True
SCRIPT_PATH = Path(__file__).with_name("package_release_binary.py")
SPEC = importlib.util.spec_from_file_location("package_release_binary", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleasePackagingTests(unittest.TestCase):
    def test_archive_is_byte_reproducible_across_paths_and_input_mtimes(self) -> None:
        epoch = 1_735_689_600
        with tempfile.TemporaryDirectory() as first_dir, tempfile.TemporaryDirectory() as second_dir:
            first_root = Path(first_dir)
            second_root = Path(second_dir)
            first_binary = first_root / "source" / "docdexd"
            second_binary = second_root / "elsewhere" / "docdexd"
            first_binary.parent.mkdir(parents=True)
            second_binary.parent.mkdir(parents=True)
            payload = b"deterministic-docdex-binary\x00\x01"
            first_binary.write_bytes(payload)
            second_binary.write_bytes(payload)
            os.utime(first_binary, (epoch + 100, epoch + 100))
            os.utime(second_binary, (epoch + 900, epoch + 900))

            first_archive = first_root / "docdexd-test.tar.gz"
            second_archive = second_root / "docdexd-test.tar.gz"
            first_digest = MODULE.create_archive(
                input_path=first_binary,
                archive_name="docdexd",
                output_path=first_archive,
                source_date_epoch=epoch,
            )
            second_digest = MODULE.create_archive(
                input_path=second_binary,
                archive_name="docdexd",
                output_path=second_archive,
                source_date_epoch=epoch,
            )

            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_archive.read_bytes(), second_archive.read_bytes())
            self.assertEqual(
                first_archive.with_name(f"{first_archive.name}.sha256").read_text(),
                second_archive.with_name(f"{second_archive.name}.sha256").read_text(),
            )
            with tarfile.open(first_archive, mode="r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual([member.name for member in members], ["docdexd"])
                self.assertEqual(members[0].mtime, epoch)
                self.assertEqual(members[0].mode, 0o755)
                extracted = archive.extractfile(members[0])
                self.assertIsNotNone(extracted)
                self.assertEqual(extracted.read(), payload)

    def test_source_date_epoch_parser_is_fail_closed(self) -> None:
        self.assertEqual(MODULE.parse_source_date_epoch("0"), 0)
        self.assertEqual(MODULE.parse_source_date_epoch(" 1735689600 "), 1_735_689_600)
        for invalid in ("", "-1", "1.5", "not-a-time", "253402300800"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    MODULE.parse_source_date_epoch(invalid)


if __name__ == "__main__":
    unittest.main()
