#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile
import unittest
from release_channel import publication_channel


class PublicationChannelTests(unittest.TestCase):
    def test_stable_and_prerelease_channels_are_separate(self):
        for tag in ("v0.0.0", "v1.2.30"):
            self.assertEqual(publication_channel(tag), {"prerelease": "false", "npm_dist_tag": "latest"})
        for tag in ("v0.2.100-codali.0", "v1.2.3-rc.1", "v1.2.3-0", "v1.2.3-01x"):
            self.assertEqual(publication_channel(tag), {"prerelease": "true", "npm_dist_tag": "next"})

    def test_invalid_tags_fail_closed(self):
        for tag in ("main", "1.2.3", "v01.2.3", "v1.2.3-", "v1.2.3-rc..1", "v1.2.3-01", "v1.2.3+build", "v1.2.3\n", "v1.2.3-rc\nnpm_dist_tag=latest"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                publication_channel(tag)

    def test_workflow_outputs_cannot_promote_a_prerelease(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "outputs"
            result = subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name("release_channel.py")), "--tag", "v1.2.3-codali.0", "--github-output", str(output)], capture_output=True, check=True, text=True)
            self.assertIn('"npm_dist_tag": "next"', result.stdout)
            self.assertEqual(output.read_text(), "prerelease=true\nnpm_dist_tag=next\n")


if __name__ == "__main__":
    unittest.main()
