from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import generate_synthetic_media as generator


class SyntheticMediaGeneratorTest(unittest.TestCase):
    def test_command_is_stable_for_identical_inputs(self) -> None:
        output = Path("fixture.mp4")
        first = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17)
        second = generator.build_command("ffmpeg", output, 320, 240, 3, 30, 17)
        self.assertEqual(first, second)
        self.assertIn("all_seed=17", first)
        self.assertIn("creation_time=1970-01-01T00:00:00Z", first)

    def test_rejects_unsafe_dimensions_and_seed_bounds(self) -> None:
        with self.assertRaisesRegex(generator.GeneratorError, "width"):
            generator.validate_options(Path("fixture.mp4"), 17, 240, 3, 30, 0)
        with self.assertRaisesRegex(generator.GeneratorError, "seed"):
            generator.validate_options(Path("fixture.mp4"), 320, 240, 3, 30, -1)

    def test_does_not_replace_existing_output_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture.mp4"
            output.write_bytes(b"existing")
            with patch.object(generator.subprocess, "run") as run:
                with self.assertRaisesRegex(generator.GeneratorError, "already exists"):
                    generator.generate(output)
                run.assert_not_called()

    def test_rejects_unsupported_output_extension(self) -> None:
        with self.assertRaisesRegex(generator.GeneratorError, r"\.mp4"):
            generator.validate_options(Path("fixture.mov"), 320, 240, 3, 30, 0)


if __name__ == "__main__":
    unittest.main()