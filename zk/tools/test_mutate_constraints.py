"""Generator checks independent of the real circuit corpus or Nargo installation."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import mutate_constraints as mc

FIXTURE = Path(__file__).with_name("fixtures") / "mutation_constraints.nr"


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.source = FIXTURE.read_text(encoding="utf-8")

    def test_inventory_includes_helpers_but_excludes_comments_strings_and_tests(self):
        constraints = mc.find_constraints(self.source)
        self.assertEqual(
            [(c.kind, c.function, c.line) for c in constraints],
            [
                ("assert", "constrain_value", 2),
                ("assert", "main", 10),
                ("assert_eq", "main", 14),
            ],
        )

    def test_each_mutant_disables_one_complete_call_and_preserves_its_surroundings(
        self,
    ):
        for constraint in mc.find_constraints(self.source):
            with self.subTest(line=constraint.line):
                mutated = mc.mutate(self.source, constraint)
                self.assertTrue(mutated.startswith(self.source[: constraint.start]))
                self.assertTrue(mutated.endswith(self.source[constraint.end :]))
                self.assertEqual(len(mc.find_constraints(mutated)), 2)
                self.assertIn(
                    'assert(false, "do not mutate the test oracle");', mutated
                )
        self.assertEqual(FIXTURE.read_text(encoding="utf-8"), self.source)

    def test_multiline_call_is_a_single_mutation(self):
        constraint = mc.find_constraints(self.source)[1]
        self.assertEqual(
            self.source[constraint.start : constraint.end],
            'assert(\n        x != 0,\n        "malformed",\n    )',
        )
        self.assertIn(
            'assert_eq(x, 7, "wrong value");', mc.mutate(self.source, constraint)
        )

    def test_new_and_removed_assertions_are_discovered_on_every_scan(self):
        updated = self.source + "\nfn added(x: Field) { assert(x != 3); }\n"
        self.assertEqual(len(mc.find_constraints(updated)), 4)
        self.assertEqual(len(mc.find_constraints(self.source)), 3)

    def test_unit_replacement_supports_assertions_in_expression_position(self):
        source = "fn main(x: Field) { let unit = assert(x != 0); unit }"
        mutated = mc.mutate(source, mc.find_constraints(source)[0])
        self.assertIn("let unit = ", mutated)
        self.assertIn("(); unit }", mutated)
        self.assertEqual(mc.find_constraints(mutated), [])

    def test_comment_delimiters_in_messages_do_not_break_the_mutated_source(self):
        source = (
            'fn main(x: Field) { assert(x != 0, "/* message */"); assert(x != 1); }'
        )
        mutated = mc.mutate(source, mc.find_constraints(source)[0])
        self.assertEqual(len(mc.find_constraints(mutated)), 1)
        self.assertIn("assert(x != 1)", mutated)

    def test_adjacent_assertions_and_attributes(self):
        source = """#[test(should_fail_with = "a ] ) {")]
pub fn negative() { assert(false); }
fn main() { assert(true);assert_eq(1, 1); }
"""
        self.assertEqual(
            [c.kind for c in mc.find_constraints(source)], ["assert", "assert_eq"]
        )

    def test_unbalanced_source_fails_instead_of_silently_missing_constraints(self):
        with self.assertRaises(ValueError):
            mc.find_constraints("fn main() { assert(true);")

    def test_array_types_in_function_signatures_do_not_hide_the_function_body(self):
        source = "fn helper(a: [Field; 2]) -> [Field; 2] { assert(a[0] != 0); a }"
        self.assertEqual(mc.find_constraints(source)[0].function, "helper")


class DiscoveryTests(unittest.TestCase):
    def test_discovers_new_circuits_and_local_dependency_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lib = root / "shared"
            lib.mkdir()
            (lib / "Nargo.toml").write_text('[package]\nname="shared"\ntype="lib"\n')
            (lib / "src").mkdir()
            (lib / "src/lib.nr").write_text(
                "pub fn guard(x: Field) { assert(x != 0); }"
            )
            for name in ("first", "added_later"):
                package = root / name
                (package / "src").mkdir(parents=True)
                (package / "Nargo.toml").write_text(
                    f'[package]\nname="{name}"\ntype="bin"\n'
                    '[dependencies]\nshared={path="../shared"}\n'
                )
                (package / "src/main.nr").write_text("fn main() { assert(true); }")
            circuits = mc.discover_circuits(root)
            self.assertEqual([c.name for c in circuits], ["added_later", "first"])
            self.assertEqual(
                {p.relative_to(root).as_posix() for p in circuits[0].sources},
                {"shared/src/lib.nr", "added_later/src/main.nr"},
            )

    def test_missing_local_dependency_fails_instead_of_omitting_its_assertions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Nargo.toml").write_text(
                '[package]\nname="broken"\ntype="bin"\n'
                '[dependencies]\nmissing={path="missing"}\n'
            )
            with self.assertRaises(ValueError):
                mc.discover_circuits(root)


class ResultTests(unittest.TestCase):
    def report(self, passed=1, failed=0):
        events = [
            {"type": "suite", "event": "started", "test_count": passed + failed},
            *[
                {"type": "test", "event": "ok", "name": f"positive_{i}"}
                for i in range(passed)
            ],
            *[
                {
                    "type": "test",
                    "event": "failed",
                    "name": f"negative_{i}",
                    "stdout": "error: Test passed when it should have failed",
                }
                for i in range(failed)
            ],
            {
                "type": "suite",
                "event": "failed" if failed else "ok",
                "passed": passed,
                "failed": failed,
                "ignored": 0,
            },
        ]
        return "\n".join(json.dumps(e) for e in events)

    def test_zero_exit_with_completed_tests_means_mutant_survived(self):
        self.assertEqual(mc.classify_run(0, self.report()), "passed")

    def test_nonzero_exit_with_failed_test_means_mutant_was_detected(self):
        self.assertEqual(mc.classify_run(1, self.report(failed=1)), "failed")

    def test_compile_failure_is_not_a_killed_mutant(self):
        self.assertEqual(mc.classify_run(1, "error: expected type Field"), "error")

    def test_empty_or_truncated_reports_are_not_successful_mutation_checks(self):
        self.assertEqual(mc.classify_run(0, ""), "error")
        self.assertEqual(mc.classify_run(0, self.report().rsplit("\n", 1)[0]), "error")
        self.assertEqual(mc.classify_run(0, self.report(passed=0)), "error")

    def test_exit_code_and_report_must_agree(self):
        self.assertEqual(mc.classify_run(0, self.report(failed=1)), "error")
        self.assertEqual(mc.classify_run(1, self.report()), "error")


@unittest.skipUnless(
    os.environ.get("NARGO"), "Set NARGO to run the real compiler integration checks"
)
class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name) / "noir"
        self.package = self.root / "fixture"
        (self.package / "src").mkdir(parents=True)
        (self.package / "Nargo.toml").write_text(
            '[package]\nname="fixture"\ntype="bin"\ncompiler_version=">=1.0.0"\n'
        )
        self.source = self.package / "src/main.nr"
        shutil.copyfile(FIXTURE, self.source)

    def campaign(self, budget=60):
        with contextlib.redirect_stdout(io.StringIO()):
            return mc.run_campaign(
                self.root,
                os.environ["NARGO"],
                Path(self.scratch.name) / "reports",
                30,
                budget,
            )

    def test_added_constraint_survives_until_a_matching_negative_test_is_added(self):
        original = self.source.read_text()
        report = self.campaign()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["counts"]["killed"], 3)
        self.assertEqual(self.source.read_text(), original)

        updated = original.replace(
            "    constrain_value(x);",
            '    constrain_value(x);\n    assert(x != 3, "new constraint");',
        )
        self.source.write_text(updated)
        report = self.campaign()
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["counts"]["survived"], 1)

        self.source.write_text(
            updated
            + """
#[test(should_fail_with = "new constraint")]
fn added_negative() { main(3); }
"""
        )
        report = self.campaign()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["counts"]["killed"], 4)

    def test_broken_baseline_leaves_mutants_unscored(self):
        self.source.write_text(
            self.source.read_text().replace("constrain_value(x);", "missing(x);")
        )
        report = self.campaign()
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["counts"]["killed"], 0)
        self.assertEqual(report["counts"]["not_run"], 3)
        self.assertEqual(report["circuits"][0]["baseline"]["status"], "error")

    def test_timeouts_and_exhausted_budget_are_not_kills(self):
        result, _ = mc.run_tests(
            os.environ["NARGO"], self.package, 0.000001, time.monotonic() + 30
        )
        self.assertEqual(result["status"], "timeout")
        report = self.campaign(budget=0.000001)
        self.assertEqual(report["exit_code"], 2)
        self.assertEqual(report["counts"]["killed"], 0)
        self.assertEqual(report["counts"]["not_run"], 3)


if __name__ == "__main__":
    unittest.main()
