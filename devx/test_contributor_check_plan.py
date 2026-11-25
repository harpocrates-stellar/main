import json
import unittest

from devx import contributor_check_plan as ccp


class NormalizePathTests(unittest.TestCase):
    def test_normalizes_separators_and_prefixes(self):
        self.assertEqual(ccp.normalize_path("./backend\\app.py"), "backend/app.py")
        self.assertEqual(ccp.normalize_path("  /frontend/x.ts "), "frontend/x.ts")


class LayerMatchingTests(unittest.TestCase):
    def test_maps_known_layers(self):
        self.assertEqual(ccp.layer_for_path("backend/app.py").layer, "backend")
        self.assertEqual(ccp.layer_for_path("contracts/lib.rs").layer, "contracts")
        self.assertEqual(ccp.layer_for_path("circuits/main.nr").layer, "circuits")

    def test_unknown_path_returns_none(self):
        self.assertIsNone(ccp.layer_for_path("README.md"))

    def test_prefix_requires_directory_boundary(self):
        # "backendx/" must not match the "backend/" layer.
        self.assertIsNone(ccp.layer_for_path("backendx/file.py"))


class BuildPlanTests(unittest.TestCase):
    def test_plan_is_order_independent_and_deduplicated(self):
        a = ccp.build_plan(["backend/a.py", "frontend/b.ts", "backend/a.py"])
        b = ccp.build_plan(["frontend/b.ts", "backend/a.py"])
        self.assertEqual(a.to_dict(), b.to_dict())
        self.assertEqual(a.changed_files, ["backend/a.py", "frontend/b.ts"])

    def test_layers_are_sorted_and_carry_commands(self):
        plan = ccp.build_plan(["frontend/x.ts", "backend/y.py"])
        names = [entry["layer"] for entry in plan.layers]
        self.assertEqual(names, ["backend", "frontend"])
        backend = plan.layers[0]
        self.assertIn("cd backend && python -m pytest -v", backend["test"])
        self.assertIn("Python 3", backend["dependencies"])

    def test_unmapped_files_are_reported_separately(self):
        plan = ccp.build_plan(["README.md", "backend/a.py"])
        self.assertEqual(plan.unmapped_files, ["README.md"])
        self.assertEqual([e["layer"] for e in plan.layers], ["backend"])

    def test_empty_input_yields_empty_plan(self):
        plan = ccp.build_plan([])
        self.assertEqual(plan.changed_files, [])
        self.assertEqual(plan.layers, [])
        self.assertIn("No changed files.", ccp.render_text(plan))

    def test_unmapped_only_reports_no_layers(self):
        text = ccp.render_text(ccp.build_plan(["docs/intro.md"]))
        self.assertIn("No protocol layers matched", text)
        self.assertIn("Unmapped files", text)


class RenderTests(unittest.TestCase):
    def test_json_output_is_valid_and_stable(self):
        plan = ccp.build_plan(["contracts/lib.rs"])
        data = json.loads(ccp.render_json(plan))
        self.assertEqual(data["layers"][0]["layer"], "contracts")
        self.assertEqual(ccp.render_json(plan), ccp.render_json(ccp.build_plan(["contracts/lib.rs"])))

    def test_text_output_lists_commands_with_prompt(self):
        text = ccp.render_text(ccp.build_plan(["circuits/main.nr"]))
        self.assertIn("$ cd circuits && nargo test", text)


class MainTests(unittest.TestCase):
    def test_main_with_explicit_files_json(self):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ccp.main(["--files", "cli/index.js", "--json"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(buf.getvalue())["layers"][0]["layer"], "cli")


if __name__ == "__main__":
    unittest.main()
