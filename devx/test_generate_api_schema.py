import sys
import unittest
import tempfile
import json
from pathlib import Path

import generate_api_schema

class GenerateApiSchemaTest(unittest.TestCase):
    def test_generate_schema_positive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("""
from flask import Flask
app = Flask(__name__)
@app.get('/test')
def test_route():
    pass
            """, encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "test.json"
            schema_file.write_text('{"schemaHash": "123", "type": "object"}', encoding="utf-8")
            
            schema = generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertIn("/test", schema["paths"])
            self.assertIn("get", schema["paths"]["/test"])
            self.assertEqual(schema["paths"]["/test"]["get"]["operationId"], "test_route")
            
            self.assertIn("123", schema["components"]["schemas"])

    def test_missing_app_py(self):
        with self.assertRaises(FileNotFoundError):
            generate_api_schema.generate_schema(Path("/does/not/exist.py"), Path("/does/not/exist/dir"))

    def test_malformed_app_py(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("def class broken syntax", encoding="utf-8")
            with self.assertRaises(SyntaxError):
                generate_api_schema.generate_schema(app_py, Path("/does/not/exist/dir"))
                
    def test_malformed_json_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "test.json"
            schema_file.write_text('{invalid json', encoding="utf-8")
            
            # Should not crash, just ignores malformed
            schema = generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertNotIn("test", schema["components"]["schemas"])

    def test_oversized_json_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("app = 1", encoding="utf-8")
            
            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()
            schema_file = schemas_dir / "test.json"
            # Oversized file (> 1MB)
            with schema_file.open("wb") as f:
                f.write(b'{"schemaHash": "123"}')
                f.write(b' ' * (1024 * 1024 + 10))
            
            # Should ignore oversized
            schema = generate_api_schema.generate_schema(app_py, schemas_dir)
            self.assertNotIn("123", schema["components"]["schemas"])

if __name__ == '__main__':
    unittest.main()
