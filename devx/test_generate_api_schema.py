import sys
import unittest
import tempfile
import json
from pathlib import Path

import re
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

    def test_path_converters_and_parameters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("""
from flask import Flask
app = Flask(__name__)

@app.get('/api/jobs/<int:job_id>')
def get_job(job_id):
    pass

@app.get('/api/proofs/by-video/<video_hash>')
def proof_by_video(video_hash):
    pass

@app.put('/api/stego/upload-session/<session_id>/chunk/<int:chunk_index>')
def upload_chunk(session_id, chunk_index):
    pass

@app.get('/api/items/<float:rate>/<path:subpath>/<uuid:item_uuid>')
def complex_route(rate, subpath, item_uuid):
    pass
            """, encoding="utf-8")

            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()

            schema = generate_api_schema.generate_schema(app_py, schemas_dir)
            
            # Acceptance criteria: No < or > characters remain in generated paths
            for path in schema["paths"]:
                self.assertNotIn("<", path)
                self.assertNotIn(">", path)

            # Check /api/jobs/{job_id}
            self.assertIn("/api/jobs/{job_id}", schema["paths"])
            job_op = schema["paths"]["/api/jobs/{job_id}"]["get"]
            self.assertEqual(job_op["operationId"], "get_job")
            self.assertEqual(len(job_op["parameters"]), 1)
            self.assertEqual(job_op["parameters"][0], {
                "name": "job_id",
                "in": "path",
                "required": True,
                "schema": {"type": "integer"}
            })

            # Check /api/proofs/by-video/{video_hash}
            self.assertIn("/api/proofs/by-video/{video_hash}", schema["paths"])
            proof_op = schema["paths"]["/api/proofs/by-video/{video_hash}"]["get"]
            self.assertEqual(proof_op["operationId"], "proof_by_video")
            self.assertEqual(proof_op["parameters"][0], {
                "name": "video_hash",
                "in": "path",
                "required": True,
                "schema": {"type": "string"}
            })

            # Check multi-parameter route: /api/stego/upload-session/{session_id}/chunk/{chunk_index}
            put_path = "/api/stego/upload-session/{session_id}/chunk/{chunk_index}"
            self.assertIn(put_path, schema["paths"])
            put_op = schema["paths"][put_path]["put"]
            self.assertEqual(put_op["operationId"], "upload_chunk")
            self.assertEqual(len(put_op["parameters"]), 2)
            self.assertEqual(put_op["parameters"][0]["name"], "session_id")
            self.assertEqual(put_op["parameters"][0]["schema"]["type"], "string")
            self.assertEqual(put_op["parameters"][1]["name"], "chunk_index")
            self.assertEqual(put_op["parameters"][1]["schema"]["type"], "integer")

            # Check float, path, uuid converters
            multi_path = "/api/items/{rate}/{subpath}/{item_uuid}"
            self.assertIn(multi_path, schema["paths"])
            multi_op = schema["paths"][multi_path]["get"]
            params = {p["name"]: p["schema"]["type"] for p in multi_op["parameters"]}
            self.assertEqual(params, {
                "rate": "number",
                "subpath": "string",
                "item_uuid": "string",
            })

    def test_route_decorator_and_methods(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("""
from flask import Flask
app = Flask(__name__)

@app.route('/api/items', methods=['GET', 'POST'])
def items():
    pass

@app.route('/api/items/<int:item_id>', methods=['DELETE', 'PATCH'])
def item_detail(item_id):
    pass

@app.route('/api/default-get')
def default_get():
    pass
            """, encoding="utf-8")

            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()

            schema = generate_api_schema.generate_schema(app_py, schemas_dir)

            self.assertIn("/api/items", schema["paths"])
            self.assertIn("get", schema["paths"]["/api/items"])
            self.assertIn("post", schema["paths"]["/api/items"])
            self.assertEqual(schema["paths"]["/api/items"]["get"]["operationId"], "items")
            self.assertEqual(schema["paths"]["/api/items"]["post"]["operationId"], "items")

            self.assertIn("/api/items/{item_id}", schema["paths"])
            self.assertIn("delete", schema["paths"]["/api/items/{item_id}"])
            self.assertIn("patch", schema["paths"]["/api/items/{item_id}"])
            self.assertEqual(schema["paths"]["/api/items/{item_id}"]["delete"]["operationId"], "item_detail")
            self.assertEqual(schema["paths"]["/api/items/{item_id}"]["patch"]["operationId"], "item_detail")
            self.assertEqual(schema["paths"]["/api/items/{item_id}"]["delete"]["parameters"][0]["schema"]["type"], "integer")

            self.assertIn("/api/default-get", schema["paths"])
            self.assertIn("get", schema["paths"]["/api/default-get"])
            self.assertEqual(schema["paths"]["/api/default-get"]["get"]["operationId"], "default_get")

    def test_blueprint_decorators(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            app_py = tmp / "app.py"
            app_py.write_text("""
from flask import Blueprint, Flask
app = Flask(__name__)
api_bp = Blueprint('api', __name__)
auth_blueprint = Blueprint('auth', __name__)

@api_bp.get('/api/blueprint-resource/<int:res_id>')
def get_resource(res_id):
    pass

@auth_blueprint.route('/auth/login', methods=['POST'])
def login():
    pass

@api_bp.route('/api/blueprint-data')
def get_data():
    pass
            """, encoding="utf-8")

            schemas_dir = tmp / "schemas"
            schemas_dir.mkdir()

            schema = generate_api_schema.generate_schema(app_py, schemas_dir)

            self.assertIn("/api/blueprint-resource/{res_id}", schema["paths"])
            self.assertIn("get", schema["paths"]["/api/blueprint-resource/{res_id}"])
            bp_op = schema["paths"]["/api/blueprint-resource/{res_id}"]["get"]
            self.assertEqual(bp_op["operationId"], "get_resource")
            self.assertEqual(bp_op["parameters"][0]["schema"]["type"], "integer")

            self.assertIn("/auth/login", schema["paths"])
            self.assertIn("post", schema["paths"]["/auth/login"])
            self.assertEqual(schema["paths"]["/auth/login"]["post"]["operationId"], "login")

            self.assertIn("/api/blueprint-data", schema["paths"])
            self.assertIn("get", schema["paths"]["/api/blueprint-data"])
            self.assertEqual(schema["paths"]["/api/blueprint-data"]["get"]["operationId"], "get_data")

    def test_structural_openapi_validation(self):
        root = Path(__file__).resolve().parent.parent
        app_path = root / "backend" / "app.py"
        schemas_dir = root / "backend" / "schemas"
        schema = generate_api_schema.generate_schema(app_path, schemas_dir)

        # Structural OpenAPI 3.1.0 assertions
        self.assertEqual(schema["openapi"], "3.1.0")
        self.assertIn("info", schema)
        self.assertIn("title", schema["info"])
        self.assertIn("version", schema["info"])
        self.assertIn("paths", schema)

        for path, path_item in schema["paths"].items():
            # Acceptance criteria: No < or > characters remain in generated paths
            self.assertNotIn("<", path)
            self.assertNotIn(">", path)
            
            # Extract template variables in path: {var}
            path_vars = set(re.findall(r"\{([^}]+)\}", path))

            for method, operation in path_item.items():
                self.assertIn(method, {"get", "post", "put", "delete", "patch", "head", "options", "trace"})
                self.assertIn("operationId", operation)
                self.assertIn("responses", operation)

                if path_vars:
                    # Each templated segment must have a matching parameter
                    self.assertIn("parameters", operation)
                    param_names = {p["name"] for p in operation["parameters"] if p.get("in") == "path"}
                    self.assertEqual(path_vars, param_names)
                    for param in operation["parameters"]:
                        self.assertEqual(param["in"], "path")
                        self.assertTrue(param["required"])
                        self.assertIn("schema", param)
                        self.assertIn("type", param["schema"])
                        self.assertIn(param["schema"]["type"], {"string", "integer", "number", "boolean"})

if __name__ == '__main__':
    unittest.main()

