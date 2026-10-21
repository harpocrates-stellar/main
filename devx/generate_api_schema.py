import sys
import json
import ast
import argparse
import re
from pathlib import Path

import re

CONVERTER_TYPE_MAP = {
    "int": "integer",
    "integer": "integer",
    "float": "number",
    "path": "string",
    "string": "string",
    "uuid": "string",
    "any": "string",
}

def parse_flask_path_and_parameters(flask_path: str):
    """
    Converts a Flask path template (e.g. '/api/jobs/<int:job_id>')
    to an OpenAPI path ('/api/jobs/{job_id}') and extracts path parameters.
    """
    parameters = []
    
    def _repl(match):
        segment = match.group(1)
        if ":" in segment:
            converter, name = segment.split(":", 1)
        else:
            converter, name = "", segment
        
        schema_type = CONVERTER_TYPE_MAP.get(converter, "string")
        parameters.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {
                "type": schema_type
            }
        })
        return f"{{{name}}}"
    
    openapi_path = re.sub(r"<([^>]+)>", _repl, flask_path)
    return openapi_path, parameters

def extract_routes_from_ast(app_path: Path):
    routes = []
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    
    # Track Blueprint instances: blueprint_var_name -> Blueprint
    blueprint_vars = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            # Check if assigned value is Blueprint(...)
            if isinstance(node.value, ast.Call):
                func = node.value.func
                is_bp = False
                if isinstance(func, ast.Name) and func.id == "Blueprint":
                    is_bp = True
                elif isinstance(func, ast.Attribute) and func.attr == "Blueprint":
                    is_bp = True
                if is_bp:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            blueprint_vars.add(target.id)

    http_methods = {"get", "post", "put", "delete", "patch"}

    def _extract_constant_str(node_arg):
        if isinstance(node_arg, ast.Constant) and isinstance(node_arg.value, str):
            return node_arg.value
        return None

    def _extract_methods_list(node_arg):
        methods = []
        if isinstance(node_arg, (ast.List, ast.Tuple, ast.Set)):
            for elt in node_arg.elts:
                val = _extract_constant_str(elt)
                if val:
                    methods.append(val.upper())
        elif isinstance(node_arg, ast.Constant) and isinstance(node_arg.value, str):
            methods.append(node_arg.value.upper())
        return methods

    for node in ast.walk(tree):
        # Handle module-level route registrations via decorators on functions
        # and also detect path parameters like <output_digest>.
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                # Handle @app.get("/path"), @app.post("/path"), @app.put("/path")
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    if isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == "app":
                        method = decorator.func.attr # "get", "post", "put"
                        if method in {"get", "post", "put", "delete", "patch"}:
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                path = decorator.args[0].value
                                routes.append((path, method.upper(), node.name))
    return routes

def _normalize_path(path: str) -> str:
    # Convert Flask-style <param> segments to OpenAPI {param} segments.
    return re.sub(r"<([^>]+)>", r"{\1}", path)

def _extract_path_params(path: str):
    params = []
    for match in re.finditer(r"<([^>]+)>", path):
        name = match.group(1)
        # Strip converters like <int:foo> -> foo
        if ":" in name:
            name = name.split(":", 1)[1]
        params.append(name)
    return params

def _build_parameters(path: str):
    parameters = []
    for name in _extract_path_params(path):
        parameters.append({
            "name": name,
            "in": "path",
            "required": True,
            "schema": {"type": "string"}
        })
    return parameters

def _legacy_extract_routes_from_ast(app_path: Path):
    routes = []
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for decorator in node.decorator_list:
                # Handle @target.method(...) or @target.route(...)
                if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                    target_name = None
                    if isinstance(decorator.func.value, ast.Name):
                        target_name = decorator.func.value.id
                    
                    if target_name and (target_name == "app" or target_name in blueprint_vars or target_name.endswith("_bp") or target_name == "bp"):
                        attr = decorator.func.attr
                        # 1. @app.<verb>("/path") or @bp.<verb>("/path")
                        if attr in http_methods:
                            if decorator.args:
                                path_val = _extract_constant_str(decorator.args[0])
                                if path_val is not None:
                                    routes.append((path_val, attr.upper(), node.name))
                        # 2. @app.route("/path", methods=[...]) or @bp.route("/path", methods=[...])
                        elif attr == "route":
                            path_val = None
                            if decorator.args:
                                path_val = _extract_constant_str(decorator.args[0])
                            else:
                                for kw in decorator.keywords:
                                    if kw.arg in {"rule", "path"}:
                                        path_val = _extract_constant_str(kw.value)
                            
                            if path_val is not None:
                                methods = []
                                for kw in decorator.keywords:
                                    if kw.arg == "methods":
                                        methods = _extract_methods_list(kw.value)
                                if not methods:
                                    methods = ["GET"]
                                for method in methods:
                                    routes.append((path_val, method.upper(), node.name))

    return routes

def generate_schema(app_path: Path, schemas_dir: Path):
    if not app_path.exists():
        raise FileNotFoundError("app.py not found")
        
    paths = {}
    routes = extract_routes_from_ast(app_path)
    for raw_path, method, endpoint in routes:
        openapi_path, parameters = parse_flask_path_and_parameters(raw_path)
        paths.setdefault(openapi_path, {})
        op_def = {
            "operationId": endpoint,
            "responses": {
                "200": {"description": "OK"}
            }
        }
        if parameters:
            op_def["parameters"] = parameters
        paths[openapi_path][method.lower()] = op_def

    schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "Harpocrates API",
            "version": "1.0.0"
        },
        "paths": paths,
        "components": {
            "schemas": {}
        }
    }

    # Normalize Flask-style path parameters to OpenAPI style and attach
    # path parameter definitions for routes such as /api/lineage/<output_digest>.
    normalized_paths = {}
    for path, methods in paths.items():
        normalized = _normalize_path(path)
        normalized_paths.setdefault(normalized, {})
        parameters = _build_parameters(path)
        for method, operation in methods.items():
            if parameters:
                operation = dict(operation)
                operation["parameters"] = parameters
            normalized_paths[normalized][method] = operation
    schema["paths"] = normalized_paths
    
    # Load canonical schemas safely
    if schemas_dir.is_dir():
        for p in sorted(schemas_dir.glob("*.json")):
            # Check for oversized/malformed schemas
            if p.stat().st_size > 1024 * 1024:
                continue # ignore oversized
            try:
                with p.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        schema_hash = data.get("schemaHash")
                        if schema_hash:
                            schema["components"]["schemas"][schema_hash] = data
            except Exception:
                pass
                
    return schema

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--app-path", type=Path)
    parser.add_argument("--schemas-dir", type=Path)
    args = parser.parse_args()
    
    root = Path(__file__).resolve().parent.parent
    app_path = args.app_path or (root / "backend" / "app.py")
    schemas_dir = args.schemas_dir or (root / "backend" / "schemas")
    
    try:
        schema = generate_schema(app_path, schemas_dir)
        out_json = json.dumps(schema, indent=2)
    except FileNotFoundError as e:
        print(f"dependency failure: {e}", file=sys.stderr)
        sys.exit(2)
    except SyntaxError as e:
        print(f"malformed input: app.py is not valid Python: {e}", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"schema generation failed: {e}", file=sys.stderr)
        sys.exit(4)
        
    if args.output:
        args.output.write_text(out_json, encoding="utf-8")
    else:
        print(out_json)

if __name__ == '__main__':
    main()
