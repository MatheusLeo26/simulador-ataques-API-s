import json
import os
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import yaml
from pydantic import BaseModel, Field

class ParameterSchema(BaseModel):
    name: str
    in_: str = Field(alias="in")  # path, query, header, cookie, body
    type: str = "string"
    required: bool = False
    default: Optional[Any] = None

    class Config:
        populate_by_name = True


class Endpoint(BaseModel):
    path: str
    method: str
    parameters: List[ParameterSchema] = []
    body_schema: Optional[Dict[str, Any]] = None


class OpenAPIParser:
    def __init__(self, spec_data: Dict[str, Any]):
        self.spec = spec_data
        self.resolved_spec = self._resolve_references(self.spec, self.spec)

    @classmethod
    def from_file(cls, filepath: str) -> "OpenAPIParser":
        """Loads and parses an OpenAPI spec from a local JSON or YAML file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Specification file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            if filepath.endswith((".yaml", ".yml")):
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        return cls(data)

    def _resolve_references(self, node: Any, root: Dict[str, Any], visited: Optional[set] = None) -> Any:
        """Recursively resolves $ref occurrences in the specification dictionary."""
        if visited is None:
            visited = set()

        if isinstance(node, dict):
            if "$ref" in node:
                ref_path = node["$ref"]
                # Avoid infinite recursion in cyclic schemas
                if ref_path in visited:
                    return {"type": "object", "description": "Cyclic reference detected"}
                
                visited.add(ref_path)
                resolved = self._get_ref_value(ref_path, root)
                resolved = self._resolve_references(resolved, root, visited)
                visited.remove(ref_path)
                return resolved
            
            return {k: self._resolve_references(v, root, visited) for k, v in node.items()}
        
        elif isinstance(node, list):
            return [self._resolve_references(item, root, visited) for item in node]
        
        return node

    def _get_ref_value(self, ref_path: str, root: Dict[str, Any]) -> Any:
        """Traverses the root dictionary to resolve the JSON reference path."""
        if not ref_path.startswith("#/"):
            # Exclude remote/external references for simplicity, or return empty schema
            return {}
        
        parts = ref_path.lstrip("#/").split("/")
        current = root
        for part in parts:
            # Unescape JSON Pointer special characters (~1 -> /, ~0 -> ~)
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                current = current[int(part)]
            else:
                return {}
        return current

    def get_endpoints(self) -> List[Endpoint]:
        """Parses paths and extracts endpoints, HTTP methods, parameters, and bodies."""
        endpoints = []
        paths = self.resolved_spec.get("paths", {})

        for path, path_item in paths.items():
            # Get path-level parameters if any
            path_params = self._parse_parameters(path_item.get("parameters", []))

            # Iterate HTTP methods
            for method in ["get", "post", "put", "delete", "patch"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                op_params = self._parse_parameters(operation.get("parameters", []))
                
                # Combine path-level parameters and operation-level parameters
                # Operation-level overrides path-level with same name and location
                all_params = { (p.name, p.in_): p for p in path_params }
                for p in op_params:
                    all_params[(p.name, p.in_)] = p

                # Extract requestBody (OpenAPI 3.x)
                body_schema = None
                if "requestBody" in operation:
                    content = operation["requestBody"].get("content", {})
                    # Look for application/json content type first
                    json_content = content.get("application/json", {})
                    body_schema = json_content.get("schema")

                # Extract post/put parameters as body if using Swagger 2.0
                elif method in ["post", "put"] and not body_schema:
                    # Look for parameters with in="body"
                    body_param = next((p for p in op_params if p.in_ == "body"), None)
                    if body_param:
                        # Extract schema if available from original parameters structure
                        # Note: _parse_parameters converts parameters. Here we extract definition
                        pass

                endpoints.append(
                    Endpoint(
                        path=path,
                        method=method.upper(),
                        parameters=list(all_params.values()),
                        body_schema=body_schema,
                    )
                )

        return endpoints

    def _parse_parameters(self, raw_params: List[Dict[str, Any]]) -> List[ParameterSchema]:
        """Converts raw OpenAPI parameters into ParameterSchema instances."""
        parsed = []
        for param in raw_params:
            if not isinstance(param, dict):
                continue
            
            name = param.get("name", "")
            in_val = param.get("in", "")
            required = param.get("required", False)
            default = param.get("default")
            
            # OpenAPI 3.x schema vs Swagger 2.0 type
            schema = param.get("schema", {})
            param_type = "string"
            if "type" in param:
                param_type = param["type"]
            elif isinstance(schema, dict) and "type" in schema:
                param_type = schema["type"]
                if default is None:
                    default = schema.get("default")

            parsed.append(
                ParameterSchema(
                    name=name,
                    in_=in_val,
                    type=param_type,
                    required=required,
                    default=default,
                )
            )
        return parsed
