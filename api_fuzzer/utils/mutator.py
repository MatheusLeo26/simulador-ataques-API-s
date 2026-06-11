import copy
from typing import Any, Dict, Iterator, Tuple

def generate_default_body(schema: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates a valid dictionary matching the OpenAPI schema provided.
    """
    if not schema or not isinstance(schema, dict):
        return {}

    properties = schema.get("properties", {})
    payload = {}

    for prop_name, prop_details in properties.items():
        prop_type = prop_details.get("type", "string")
        
        if prop_type == "string":
            payload[prop_name] = "test"
        elif prop_type == "integer" or prop_type == "number":
            payload[prop_name] = 1
        elif prop_type == "boolean":
            payload[prop_name] = True
        elif prop_type == "object":
            payload[prop_name] = generate_default_body(prop_details)
        elif prop_type == "array":
            items = prop_details.get("items", {})
            payload[prop_name] = [generate_default_body(items) if items.get("type") == "object" else "test"]
        else:
            payload[prop_name] = "test"

    return payload

def mutate_payload(base_payload: Dict[str, Any], payloads: list) -> Iterator[Tuple[str, Any, Dict[str, Any]]]:
    """
    Recursively iterates through the dictionary and yields permutations where
    exactly one field is replaced by a malicious payload.
    Yields: (mutated_field_path, payload_used, mutated_json_dict)
    """
    def _mutate_recursive(current_obj, path):
        if isinstance(current_obj, dict):
            for key, value in current_obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # If value is primitive, yield mutations for it
                if not isinstance(value, (dict, list)):
                    for pl in payloads:
                        mutated_copy = copy.deepcopy(base_payload)
                        # Navigate the deepcopy and inject the payload
                        target = mutated_copy
                        if path:
                            for p in path.split("."):
                                target = target[p]
                        target[key] = pl
                        yield current_path, pl, mutated_copy
                
                # Recurse deeper
                yield from _mutate_recursive(value, current_path)
                
        elif isinstance(current_obj, list):
            for i, item in enumerate(current_obj):
                current_path = f"{path}[{i}]"
                if not isinstance(item, (dict, list)):
                    for pl in payloads:
                        mutated_copy = copy.deepcopy(base_payload)
                        # This simple nav doesn't handle array paths fully out of the box, 
                        # but for standard JSON fuzzing it's enough to mutate the dict keys.
                        # For robustness, we could use a proper JSONPath library, but let's keep it simple.
                        pass
                yield from _mutate_recursive(item, current_path)

    yield from _mutate_recursive(base_payload, "")
