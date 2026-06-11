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

def get_smart_payloads(prop_type: str) -> list:
    """Returns malicious payloads specifically targeted at a given data type."""
    from api_fuzzer.utils.payloads import LOGIC_BREAKING_PAYLOADS
    
    if prop_type in ["integer", "number"]:
        return [-999999999999999999, 999999999999999999, 0, -1, "NaN", "1.0000000000000001", "NOT_A_NUM", None, []]
    elif prop_type == "boolean":
        return ["true", "false", 2, -1, "random_string", None, []]
    elif prop_type == "string":
        # Combines generic logic breakers with extremely large strings for overflow
        return LOGIC_BREAKING_PAYLOADS + ["A" * 5000, ""]
    elif prop_type == "array":
        return ["not_an_array", {}, None]
    
    return LOGIC_BREAKING_PAYLOADS

def mutate_payload_smart(schema: Dict[str, Any], base_payload: Dict[str, Any]) -> Iterator[Tuple[str, Any, Dict[str, Any]]]:
    """
    Recursively iterates through the schema and base payload, yielding permutations 
    where exactly one field is replaced by a type-specific malicious payload.
    """
    def _mutate_recursive(current_schema: Dict[str, Any], current_obj: Any, path: str):
        properties = current_schema.get("properties", {})
        
        if isinstance(current_obj, dict):
            for key, value in current_obj.items():
                current_path = f"{path}.{key}" if path else key
                prop_details = properties.get(key, {})
                prop_type = prop_details.get("type", "string")
                
                # If value is primitive, yield mutations for it based on its type
                if not isinstance(value, (dict, list)):
                    payloads = get_smart_payloads(prop_type)
                    for pl in payloads:
                        mutated_copy = copy.deepcopy(base_payload)
                        # Navigate the deepcopy and inject the payload
                        target = mutated_copy
                        if path:
                            for p in path.split("."):
                                target = target[p]
                        target[key] = pl
                        yield current_path, pl, mutated_copy
                
                # Recurse deeper if object
                if prop_type == "object" and isinstance(value, dict):
                    yield from _mutate_recursive(prop_details, value, current_path)
                
                # Handle Array items
                elif prop_type == "array" and isinstance(value, list):
                    items_schema = prop_details.get("items", {})
                    for i, item in enumerate(value):
                        item_path = f"{current_path}[{i}]"
                        if isinstance(item, dict):
                            yield from _mutate_recursive(items_schema, item, item_path)
                        else:
                            # Primitive array element mutation
                            payloads = get_smart_payloads(items_schema.get("type", "string"))
                            for pl in payloads:
                                mutated_copy = copy.deepcopy(base_payload)
                                target = mutated_copy
                                if path:
                                    for p in path.split("."):
                                        target = target[p]
                                target[key][i] = pl
                                yield item_path, pl, mutated_copy

    yield from _mutate_recursive(schema, base_payload, "")
