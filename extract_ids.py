from typing import Tuple, Union, Any, Iterable
import json
import jwt

def extract_gpu_ids(
    token_data: Any,
) -> Union[Tuple[Iterable[str], None], Tuple[None, str]]:
    """
    Extract claims from token data using PyJWT.

    Args:
        token_data: Token data from get_token()

    Returns:
        Dictionary of claims or empty dict if parsing fails
    """
    gpu_ids = []
    # Handle string token (likely in JSON format)
    if not isinstance(token_data, str):
        return None, "invalid format"
    try:
        # First, try to parse as JSON
        token_json = json.loads(token_data)
        if not (
            isinstance(token_json, list)
            and len(token_json) >= 2
            and isinstance(token_json[1], dict)
        ):
            return None, "invalid format"
        for claims_key, claims_val in token_json[1].items():
            if not (
                claims_key == "REMOTE_GPU_CLAIMS"
                and isinstance(claims_val, list)
                and len(claims_val) >= 2
            ):
                continue
            gpu_dict = claims_val[1]
            if not isinstance(gpu_dict, dict):
                continue
            # Now we have a dictionary of GPU-ID to JWT token
            for gpu_id, gpu_token in gpu_dict.items():
                if not gpu_id.startswith("GPU-"):
                    continue
                # For each GPU, extract the claims by decoding the JWT with PyJWT
                try:
                    # Decode without verification (we're just extracting claims)
                    gpu_token_data = jwt.decode(
                        gpu_token,
                        options={"verify_signature": False},
                        algorithms=[
                            "ES384",
                            "HS256",
                        ],  # Support both NVIDIA's ES384 and test HS256
                    )

                    # Add this GPU's claims to our results
                    gpu_id = gpu_token_data.get("ueid")
                    if gpu_id:
                        gpu_ids.append(gpu_id)

                except jwt.PyJWTError as e:
                    return None, f"Failed decoding JWT: {e}"

    except Exception as e:
        return None, f"Failed parsing token as json: {e}"

    return gpu_ids, None
