import sys
from pydantic import BaseModel
from nv_attestation_sdk import attestation
from fastapi import FastAPI
import json
from typing import Iterable, Optional, Dict, Any, Tuple, Union
from logconfig import setupLogging
import jwt

logger = setupLogging()


def load_policy(filename: str) -> str:
    try:
        with open(filename, "r") as f:
            policy = json.load(f)
        return json.dumps(policy)
    except Exception as e:
        logger.error(f"No policy found: {e}")
        sys.exit()


app = FastAPI()
GPU_ATTESTATION_POLICY = load_policy("gpu_remote_policy.json")
SWITCH_ATTESTATION_POLICY = load_policy("switch_remote_policy.json")


@app.get("/")
def ping():
    return ""


class Attestation(BaseModel):
    attestation_result: bool
    token: str
    valid: bool


class GPUClaims(BaseModel):
    gpu_type: str
    gpu_id: str


class SwitchClaims(BaseModel):
    switch_type: str
    switch_id: str


class AttestationResponse(BaseModel):
    gpu_attestation_success: bool
    switch_attestation_success: bool
    gpu_claims: Optional[Dict[str, GPUClaims]] | bool = None
    switch_claims: Optional[Dict[str, SwitchClaims]] | bool = None
    gpu_ids: Iterable[str] = []


class Request(BaseModel):
    gpu_remote: Attestation
    switch_remote: Attestation
    gpu_local: Attestation
    switch_local: Attestation
    expected_nonce: str


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
    try:
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
                        logger.debug(f"Failed to decode JWT for {gpu_id}: {str(e)}")
                        return None, "Failed decoding JWT"

        except Exception as e:
            logger.debug(f"Failed to parse token as JSON: {str(e)}")
            return None, "Failed parsing token as json"

        return gpu_ids, None

    except Exception as e:
        logger.warning(f"Error extracting claims from token: {str(e)}")
        return None, "Error extracting claims from token"


def extract_gpu_claims_from_token(
    token_data: str, expected_nonce: str
) -> Union[Tuple[Dict[str, Any], None], Tuple[None, str]]:
    """
    Extract claims from token data using PyJWT.

    Args:
        token_data: Token data from get_token()

    Returns:
        Dictionary of claims or empty dict if parsing fails
    """
    try:
        gpu_claims = {}

        # Handle string token (likely in JSON format)
        if isinstance(token_data, str):
            try:
                # First, try to parse as JSON
                token_json = json.loads(token_data)

                # The token has a complex nested structure:
                # [[JWT, token], {REMOTE_GPU_CLAIMS: [[JWT, token], {GPU-0: token, ...}]}]

                # Look for LOCAL_GPU_CLAIMS
                if (
                    isinstance(token_json, list)
                    and len(token_json) >= 2
                    and isinstance(token_json[1], dict)
                ):
                    for claims_key, claims_val in token_json[1].items():
                        if (
                            claims_key == "LOCAL_GPU_CLAIMS"
                            and isinstance(claims_val, list)
                            and len(claims_val) >= 2
                        ):
                            gpu_dict = claims_val[1]
                            if isinstance(gpu_dict, dict):
                                # Now we have a dictionary of GPU-ID to JWT token
                                for gpu_id, gpu_token in gpu_dict.items():
                                    if gpu_id.startswith("GPU-"):
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

                                            if (
                                                gpu_token_data.get("eat_nonce")
                                                != expected_nonce
                                            ):
                                                return None, "Nonce does not match"

                                            # Add this GPU's claims to our results
                                            gpu_claims[gpu_id] = {
                                                "gpu_id": gpu_token_data.get(
                                                    "ueid", "Unknown"
                                                ),
                                                "gpu_type": gpu_token_data.get(
                                                    "gpu_type", "Unknown"
                                                ),
                                            }

                                        except jwt.PyJWTError as e:
                                            logger.debug(
                                                f"Failed to decode JWT for {gpu_id}: {str(e)}"
                                            )
                                            return None, "Failed decoding JWT"

            except Exception as e:
                logger.debug(f"Failed to parse token as JSON: {str(e)}")
                return None, "Failed parsing token as json"

        # If we successfully extracted claims, return them
        if gpu_claims:
            return gpu_claims, None

        # If we get here, we couldn't extract claims
        logger.debug("Unable to extract claims from token")
        return None, "Unable to extract claims from token"

    except Exception as e:
        logger.warning(f"Error extracting claims from token: {str(e)}")
        return None, "Error extracting claims from token"


def extract_switch_claims_from_token(
    token_data: str, expected_nonce: str
) -> Union[Tuple[Dict[str, Any], None], Tuple[None, str]]:
    """
    Extract claims from switch token data using PyJWT.

    Args:
        token_data: Token data from get_token()
        expected_nonce: Expected nonce value to verify

    Returns:
        True if claims are extracted successfully and nonce matches, False otherwise
    """
    try:
        switch_claims = {}
        # Handle string token (likely in JSON format)
        if isinstance(token_data, str):
            try:
                # First, try to parse as JSON
                token_json = json.loads(token_data)

                # The token has a complex nested structure:
                # [[JWT, token], {REMOTE_SWITCH_CLAIMS: [[JWT, token], {SWITCH-0: token, ...}]}]

                # Look for LOCAL_SWITCH_CLAIMS
                if (
                    isinstance(token_json, list)
                    and len(token_json) >= 2
                    and isinstance(token_json[1], dict)
                ):
                    for claims_key, claims_val in token_json[1].items():
                        if (
                            claims_key == "LOCAL_SWITCH_CLAIMS"
                            and isinstance(claims_val, list)
                            and len(claims_val) >= 2
                        ):
                            switch_dict = claims_val[1]
                            if isinstance(switch_dict, dict):
                                # Now we have a dictionary of SWITCH-ID to JWT token
                                for switch_id, switch_token in switch_dict.items():
                                    if switch_id.startswith("SWITCH-"):
                                        try:
                                            # Decode without verification (we're just extracting claims)
                                            switch_token_data = jwt.decode(
                                                switch_token,
                                                options={"verify_signature": False},
                                                algorithms=[
                                                    "ES384",
                                                    "HS256",
                                                ],  # Support both NVIDIA's ES384 and test HS256
                                            )

                                            # Verify nonce match
                                            if (
                                                switch_token_data.get("eat_nonce")
                                                != expected_nonce
                                            ):
                                                return None, "Nonce does not match"

                                            # Return the switch claims
                                            switch_claims[switch_id] = {
                                                "switch_id": switch_token_data.get(
                                                    "ueid", "Unknown"
                                                ),
                                                "switch_type": switch_token_data.get(
                                                    "hwmodel", "Unknown"
                                                ),
                                            }
                                        except jwt.PyJWTError as e:
                                            logger.debug(
                                                f"Failed to decode JWT for {switch_id}: {str(e)}"
                                            )
                                            return None, "Failed decoding JWT token"
            except Exception as e:
                logger.debug(f"Failed to parse token as JSON: {str(e)}")

        if switch_claims:
            return switch_claims, None
        # If we get here, we couldn't extract claims
        logger.debug("Unable to extract claims from token")
        return None, "Unable to extract claims from token"

    except Exception as e:
        logger.warning(f"Error extracting claims from token: {str(e)}")
        return None, "Error extracting claims from token"


@app.post("/attest", response_model=AttestationResponse)
async def attest(req: Request) -> AttestationResponse:
    logger.info("getting attest request")
    try:
        # GPU Attestation
        gpu_client = attestation.Attestation()
        gpu_client.set_name("HGX-node")
        gpu_client.set_nonce(req.expected_nonce)
        gpu_client.set_claims_version("2.0")
        gpu_client.set_ocsp_nonce_disabled(False)

        gpu_client.add_verifier(
            dev=attestation.Devices.GPU,
            env=attestation.Environment.REMOTE,
            url="https://nras.attestation.nvidia.com/v3/attest/gpu",
            evidence="",
            ocsp_url="https://ocsp.ndis.nvidia.com/",
            rim_url="https://rim.attestation.nvidia.com/v1/rim/",
        )

        # Set the token from the request
        gpu_client.set_token("HGX-node", req.gpu_remote.token)

        # Validate GPU token with policy
        if not gpu_client.validate_token(GPU_ATTESTATION_POLICY):
            logger.info("Invalid token")
            return AttestationResponse(
                gpu_attestation_success=False, switch_attestation_success=False
            )

        # Verify GPU claims
        gpu_claims, err = extract_gpu_claims_from_token(
            req.gpu_local.token, req.expected_nonce
        )
        if err is not None:
            logger.info(f"Error extracting gpu claims: {err}")
            return AttestationResponse(
                gpu_attestation_success=False, switch_attestation_success=False
            )
        gpu_client.clear_verifiers()

        # Switch Attestation
        switch_client = attestation.Attestation()
        switch_client.set_name("HGX-node")
        switch_client.set_nonce(req.expected_nonce)
        switch_client.set_claims_version("2.0")
        switch_client.set_ocsp_nonce_disabled(False)

        switch_client.add_verifier(
            dev=attestation.Devices.SWITCH,
            env=attestation.Environment.REMOTE,
            url="https://nras.attestation.nvidia.com/v3/attest/switch",
            evidence="",
            ocsp_url="https://ocsp.ndis.nvidia.com/",
            rim_url="https://rim.attestation.nvidia.com/v1/rim/",
        )

        # Set the token from the request
        switch_client.set_token("HGX-node", req.switch_remote.token)

        # Validate switch token with policy
        if not switch_client.validate_token(SWITCH_ATTESTATION_POLICY):
            logger.info("Error validating token")
            return AttestationResponse(
                gpu_attestation_success=True,
                switch_attestation_success=False,
            )

        # Verify switch claims
        switch_claims, err = extract_switch_claims_from_token(
            req.switch_local.token, req.expected_nonce
        )
        if err is not None:
            logger.info(f"Error extracting switch claims: {err}")
            return AttestationResponse(
                gpu_attestation_success=True,
                switch_attestation_success=False,
            )

        switch_client.clear_verifiers()
        gpu_ids, err = extract_gpu_ids(req.gpu_remote.token)
        if err is not None or gpu_ids is None:
            logger.info(f"Error extracting gpu ids: {err}")
            return AttestationResponse(
                gpu_attestation_success=True,
                switch_attestation_success=False,
            )

        res = AttestationResponse(
            gpu_ids=gpu_ids,
            gpu_attestation_success=True,
            switch_attestation_success=True,
            gpu_claims=gpu_claims,
            switch_claims=switch_claims,
        )
        logger.info(f"Successfully passed attesstation, {res=}")
        return res

    except Exception as e:
        logger.error(f"Error during attestation: {e}")
        return AttestationResponse(
            gpu_attestation_success=False, switch_attestation_success=False
        )


logger.info("Starting nvidia-attest")
