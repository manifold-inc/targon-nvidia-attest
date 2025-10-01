import sys
from typing import List
from pydantic import BaseModel
from nv_attestation_sdk import attestation
from fastapi import FastAPI
import json
from logconfig import setupLogging
from extract_ids import extract_gpu_ids

logger = setupLogging()


def load_policy(filename: str) -> str:
    try:
        with open(filename, "r") as f:
            policy = json.load(f)
        return json.dumps(policy)
    except Exception as e:
        logger.error(f"No policy found: {e}")
        sys.exit()


def load_ueids(filename: str) -> List[str]:
    try:
        with open(filename, "r") as f:
            ueids = f.read().strip()
            ids = ueids.split("\n")
            ids = [i.strip() for i in ids]
        return ids
    except Exception as e:
        logger.error(f"ueids not found: {e}")
        sys.exit()


app = FastAPI()
GPU_ATTESTATION_POLICY = load_policy("gpu_remote_policy.json")
SWITCH_ATTESTATION_POLICY = load_policy("switch_remote_policy.json")
UEIDS = load_ueids("ueids/ueids.txt")
logger.info(UEIDS)


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


class Request(BaseModel):
    gpu_remote: Attestation
    switch_remote: Attestation
    expected_nonce: str


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

        ids, err = extract_gpu_ids(gpu_client.get_token())
        if err != None or ids == None:
            return AttestationResponse(
                gpu_attestation_success=False, switch_attestation_success=False
            )
        for i in ids:
            if i in UEIDS:
                return AttestationResponse(
                    gpu_attestation_success=False, switch_attestation_success=False
                )

        # Validate GPU token with policy
        if not gpu_client.validate_token(GPU_ATTESTATION_POLICY):
            logger.info("Invalid token")
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

        switch_client.clear_verifiers()
        res = AttestationResponse(
            gpu_attestation_success=True,
            switch_attestation_success=True,
        )
        logger.info(f"Successfully passed attesstation, {res=}")
        return res

    except Exception as e:
        logger.error(f"Error during attestation: {e}")
        return AttestationResponse(
            gpu_attestation_success=False, switch_attestation_success=False
        )


logger.info("Starting nvidia-attest")
