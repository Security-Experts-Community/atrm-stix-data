from enum import Enum
from pathlib import Path
from typing import Literal

ATRM_PATH = Path(__file__).parent.parent / "ms-matrix" / "Azure-Threat-Research-Matrix"
ATRM_TACTICS_MAP = {
    "Reconnaissance": "AZTA100",
    "InitialAccess": "AZTA200",
    "Execution": "AZTA300",
    "PrivilegeEscalation": "AZTA400",
    "Persistence": "AZTA500",
    "CredentialAccess": "AZTA600",
    "Impact": "AZTA700",
}
ATRM_VERSION = "0.1"
ATTACK_SPEC_VERSION = "2.1.0"
ATRM_PLATFORM = "Azure AD"
CREATOR_IDENTITY = "identity--5dcf0a7a-875b-470b-8a01-7c6a84c5e68e"


class Mode(Enum):
    STRICT: int = 1
    ATTACK_COMPATIBLE: int = 2


ModeEnumAttribute = Literal[Mode.STRICT, Mode.ATTACK_COMPATIBLE]
# DEFAULT_MODE = Mode.STRICT
DEFAULT_MODE = Mode.ATTACK_COMPATIBLE


class UnexpectedMode(Exception): ...


def get_collection_id(mode: ModeEnumAttribute = DEFAULT_MODE) -> str:
    match mode:
        case Mode.STRICT:
            return "x-mitre-collection--bf1027b3-fe3a-4eac-bdd5-a1c48c4cb89e"
        case Mode.ATTACK_COMPATIBLE:
            return "x-mitre-collection--6aaadb00-2dbf-450a-a3e8-d4c6c5309639"
        case _:
            raise UnexpectedMode("Unexpected mode")


def get_atrm_domain(mode: ModeEnumAttribute = DEFAULT_MODE) -> str:
    match mode:
        case Mode.STRICT:
            return "atrm"
        case Mode.ATTACK_COMPATIBLE:
            return "enterprise-attack"
        case _:
            raise UnexpectedMode("Unexpected mode")


def get_atrm_source(mode=DEFAULT_MODE) -> str:
    match mode:
        case Mode.STRICT:
            return "atrm"
        case Mode.ATTACK_COMPATIBLE:
            return "mitre-attack"
        case _:
            raise UnexpectedMode("Unexpected mode")


def get_kill_chain_name(mode: ModeEnumAttribute = DEFAULT_MODE) -> str:
    match mode:
        case Mode.STRICT:
            return "atrm"
        case Mode.ATTACK_COMPATIBLE:
            return "mitre-attack"
        case _:
            raise UnexpectedMode("Unexpected mode")


DEFAULT_CREATOR_JSON = f"""
{{
    "id": "{CREATOR_IDENTITY}",
    "type": "identity",
    "identity_class": "organization",
    "created": "2024-02-05T14:00:00.188Z",
    "modified": "2024-02-05T14:00:00.188Z",
    "name": "aw350m33d (Security Experts Community)",
    "spec_version": "2.1",
    "x_mitre_attack_spec_version": "2.1.0",
    "x_mitre_domains": [
        "{get_atrm_domain()}"
    ],
    "x_mitre_version": "{ATRM_VERSION}"
}}
"""
