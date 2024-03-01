from pathlib import Path
from enum import Enum

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

class Mode(Enum):
    strict = 1
    attack_compatible = 2
    
# DEFAULT_MODE = Mode.strict
DEFAULT_MODE = Mode.attack_compatible

def GET_ATRM_DOMAIN(mode=DEFAULT_MODE):
    match mode:
        case Mode.strict: 
            return "atrm"
        case Mode.attack_compatible: 
            return "enterprise-attack"
        case _: 
            raise Exception("Unexpected mode")

def GET_ATRM_SOURCE(mode=DEFAULT_MODE):
    match mode:
        case Mode.strict: 
            return "atrm"
        case Mode.attack_compatible: 
            return "mitre-attack"
        case _: 
            raise Exception("Unexpected mode")

def GET_KILL_CHAIN_NAME(mode=DEFAULT_MODE):
    match mode:
        case Mode.strict: 
            return "atrm"
        case Mode.attack_compatible: 
            return "mitre-attack"
        case _: 
            raise Exception("Unexpected mode")

CREATOR_IDENTITY = "identity--5dcf0a7a-875b-470b-8a01-7c6a84c5e68e"
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
        "{GET_ATRM_DOMAIN()}"
    ],
    "x_mitre_version": "{ATRM_VERSION}"
}}
"""