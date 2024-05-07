import html_to_json
from constants import (
    ATRM_PATH,
    ATRM_TACTICS_MAP,
    ATRM_VERSION,
    ATTACK_SPEC_VERSION,
    GET_ATRM_DOMAIN,
    GET_ATRM_SOURCE,
    Mode,
    CREATOR_IDENTITY,
)
from git_tools import get_file_creation_date, get_file_modification_date
from marko.ext.gfm import gfm
from mitreattack.stix20.custom_attack_objects import Tactic
from utils import create_uuid_from_string


def parse_tactic(file_path: str, tactic_name: str, mode: Mode) -> Tactic:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        html_content = gfm(content)
        json_content = html_to_json.convert(html_content)

        tactic_id = ATRM_TACTICS_MAP[tactic_name]
        tactic_description = json_content["p"][0]["_value"]
        tactic_link = f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactic_name}/{tactic_name}"
        tactic_display_name = json_content["h1"][0]["_value"]
        modified_datetime = get_file_modification_date(
            repo_path=ATRM_PATH, file_path=file_path
        )
        creation_datetime = get_file_creation_date(
            repo_path=ATRM_PATH, file_path=file_path
        )

        mitre_tactic_id = "x-mitre-tactic--" + str(
            create_uuid_from_string(val=f"microsoft.atrm.tactic.{tactic_id}")
        )
        return Tactic(
            id=mitre_tactic_id,
            x_mitre_domains=[GET_ATRM_DOMAIN(mode=mode)],
            created=creation_datetime,
            modified=modified_datetime,
            created_by_ref=CREATOR_IDENTITY,
            external_references=[
                {
                    "external_id": tactic_id,
                    "url": tactic_link,
                    "source_name": GET_ATRM_SOURCE(mode=mode),
                },
            ],
            name=tactic_display_name,
            description=tactic_description,
            x_mitre_version=ATRM_VERSION,
            x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
            x_mitre_modified_by_ref=CREATOR_IDENTITY,
            x_mitre_shortname=tactic_display_name.replace(" ", "-").lower(),
        )
