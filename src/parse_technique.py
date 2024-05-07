import re
from pathlib import Path

import html_to_json
from constants import (
    ATRM_PATH,
    ATRM_PLATFORM,
    GET_ATRM_DOMAIN,
    GET_ATRM_SOURCE,
    GET_KILL_CHAIN_NAME,
    Mode,
    CREATOR_IDENTITY,
)
from custom_atrm_objects import Technique
from git_tools import get_file_creation_date, get_file_modification_date
from marko.ext.gfm import gfm
from mitreattack.stix20.custom_attack_objects import Tactic


def techniques_table(page_as_json):
    return page_as_json["table"][0]["tbody"][0]["tr"]


def is_technique(row) -> bool:
    return bool(row["td"][0])


def get_technique_id(row) -> str:
    return row["td"][0]["a"][0]["_value"]


def get_subtechnique_id(row) -> str:
    return row["td"][1]["a"][0]["_value"]


def get_technique_name(row) -> str:
    return row["td"][2]["_value"]


def get_technique_brief(row) -> str:
    desc_td = row["td"][3]
    return "" if not desc_td else desc_td["_value"]


def get_techniques_brief_info(file_path: str, tactic: Tactic) -> dict:
    techniques = {}
    with open(file_path, "r", encoding="utf-8") as f:
        html_content = gfm(f.read())
        json_content = html_to_json.convert(html_content)

        parent_tech_id = ""
        for row in techniques_table(json_content):
            if is_technique(row):
                parent_tech_id = current_id = get_technique_id(row)
            else:
                subtechnique_id = get_subtechnique_id(row)
                if parent_tech_id in subtechnique_id:
                    current_id = subtechnique_id
                else:
                    current_id = parent_tech_id + subtechnique_id

            tech_name = get_technique_name(row)
            tech_desc = get_technique_brief(row)

            technique = {
                "id": current_id,
                "parent_id": parent_tech_id,
                "url": f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactic.name}/{parent_tech_id}/{current_id.replace('.00','-')}",
                "name": tech_name,
                "brief": tech_desc,
                "phase_name": tactic.get_shortname(),
                "is_subtechnique": parent_tech_id != current_id,
            }

            techniques[current_id] = technique

        return techniques


def handle_description_markup(description_row: dict) -> str:
    mdescription = ""
    if "code" in description_row:
        codes = [c["_value"] for c in description_row["code"]]
        mdescription = description_row["_values"][0]
        for i, code in enumerate(codes):
            mdescription += " " + code + description_row["_values"][i + 1]
    else:
        mdescription = description_row["_value"]
    return mdescription


def strip_star(value: str) -> str:
    return value[1:] if value.startswith("*") else value


def get_tech_elements(
    json_content: dict, index: int, split: bool = False
) -> str | list:
    values = ""
    if len(json_content["pre"]) >= index + 1:
        values = json_content["pre"][index]["code"][0]["_value"]
        if split:
            return [
                strip_star(v).strip()
                for v in values.split("\n")
                if strip_star(v).strip().lower() != "n/a"
            ]
    if values.lower() == "n/a":
        return None
    return values


def get_merged_values(json_content: dict, index: int) -> str | list:
    values = json_content["p"][index]["_value"]
    return [strip_star(v).strip() for v in values.split("\n")[1:]]


def get_technique_description(json_content) -> str:
    description = ""
    if "_values" in json_content["p"][0]:
        description = " ".join(json_content["p"][0]["_values"])
    else:
        description = json_content["p"][0]["_value"]
    return description


def fix_id(atrm_id: str) -> str:
    if "." in atrm_id:
        tpart = atrm_id.split(".")[0]
        spart = atrm_id.split(".")[1].replace("0", "")
        atrm_id = f"{tpart}.00{spart}"
    return atrm_id


def parse_technique(
    file_path: str, tactic_name: str, techniques_brief_info: dict, tactic_short: str, mode: Mode
) -> tuple[Technique, dict] :
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
        html_content = gfm(content)
        json_content = html_to_json.convert(html_content)
        modified_datetime = get_file_modification_date(
            repo_path=ATRM_PATH, file_path=file_path
        )
        creation_datetime = get_file_creation_date(
            repo_path=ATRM_PATH, file_path=file_path
        )

        header_parts = json_content["h1"][0]["_value"].split(" - ")
        atrm_id = header_parts[0]
        # technique_name = header_parts[1].split(":")[0].strip()
        subtechnique_name = header_parts[1].split(":")[-1].strip()

        description = get_technique_description(json_content)
        relation = None
        atrm_id = fix_id(atrm_id)

        if atrm_id in techniques_brief_info:
            technique_info = techniques_brief_info[atrm_id]
        else:
            technique_info = {
                "id": atrm_id,
                "parent_id": atrm_id.split(".")[0],
                "name": subtechnique_name,
                "brief": description,
            }

        technique_id = technique_info["id"]
        parent_id = technique_info["parent_id"]

        if "." in atrm_id or "table" not in json_content:
            if "ul" in json_content:
                bullits = json_content["ul"][0]["li"]
                description += "\n- " + "\n- ".join(
                    [
                        b["p"][0]["strong"][0]["_value"] + b["p"][0]["_value"]
                        for b in bullits
                    ]
                )
                resources = get_merged_values(json_content, 1)
                actions = get_merged_values(json_content, 2)
                examples = get_tech_elements(json_content, 0)
                detections = get_tech_elements(json_content, 1)
                additional_reqources = get_tech_elements(json_content, 2, split=True)
                links = []
                for r in additional_reqources:
                    if r:
                        if match := re.match(r"\[.*\]\((.*)\)", r):
                            links.append(match.group(1))
                        elif match := re.match(r"^(https?:.*)", r):
                            links.append(match.group(1))

                external_references = [
                    {
                        "source_name": GET_ATRM_SOURCE(mode=mode),
                        "external_id": technique_id,
                        "url": f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactic_name}/{atrm_id.split('.')[0]}/{Path(file_path).stem}",
                    },
                ]
                external_references.extend(
                    [
                        {
                            "source_name": "microsoft",
                            "url": link,
                        }
                        for link in links
                    ]
                )

                desc = description
                if "!!!" in desc:
                    desc = technique_info['brief']

                technique = Technique(
                    x_mitre_platforms=[ATRM_PLATFORM],
                    x_mitre_domains=[GET_ATRM_DOMAIN(mode=mode)],
                    created=creation_datetime,
                    modified=modified_datetime,
                    created_by_ref=CREATOR_IDENTITY,
                    external_references=external_references,
                    name=technique_info["name"],
                    description=desc,
                    x_mitre_brief=technique_info["brief"],
                    kill_chain_phases=[
                        {
                            "kill_chain_name": GET_ATRM_SOURCE(mode=mode),
                            "phase_name": tactic_short,
                        }
                    ],
                    x_mitre_is_subtechnique=parent_id != technique_id,
                    x_mitre_version="1.0",
                    x_mitre_modified_by_ref=CREATOR_IDENTITY,
                    x_mitre_attack_spec_version="2.1.0",
                    x_atrm_resources=resources,
                    x_atrm_actions=actions,
                    x_atrm_examples=examples,
                    x_atrm_detections=detections,
                )
            else:
                resources = get_tech_elements(json_content, 0, split=True)
                actions = get_tech_elements(json_content, 1, split=True)
                examples = get_tech_elements(json_content, 2)
                detections = get_tech_elements(json_content, 3)
                additional_reqources = get_tech_elements(json_content, 4, split=True)
                links = []
                for r in additional_reqources:
                    if r:
                        if match := re.match(r"\[.*\]\((.*)\)", r):
                            links.append(match.group(1))
                        elif match := re.match(r"^(https?:.*)", r):
                            links.append(match.group(1))

                external_references = [
                    {
                        "source_name": GET_ATRM_SOURCE(mode=mode),
                        "external_id": technique_id,
                        "url": f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactic_name}/{atrm_id.split('.')[0]}/{Path(file_path).stem}",
                    },
                ]
                external_references.extend(
                    [
                        {
                            "source_name": "microsoft",
                            "url": link,
                        }
                        for link in links
                    ]
                )
                desc = description
                if "!!!" in desc:
                    desc = technique_info['brief']

                technique = Technique(
                    x_mitre_platforms=[ATRM_PLATFORM],
                    x_mitre_domains=[GET_ATRM_DOMAIN(mode=mode)],
                    created_by_ref=CREATOR_IDENTITY,
                    created=creation_datetime,
                    modified=modified_datetime,
                    external_references=external_references,
                    name=technique_info["name"],
                    description=desc,
                    x_mitre_brief=technique_info["brief"],
                    kill_chain_phases=[
                        {
                            "kill_chain_name": GET_KILL_CHAIN_NAME(mode=mode),
                            "phase_name": tactic_short,
                        }
                    ],
                    x_mitre_is_subtechnique=parent_id != technique_id,
                    x_mitre_version="1.0",
                    x_mitre_modified_by_ref=CREATOR_IDENTITY,
                    x_mitre_attack_spec_version="2.1.0",
                    x_atrm_resources=resources,
                    x_atrm_actions=actions,
                    x_atrm_examples=examples,
                    x_atrm_detections=detections,
                )
            if parent_id != technique_id:
                relation = {
                    "source": technique_id,
                    "relation": "subtechnique-of",
                    "target": parent_id,
                }
        else:
            desc = description
            if "!!!" in desc:
                desc = technique_info['brief']
            technique = Technique(
                x_mitre_platforms=[ATRM_PLATFORM],
                x_mitre_domains=[GET_ATRM_DOMAIN(mode=mode)],
                created_by_ref=CREATOR_IDENTITY,
                created=creation_datetime,
                modified=modified_datetime,
                external_references=[
                    {
                        "source_name": GET_ATRM_SOURCE(mode=mode),
                        "external_id": technique_id,
                        "url": f"https://microsoft.github.io/Azure-Threat-Research-Matrix/{tactic_name}/{atrm_id.split('.')[0]}/{Path(file_path).stem}",
                    },
                ],
                name=technique_info["name"],
                description=desc,
                x_mitre_brief=technique_info["brief"],
                kill_chain_phases=[
                    {
                        "kill_chain_name": GET_KILL_CHAIN_NAME(mode=mode),
                        "phase_name": tactic_short,
                    }
                ],
                x_mitre_is_subtechnique=parent_id != technique_id,
                x_mitre_version="1.0",
                x_mitre_modified_by_ref=CREATOR_IDENTITY,
                x_mitre_attack_spec_version="2.1.0",
            )
        print(technique_id)
        return technique, relation
