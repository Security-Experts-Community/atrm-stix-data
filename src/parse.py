import os
from datetime import datetime
from pathlib import Path

from constants import (
    ATRM_PATH,
    ATRM_TACTICS_MAP,
    ATRM_VERSION,
    ATTACK_SPEC_VERSION,
    CREATOR_IDENTITY,
    DEFAULT_CREATOR_JSON,
    get_atrm_domain,
    get_atrm_source,
    get_collection_id,
    Mode,
)
from custom_atrm_objects import Collection, ObjectRef, Relationship
from git_tools import get_last_commit_hash
from mitreattack.stix20.custom_attack_objects import Matrix
from parse_tactic import parse_tactic
from parse_technique import get_techniques_brief_info, parse_technique
from stix2 import Bundle, parse


def parse_atrm(mode: Mode):
    tactics = {}
    techniques = {}
    relations = []
    relationships = []

    for tactic_name in ATRM_TACTICS_MAP:
        path = ATRM_PATH / "docs" / tactic_name
        tactic_file = path / [f for f in os.listdir(path) if f.endswith(".md")][0]
        tactic = parse_tactic(tactic_file, tactic_name, mode)
        tactics[tactic_name] = tactic
        techniques_brief = get_techniques_brief_info(
            file_path=path / tactic_file, tactic=tactic
        )
        tactic_short = tactic.get_shortname()
        tech_folders = [f for f in os.listdir(path) if not f.endswith(".md")]
        for tech_folder in tech_folders:
            tech_path = ATRM_PATH / "docs" / tactic_name / tech_folder
            tech_files = [f for f in os.listdir(tech_path) if f.endswith(".md")]
            for tech_file in tech_files:
                tech_file_path = os.path.join(tech_path, tech_file)
                technique, relation = parse_technique(
                    tech_file_path, tactic_name, techniques_brief, tactic_short, mode
                )
                techniques[technique.get_id(mode)] = technique
                if relation:
                    relations.append(relation)

    relationships = [
        Relationship(
            source_ref=techniques[relation["source"]]["id"],
            relationship_type=relation["relation"],
            target_ref=techniques[relation["target"]]["id"],
            created_by_ref=CREATOR_IDENTITY,
            x_mitre_version=ATRM_VERSION,
            x_mitre_modified_by_ref=CREATOR_IDENTITY,
            x_mitre_attack_spec_version="2.1.0",
            x_mitre_domains=[get_atrm_domain(mode=mode)],
        )
        for relation in relations
    ]

    objects = []
    objects.extend([tactics[t] for t in tactics])
    objects.extend([techniques[t] for t in techniques])
    objects.extend(relationships)

    matrix = Matrix(
        tactic_refs=[tactics[t].id for t in tactics],
        created=datetime.now(),
        modified=datetime.now(),
        created_by_ref=CREATOR_IDENTITY,
        external_references=[
            {
                "external_id": "atrm",
                "source_name": get_atrm_source(mode=mode),
                "url": "https://microsoft.github.io/Azure-Threat-Research-Matrix/",
            }
        ],
        name="Azure Threat Research Matrix",
        description="The purpose of the Azure Threat Research Matrix (ATRM) is to educate readers on the potential of Azure-based tactics, techniques, and procedures (TTPs). It is not to teach how to weaponize or specifically abuse them. For this reason, some specific commands will be obfuscated or parts will be omitted to prevent abuse.",
        x_mitre_version=ATRM_VERSION,
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
        x_mitre_modified_by_ref=CREATOR_IDENTITY,
        spec_version="2.1",
        x_mitre_domains=[get_atrm_domain(mode=mode)],
        allow_custom=True,
    )
    objects.append(matrix)

    identity = parse(data=DEFAULT_CREATOR_JSON, allow_custom=True)
    objects.append(identity)

    collection = Collection(
        id=get_collection_id(mode=mode),
        spec_version="2.1",
        name="Azure Threat Research Matrix",
        description="The purpose of the Azure Threat Research Matrix (ATRM) is to educate readers on the potential of Azure-based tactics, techniques, and procedures (TTPs). It is not to teach how to weaponize or specifically abuse them. For this reason, some specific commands will be obfuscated or parts will be omitted to prevent abuse.",
        x_mitre_attack_spec_version=ATTACK_SPEC_VERSION,
        x_mitre_version=ATRM_VERSION,
        created_by_ref=CREATOR_IDENTITY,
        x_mitre_contents=[
            ObjectRef(object_ref=obj.id, object_modified=obj.modified)
            for obj in objects
        ],
    )

    bundle = Bundle(collection, objects, allow_custom=True)
    commit_hash = get_last_commit_hash(ATRM_PATH)
    output_file_last = Path(__file__).parent.parent / "build" / f"atrm_{mode.name.lower()}.json"
    with open(output_file_last, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))

    output_file_versioned = (
        Path(__file__).parent.parent / "build" / f"atrm_{mode.name.lower()}_{commit_hash}.json"
    )
    with open(output_file_versioned, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))


if __name__ == "__main__":
    for mode in Mode:
        parse_atrm(mode)
