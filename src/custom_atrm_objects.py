"""The classes found here are how ATRM objects can be represented as custom STIX objects instead of python dictionaries."""
from collections import OrderedDict

from constants import GET_ATRM_SOURCE, Mode
from stix2 import CustomObject, KillChainPhase
from stix2.properties import (
    BooleanProperty,
    IDProperty,
    ListProperty,
    ReferenceProperty,
    StringProperty,
    TimestampProperty,
    TypeProperty,
)
from stix2.v21.base import _STIXBase21


class CustomStixObject(object):
    """Custom STIX object used for ATRM objects."""

    def get_version(self) -> str:
        """Get the version of the object.

        Returns
        -------
        str
            the object version
        """
        return self.x_mitre_version


@CustomObject(
    "mitre-attack-pattern",
    [
        ("id", IDProperty("attack-pattern", spec_version="2.1")),
        ("type", TypeProperty("attack-pattern", spec_version="2.1")),
        ("name", StringProperty(required=True)),
        ("description", StringProperty()),
        (
            "x_mitre_modified_by_ref",
            ReferenceProperty(valid_types="identity", spec_version="2.1"),
        ),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_brief", StringProperty()),
        ("kill_chain_phases", ListProperty(KillChainPhase)),
        ("x_mitre_domains", ListProperty(StringProperty())),
        ("x_mitre_contributors", ListProperty(StringProperty())),
        ("x_mitre_attack_spec_version", StringProperty()),
        ("x_mitre_is_subtechnique", BooleanProperty()),
        ("x_mitre_platforms", ListProperty(StringProperty())),
        ("x_mitre_collection_layers", ListProperty(StringProperty())),
        ("x_atrm_resources", ListProperty(StringProperty())),
        ("x_atrm_actions", ListProperty(StringProperty())),
        ("x_atrm_detections", ListProperty(StringProperty())),
        ("x_atrm_examples", ListProperty(StringProperty())),
    ],
)
class Technique(CustomStixObject, object):
    def get_id(self, mode: Mode):
        external_references = self.get("external_references")
        if external_references:
            for reference in external_references:
                if (
                    reference.get("external_id")
                    and reference.get("source_name") == GET_ATRM_SOURCE(mode=mode)
                ):
                    return reference["external_id"]
        return None


@CustomObject(
    "mitre-relationship",
    [
        ("id", IDProperty("relationship", spec_version="2.1")),
        ("type", TypeProperty("relationship", spec_version="2.1")),
        (
            "x_mitre_modified_by_ref",
            ReferenceProperty(valid_types="identity", spec_version="2.1"),
        ),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_domains", ListProperty(StringProperty())),
        ("x_mitre_attack_spec_version", StringProperty()),
        ("relationship_type", StringProperty(required=True)),
        (
            "source_ref",
            ReferenceProperty(
                invalid_types=[
                    "bundle",
                    "language-content",
                    "marking-definition",
                    "relationship",
                    "sighting",
                ],
                spec_version="2.1",
                required=True,
            ),
        ),
        (
            "target_ref",
            ReferenceProperty(
                invalid_types=[
                    "bundle",
                    "language-content",
                    "marking-definition",
                    "relationship",
                    "sighting",
                ],
                spec_version="2.1",
                required=True,
            ),
        ),
    ],
)
class Relationship(CustomStixObject, object):
    pass


class ObjectRef(_STIXBase21):
    _properties = OrderedDict(
        [
            ("object_ref", StringProperty(required=True)),
            (
                "object_modified",
                TimestampProperty(
                    precision="millisecond", precision_constraint="min", required=True
                ),
            ),
        ]
    )


@CustomObject(
    "x-mitre-collection",
    [
        ("name", StringProperty()),
        ("description", StringProperty()),
        ("x_mitre_version", StringProperty()),
        ("x_mitre_attack_spec_version", StringProperty()),
        ("x_mitre_contents", ListProperty(ObjectRef)),
    ],
)
class Collection(CustomStixObject, object):
    pass
