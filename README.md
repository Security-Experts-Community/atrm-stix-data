# Azure Threat Research Matrix STIX Data
[![Telegram chat](https://img.shields.io/static/v1?label=chat&message=Telegram&color=blue&logo=telegram)](https://t.me/s3curity_experts_community/3744)

The purpose of the [Azure Threat Research Matrix (ATRM)](https://microsoft.github.io/Azure-Threat-Research-Matrix/) is to educate readers on the potential of Azure-based tactics, techniques, and procedures (TTPs). It is not to teach how to weaponize or specifically abuse them. For this reason, some specific commands will be obfuscated or parts will be omitted to prevent abuse.

This repository contains the ATRM dataset represented in STIX 2.1 JSON collections.

## Repository Structure

```
.
├─ build ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Collection folder
│   ├─ atrm_strict.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Most recent strict ATRM release
│   ├─ atrm_attack_compatible.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Most recent ATT&CK compatible ATRM release
│   ├─ atrm_strict_9f05fef.json ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ ATRM strict collection for commit hash 9f05fef of site repo
│   ├─ atrm_attack_compatible_9f05fef.json ∙∙∙∙∙∙ ATRM ATT&CK compatible collection for commit hash 9f05fef of site repo
│   └─ [other commits of ATRM]
├─ make.sh ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Build script for *nix and MacOS
└─ make.bat ∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙∙ Build script for Windows
```

## Supporting Documentation

### [STIX](https://oasis-open.github.io/cti-documentation/)

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

## ATT&CK compatibility

[ATT&CK compatible](https://raw.githubusercontent.com/Security-Experts-Community/atrm-stix-data/main/build/atrm_attack_compatible.json) version can be loaded into ATT&CK Workbench.

![Pasted image 20240301143233](https://github.com/Security-Experts-Community/atrm-stix-data/assets/61383585/eab57654-d75b-4e50-81f1-ab6b8e58e684)

It uses domain `enterprise-attack` to comply internal contract of ATT&CK Workbench.

![Pasted image 20240301143318](https://github.com/Security-Experts-Community/atrm-stix-data/assets/61383585/c871237c-d2b0-41d0-953c-644935376483)

You can also use the [mitreattack-python](https://mitreattack-python.readthedocs.io/en/latest/) library to process the STIX bundle(see [example.ipynb](https://github.com/Security-Experts-Community/atrm-stix-data/blob/main/src/example.ipynb)).
