# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0] galaxy and script version - 2023-01-03
### Added
- Relationship with MITRE ATT&CK galaxy (mitre-attack-pattern.json)[https://github.com/MISP/misp-galaxy/blob/main/clusters/mitre-attack-pattern.json].
- Config file to establish the MITRE ATT&CK galaxy. (config.ini)[https://github.com/jstnk9/MISP/tree/main/misp-galaxy/sigma/config.ini].

## Changed
- uuid predefined in the script code to maintain the same in [MISP](https://github.com/MISP/misp-galaxy/blob/main/clusters/sigma-rules.json) galaxy. By [adulau](https://github.com/adulau)

## [1.0] galaxy and script version - 2022-11-18
### Added
- First version to generate sigma rules galaxy.