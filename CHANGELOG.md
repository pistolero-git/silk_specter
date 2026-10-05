# Changelog

## Unreleased

### Finding entity and truth alignment

- Aligned synthetic findings with the direct Enterprise Security finding shape represented by the supplied `notables.csv` sample.
- Set `entity=risk_object` and `entity_type=risk_object_type` for every finding while retaining `risk_score` as the direct finding score.
- Added direct-finding metadata such as `detection_type=ebd`, `count=1`, `orig_action_name=notable`, `orig_investigation_type=default`, `risk_message`, and `contributing_events_search`.
- Enforced that every notable is backed by exactly one event that is actually present in `dataset/<track>/hec/events.jsonl`.
- Enforced `True Positive` -> authored `truth_label=malicious`.
- Enforced `Benign Positive` -> authored `truth_label=benign` or generated non-malicious background event.
- Removed the former `questionable` disposition from synthetic notable noise; generated noise findings are `Benign Positive`.
- Kept truth/disposition labels instructor-only so participant notable data does not reveal the answer.

### ES finding/notable fidelity

- Changed synthetic findings to the native comma-delimited `stash`/modaction record shape used by Splunk ES instead of simplified space-delimited key/value text.
- Added realistic finding metadata including descriptions, entities/entity types, risk/finding scores, source counts, stable detection/source IDs, annotations, status fields, and drilldowns.
- Enriched instructor notable ground truth with entity, score, severity, domain, and source-count context without exposing instructor disposition to participants.
- Added runtime-facing notable schema tests and Quick Start parsing/cleanup validation.


### Medium/Hard static normalization

- Expanded Medium static evidence from 65 to 1,250 events while preserving the original answer-bearing spine.
- Expanded Hard static evidence from 75 to 1,500 events while preserving the original answer-bearing spine.
- Medium now contains 650 malicious/corroborating events and 600 fixed benign lookalikes; Hard contains 450 malicious/corroborating events and 1,050 fixed benign/admin lookalikes.
- Broadened Hard to 31 static sourcetypes so difficulty comes from heterogeneous evidence and authorization context rather than missing telemetry.
- Added Medium/Hard instructor scenario, evidence-matrix, and tactic-summary ground truth.
- Re-authored Hard hints and reference pivots for the normalized decoy-rich corpus without changing canonical answers.
- Updated Medium ATT&CK/notable-triage questions and hints so participant-facing content uses ingested raw/notable evidence instead of instructor-only files.


### Canonical-source cleanup

- Made `question_bank/<track>/` the single committed question/answer/hint source and merged instructor metadata/answer types into those files.
- Removed duplicate instructor/participant question exports, duplicate static-event ground-truth CSVs, legacy generated ground-truth copies, the historical release snapshot, and the duplicate participant topology SVG.
- Changed notable generation to use `scenario_data/<track>/attack_events.jsonl` directly.
- Updated tests and documentation to the canonical layout and added loader workflow checks for all tracks.


### Track/data consistency

- Standardized all tracks on committed static answer-bearing campaign files under `scenario_data/<track>/attack_events.jsonl`.
- Added the validated Easy campaign as static evidence without changing the committed Easy participant dataset.
- Added ingest-ready `raw/` and `hec/` baseline datasets for Medium and Hard under `dataset/<track>/`.
- Standardized generated layout, manifests, expected counts, and scenario-scoped ground truth across Easy/Medium/Hard.

### Questions and difficulty tracks

- Easy question bank: 180 questions / 360 hints.
- Medium question bank: 170 questions / 510 hints with static multi-region campaign evidence.
- Hard question bank: 150 questions / 450 hints with global/OT-adjacent static campaign evidence.
- Preserved subject grouping and explicit answer-format guidance for multi-value answers.

### Notables

- Reworked all Easy/Medium/Hard synthetic notables as direct **non-RBA** notable events.
- Every notable is backed by exactly one event already present in the generated participant dataset.
- Retained direct-finding `risk_object`, `risk_object_type`, and `risk_score` so the ES finding entity is represented correctly, while omitting RBA aggregation/threshold fields (`risk_event_count`, `all_risk_objects`, `normalized_risk_object`, `risk_threshold`, `risk_object_system`).
- Campaign notables use one authored APT event; Benign Positive alert noise uses one deterministic generated non-malicious background event.
- `source_count=1` for every notable and drilldowns point to the single backing source event.
- Added deterministic synthetic ES-style notable feeds under `dataset/<track>/notables/`.
- Added expected campaign findings plus Benign Positive notable noise.
- Noise scales with difficulty: Easy 25, Medium 60, Hard 120 noise events.
- Added `scripts/load_notables.sh` with track-index drilldown substitution.
- Added instructor-only notable ground truth without leaking disposition into participant events.

### Repository cleanup

- Consolidated release history into this file.
- Added `docs/QUICKSTART.md` for a short generate/index/ingest/notable workflow.
- Simplified the root README and generation documentation.
- Added Make targets for all three tracks.

## v0.3.0 — repository/reproducibility baseline

- Added `AGENTS.md`, Git-ready project files, scenario registry, UTC scenario windows, reusable network-flow helpers, and repository-readiness tests.
- Added Easy/Medium/Hard scenario configuration and question-bank architecture.
- Added network-layout, TA-compatibility, Splunk-load, scenario-authoring, and question-bank documentation.
- Preserved the validated v0.2.3 Easy corpus and TA/data contracts.

## v0.2.3 — generator/data compatibility corrections

- Standardized Windows Security and Sysmon on `sourcetype=XmlWinEventLog` with channel-specific `source` values.
- Added/retained Security 4624, 4625, 4688, 4769 and account/group change events.
- Preserved Sysmon IDs 1, 3, 11, and 22 with event-appropriate fields.
- Added Junos authentication failures, TACACS PASS/FAIL diversity, WSUS status diversity, and Defender AlertInfo/AlertEvidence Event Hub records.
- Corrected X.509 fingerprint formatting and constrained WSUS examples to the campaign date window.

## v0.2.2 — TA compatibility corrections

- Corrected Cisco ASA connection IDs, Cisco IOS auth/config events, AWS CloudTrail service schemas, Defender Event Hub layout, FortiGate sourcetype, Ivanti update telemetry, Junos sourcetypes, Linux audit coverage, PAN-OS traffic shape, Windows source metadata, and Tenable schema.
### Finding field requirement update

- Added `risk_score` to every synthetic finding/notable, set equal to the direct finding score.
- Retained required `entity` and `entity_type` on every finding.
- This remains a non-RBA, one-source-event-per-notable model. `risk_object`/`risk_object_type` are direct finding-entity fields; no `risk_event_count`, threshold aggregation, or intermediate findings are emitted.

