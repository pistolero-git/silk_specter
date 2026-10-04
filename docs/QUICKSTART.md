# Quick start: generate, add synthetic noise, and load a track

This is the shortest path from the repository to a playable Splunk dataset.

SILK SPECTER has three different data layers:

1. **Static campaign evidence** — fixed answer-bearing APT activity from `scenario_data/<track>/attack_events.jsonl`.
2. **Synthetic background/noise telemetry** — generated normal Asteron activity around the fixed campaign.
3. **Synthetic notable noise** — generated benign/questionable ES-style findings mixed with the authored campaign findings.

Regenerating noise does **not** change the static answer-bearing campaign evidence or the canonical question answers.

## 1. Pick a track

Use one of:

```text
easy
medium
hard
```

Current status:

| Track | Status | Intended difficulty |
|---|---|---|
| Easy | validated | clearer pivots, less noise |
| Medium | authoring | more background overlap and notable noise |
| Hard | authoring | highest benign/admin overlap and sparse useful findings |

Medium and Hard still require `ALLOW_AUTHORING=1` when loading until target-Splunk validation is complete.


### Complete track commands

Keep these track-specific commands together so the Quick Start shows how to add **all three** datasets to Splunk.

Easy:

```bash
make generate-easy
./scripts/load_to_splunk.sh easy asteron_easy_v001
./scripts/load_notables.sh easy asteron_easy_v001 notable
```

Medium:

```bash
make generate-medium

ALLOW_AUTHORING=1 \
./scripts/load_to_splunk.sh medium asteron_medium_v001

./scripts/load_notables.sh medium asteron_medium_v001 notable
```

Hard:

```bash
make generate-hard

ALLOW_AUTHORING=1 \
./scripts/load_to_splunk.sh hard asteron_hard_v001

./scripts/load_notables.sh hard asteron_hard_v001 notable
```

The three main datasets are separate and should use separate indexes:

```text
easy   -> asteron_easy_v001
medium -> asteron_medium_v001
hard   -> asteron_hard_v001
```

The notable feeds can all go to the ES `notable` index because each event retains its track/scenario metadata.

## 2. Generate the dataset and synthetic noise

Generation rebuilds `dataset/<track>/` from scratch. It does **not** append new noise to the previous generated dataset.

Generate the default corpus for the track you are working with:

```bash
make generate-easy
make generate-medium
make generate-hard
```

Run only the target(s) you intend to regenerate. Each track writes to its own `dataset/<track>/` directory.

Each generation run includes:

```text
fixed static campaign evidence
+ synthetic basic/background telemetry
+ synthetic enterprise background telemetry
+ other generated background such as Defender activity
+ synthetic campaign notables
+ synthetic benign/questionable notable noise
```

The default raw-telemetry noise controls are:

| Track | `BACKGROUND_EVENTS` | `ENTERPRISE_BACKGROUND_EVENTS` | Notable noise |
|---|---:|---:|---:|
| Easy | 5,000 | 45,000 | 25 |
| Medium | 7,000 | 60,000 | 60 |
| Hard | 9,000 | 80,000 | 120 |

The two raw-telemetry values are **not** the final event count. Static campaign events and additional generated telemetry are added on top of them.

### Increase or decrease raw telemetry noise

Use `BACKGROUND_EVENTS` and `ENTERPRISE_BACKGROUND_EVENTS` when invoking the Make target.

Example — larger Easy corpus:

```bash
make generate-easy \
  BACKGROUND_EVENTS=25000 \
  ENTERPRISE_BACKGROUND_EVENTS=225000
```

Example — larger Medium corpus:

```bash
make generate-medium \
  BACKGROUND_EVENTS=20000 \
  ENTERPRISE_BACKGROUND_EVENTS=150000
```

Example — larger Hard corpus:

```bash
make generate-hard \
  BACKGROUND_EVENTS=30000 \
  ENTERPRISE_BACKGROUND_EVENTS=250000
```

These settings change only the generated background telemetry. They do not change the fixed attack facts used by the questions.

### Synthetic notable noise

The notable feed is generated automatically by the same `make generate-<track>` command. You do not need a second generation command.

Generated notable files are written under:

```text
dataset/<track>/notables/raw/notables.log
dataset/<track>/notables/hec/events.jsonl
dataset/<track>/notables/manifest.json
dataset/<track>/notables/expected_counts.csv
```

The notable-noise count comes from `notables.noise_events` in:

```text
config/scenarios/easy.json
config/scenarios/medium.json
config/scenarios/hard.json
```

If you intentionally change the notable-noise count, edit the scenario JSON and regenerate the track. The corresponding instructor disposition file is regenerated under:

```text
instructor/findings/<track>_notable_ground_truth.csv
```

## 3. Check the generated files

The main participant corpus is written to:

```text
dataset/<track>/raw/
dataset/<track>/hec/events.jsonl
dataset/<track>/manifest.json
dataset/<track>/expected_counts.csv
```

Validate the repository and generated corpus:

```bash
make validate
```

Check the main event count:

```bash
python3 -m json.tool dataset/easy/manifest.json
wc -l dataset/easy/hec/events.jsonl
```

Check the notable count:

```bash
python3 -m json.tool dataset/easy/notables/manifest.json
wc -l dataset/easy/notables/hec/events.jsonl
```

For another track, replace `easy` with `medium` or `hard`.

The HEC line count should match the `events` value in the corresponding manifest.

## 4. Load the main dataset into Splunk

The container-native loader:

- installs/updates `TA-asteron-v3` with `podman cp`;
- creates or reuses an empty track index through Splunk configuration;
- restarts the Splunk container;
- waits for container health;
- copies the prepared event stream into the live container after restart;
- lets Splunk consume it through a local batch input; and
- verifies that raw index bucket data exists before reporting success.

It does not require a host-published HEC or management port, and it does not require an interactive Splunk CLI login.

Easy:

```bash
./scripts/load_to_splunk.sh easy asteron_easy_v001
```

Medium:

```bash
ALLOW_AUTHORING=1 \
./scripts/load_to_splunk.sh medium asteron_medium_v001
```

Hard:

```bash
ALLOW_AUTHORING=1 \
./scripts/load_to_splunk.sh hard asteron_hard_v001
```

If the requested index already exists but is empty, the loader can reuse it. If it already contains indexed data, the loader refuses to add another corpus to it; use a fresh index name.

## 5. Load the synthetic notables

The main loader does **not** load the notable feed. Load it separately after the main track is present.

The notable loader is container-native, like the main loader. It checks indexes with
`btool`, installs a temporary `batch://` input through Splunk configuration, restarts
Splunk, then copies the notable stream into the live container. It does not depend on
interactive Splunk CLI authentication or host-published Splunk ports.

Splunk Enterprise Security normally already provides `index=notable`. If `index=notable`
is searchable in Splunk Web, the loader should detect it through `btool` and use it.

Easy:

```bash
./scripts/load_notables.sh easy asteron_easy_v001 notable
```

Medium:

```bash
./scripts/load_notables.sh medium asteron_medium_v001 notable
```

Hard:

```bash
./scripts/load_notables.sh hard asteron_hard_v001 notable
```

The notable loader replaces the `<index>` placeholder in each drilldown with the track index you supply.

If the lab does not have Splunk ES and therefore does not have `index=notable`, create/use a lab-only notable index:

```bash
CREATE_NOTABLE_INDEX=1 \
./scripts/load_notables.sh medium asteron_medium_v001 asteron_notable
```

Do not repeatedly load the same generated notable feed into the same notable index unless duplicate notables are intentional.

## 6. Verify in Splunk

### Main event count

Easy example:

```spl
| tstats count where index=asteron_easy_v001
```

### Sourcetype distribution

```spl
| tstats count where index=asteron_easy_v001 by sourcetype
| sort - count
```

### Notable distribution

```spl
index=notable source=notable sourcetype=stash scenario=easy
| stats count by rule_name urgency
| sort - count
```

### Current normalized baseline

| Track | Main events | Campaign notables | Noise notables | Total notables |
|---|---:|---:|---:|---:|
| Easy | 56,844 | 11 | 25 | 36 |
| Medium | 75,690 | 8 | 60 | 68 |
| Hard | 100,073 | 7 | 120 | 127 |

These values describe the current normalized default corpora. If you regenerate with different noise settings, use these files as the source of truth instead of the table:

```text
dataset/<track>/manifest.json
dataset/<track>/expected_counts.csv
dataset/<track>/notables/manifest.json
```

## 7. Regeneration rule

If you change raw telemetry noise or correct generated data:

```text
regenerate track
→ make validate
→ load main data into a fresh/empty track index
→ load the matching notable feed
→ verify manifest counts in Splunk
```

The static campaign remains fixed unless you intentionally modify `scenario_data/<track>/attack_events.jsonl`. If static answer-bearing evidence changes, revalidate the affected questions, answers, hints, detections, and instructor ground truth before using the track.

## 8. Validate ES finding/notable field parsing

SILK SPECTER notables use the native `stash`/modaction record shape used by Splunk ES: an epoch prefix followed by comma-separated `key="value"` fields. The feed includes finding title/description, entity, entity type, risk/finding score, severity, urgency, status, security domain, source counts, stable detection IDs, annotations, and drilldown searches.

After loading a track, verify that the fields are actually extracted:

```spl
index=notable host=SILK-SPECTER-ES source=notable sourcetype=stash scenario=easy
| table _time rule_name rule_description entity entity_type risk_score finding_score severity urgency status_label security_domain src dest user source_count drilldown_search
```

This health check should return **zero** events:

```spl
index=notable host=SILK-SPECTER-ES source=notable sourcetype=stash
| where isnull(rule_name) OR isnull(rule_description) OR isnull(entity) OR isnull(entity_type) OR isnull(risk_score) OR isnull(severity)
| stats count
```

### Rebuild only the notable feeds

If the main track data is already correct in Splunk, you do not need to regenerate the full corpus just to rebuild findings:

```bash
python3 generator/notables.py --scenario easy
python3 generator/notables.py --scenario medium
python3 generator/notables.py --scenario hard
```

### Remove an older malformed SILK SPECTER notable feed before reloading

Older SILK SPECTER builds used a simplified space-delimited record. Do not load the corrected feed on top of those events or the Analyst Queue can contain duplicates.

First confirm the scope:

```spl
index=notable host=SILK-SPECTER-ES source=notable sourcetype=stash
| rex field=_raw "scenario=\"(?<silk_scenario>[^\"]+)\""
| stats count by silk_scenario
```

If the results contain only the old SILK SPECTER events you intend to replace, an administrator with the `can_delete` capability can hide the old Easy events from search with:

```spl
index=notable host=SILK-SPECTER-ES source=notable sourcetype=stash
| rex field=_raw "scenario=\"(?<silk_scenario>[^\"]+)\""
| search silk_scenario=easy
| delete
```

Then reload the corrected feed:

```bash
./scripts/load_notables.sh easy asteron_easy_v001 notable
```

`delete` does not reclaim bucket disk space; it marks matching events as deleted from search results. Never run a broad delete against the shared ES `notable` index.
