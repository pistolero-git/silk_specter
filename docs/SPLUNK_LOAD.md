# Splunk load reference

Use [`QUICKSTART.md`](QUICKSTART.md) for the normal sequence.

## Main loader

```bash
./scripts/load_to_splunk.sh easy asteron_easy_v001
ALLOW_AUTHORING=1 ./scripts/load_to_splunk.sh medium asteron_medium_v001
ALLOW_AUTHORING=1 ./scripts/load_to_splunk.sh hard asteron_hard_v001
```

`load_to_splunk.sh`:

1. verifies the track/build exists;
2. installs/updates `splunk/app/TA-asteron-v3` in the rootless Podman Splunk container;
3. restarts Splunk and verifies `INDEXED_EXTRACTIONS=HEC`;
4. requests interactive Splunk CLI login;
5. refuses to reuse an existing index;
6. creates the fresh index;
7. copies the dataset and loads `hec/events.jsonl`.

Override the container name with `SPLUNK_CONTAINER=<name>` if needed.

## Notable loader

```bash
./scripts/load_notables.sh medium asteron_medium_v001 notable
```

The second argument is the main track index and is substituted into the notable drilldown searches. Splunk ES normally provides `index=notable`.

Without ES:

```bash
CREATE_NOTABLE_INDEX=1 \
./scripts/load_notables.sh medium asteron_medium_v001 asteron_notable
```

## Verification

```spl
| tstats count where index=asteron_medium_v001
```

```spl
| tstats count where index=asteron_medium_v001 by sourcetype
| sort - count
```

```spl
index=notable host=SILK-SPECTER-ES sourcetype=stash scenario=medium
| stats count by rule_name urgency
```

Compare indexed counts with the generated `manifest.json`/`expected_counts.csv`. Parser contracts are documented in [`TA_COMPATIBILITY.md`](TA_COMPATIBILITY.md).
