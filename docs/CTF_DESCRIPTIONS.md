# Easy
## Short description
```text
Investigate a high signal intrusion against Asteron Utilities Group and trace an adversary through Windows, Linux, network, and 
cloud telemetry.
```

## Full description
```text
SILK SPECTER Easy is an introductory investigation track inspired by Volt Typhoon tradecraft. Analysts investigate a focused intrusion against Asteron Utilities Group using realistic Splunk data from Windows, Linux, network security, authentication, and AWS sources. The track is designed to teach the investigation workflow without hiding important evidence behind excessive noise. Malicious activity is comparatively visible, supporting events are easier to correlate, and the attack path is more direct. Participants will identify suspicious infrastructure, reconstruct attacker activity, follow movement through the environment, and determine what systems, accounts, and data were affected. The goal is to understand how multiple telemetry sources combine into a coherent incident narrative.
```
# Medium
## Short description
```text
Investigate a multi stage intrusion where malicious activity is mixed with legitimate administrative behavior and requires cross source correlation.
```
## Full description
```text
SILK SPECTER Medium increases the investigation challenge by placing adversary activity inside a larger and noisier Asteron Utilities Group environment. Inspired by Volt Typhoon techniques, this track requires analysts to distinguish malicious behavior from legitimate administration, infrastructure activity, and benign lookalikes. The intrusion spans multiple systems and telemetry sources, with evidence distributed across endpoint, authentication, network, firewall, cloud, and infrastructure logs. Indicators are less obvious than in the Easy track, and several questions require analysts to correlate activity across hosts, users, services, and time rather than relying on a single event. Participants will reconstruct the attack chain, identify compromised systems and identities, distinguish true positives from benign positives, and determine how the adversary moved through the environment and prepared data for collection or exfiltration.
```
# Hard
## Short description
```text
Hunt a stealthy adversary across a noisy enterprise environment where attacker behavior closely resembles normal administrative activity.
```
## Full description
```text
SILK SPECTER Hard is the most demanding investigation track and is designed to simulate the ambiguity of a real enterprise intrusion. The adversary blends into normal Asteron Utilities Group operations by using legitimate tools, trusted infrastructure, valid credentials, and activity patterns that resemble routine administration. Evidence is distributed across endpoint, network, identity, firewall, cloud, and infrastructure telemetry. Malicious events are surrounded by substantial benign activity and realistic lookalikes, requiring analysts to establish relationships between systems, identities, infrastructure, and timelines before conclusions become clear. This track emphasizes threat hunting, hypothesis driven investigation, timeline reconstruction, and evidence correlation. Participants must determine which activity is truly malicious, identify the adversary path through the environment, uncover staging and exfiltration behavior, and build a defensible picture of the intrusion from fragmented evidence.
```