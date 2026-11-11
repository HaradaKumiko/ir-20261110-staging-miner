# Incident evidence: staging server, /tmp/.xvd

## Summary

Crypto miner payload set found on the Comtelindo staging host, running out of a hidden directory.
Evidence was captured before any remediation so the live state (PID files, state, logs) stays intact.

- Host: `staging` (`103.80.241.147`)
- Path: `/tmp/.xvd`
- Owner: `genieacs`
- Captured: 2026-11-11 05:21 (UTC+8), pulled over SSH as `assistant` with `sudo`
- Capture method: `sudo tar czf - -C /tmp .xvd` streamed to the analysis host, then repacked as zip
- Chain of custody: files were only read, nothing was stopped, deleted or modified on the host
- Zip archive: `evidence/xvd-staging-20261111-0521.zip`
- Zip sha256: `d1c87b3202bed85079cf238e5b8f5c697a9621dbbad623ebd5d52a4c3e85a5bc`

## Contents

| File | Bytes | mtime | sha256 |
| --- | --- | --- | --- |
| `.wd_ts` | 13 | 2026-11-11 05:09 UTC | `6886887a0f587bbce8fb4f90551f04dd81e67d3f97a4c8d0f39d5be900a393eb` |
| `agent.js` | 27,917 | 2026-11-09 21:19 UTC | `76ba48667f433a4c994cafdfaf1542540c28e2164329a04c0d21aaff7697c9dc` |
| `agent.log` | 1,335,053 | 2026-11-11 05:20 UTC | `ad0371f597eb583720f97a11e096c44b69b124808e3f31d9b7545bc676abc391` |
| `agent.log.1` | 2,000,022 | 2026-11-10 19:17 UTC | `b9020316c0cfed193677042ca9737b386a30ad3b16ee19fbb84d476700007e11` |
| `config.json` | 1,386 | 2026-11-09 21:19 UTC | `077a5b3900978af18fa6878ebc48942f427a8ca353aed99ade0da1c846f12469` |
| `hostid` | 19 | 2026-11-09 21:19 UTC | `2fd996ffd255ccd42b82bcda99e8e623140763d985148b9443f23b9c11d0e719` |
| `install.log` | 37 | 2026-11-09 21:19 UTC | `7795bef531c00d0ad0931b02bd58194029e082eb99cb3a6b1dfabf3c7bc98e89` |
| `installer.sh` | 24,190 | 2026-11-11 05:09 UTC | `86c7d1138535012b4305fdc1d30ccf17a424be61f2d225851100920162004e90` |
| `miner.log` | 1,483,576 | 2026-11-11 05:21 UTC | `f6a2a2fbbebfd2a941858072e47bf3a1a9e0d336e31882d1a7a6885c4d410cb7` |
| `miner.pid` | 6 | 2026-11-09 21:19 UTC | `250776c57163b6244a55f2eba9ec63aacdf5c0904f575ec51dcad2ec4de2b1cc` |
| `seen.json` | 51 | 2026-11-09 13:39 UTC | `d40661256c5d7ac9a9eef6b077431c2cef7a3cd2599b876f0073536082338c7c` |
| `state.json` | 48 | 2026-11-09 21:19 UTC | `eed844ea4b76dfbb289c62c9743917f2e7a440a34b0e2e300db2bcb9cf2199f3` |
| `watch.sh` | 364 | 2026-11-11 05:09 UTC | `7fffc756b3f74d64956cfc57aa06bbe79e5fe8a05cc973323f50c3174ef3ea02` |
| `xmrig` | 8,350,992 | 2026-11-09 13:39 UTC | `b20f39fc00d242e706b6c30367ad811c676e0575050a4ec2f30104b696944b49` |

## Initial observations

- `xmrig` (8.3 MB) plus `config.json` and `miner.pid` indicate an active Monero miner process.
- `agent.js`, `installer.sh`, `watch.sh` and `.wd_ts` look like a dropper plus a watchdog loop.
- `miner.log` and `agent.log` were still growing at capture time, so the process was alive when the snapshot was taken.
- `hostid`, `state.json` and `seen.json` are small state files consistent with a beaconing or inventory agent.

## Handling

This repository is private and the payload is kept for analysis only. Do not execute `xmrig`,
`agent.js`, `installer.sh` or `watch.sh` on any host. Treat `config.json` and the logs as
potentially containing wallet addresses and host identifiers.

## Status

Remediation not started at capture time. Persistence (cron, systemd unit, shell profile) has not
been checked yet.
