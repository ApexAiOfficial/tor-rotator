# Operations Guide

## Deployment checklist

1. Tor installed and running; `tor-rotator doctor` healthy as the service account:
   `sudo -u tor-rotator /opt/tor-rotator/venv/bin/tor-rotator -c /etc/tor-rotator/config.toml doctor`
2. Config validated: `tor-rotator -c /etc/tor-rotator/config.toml config`.
3. Config permissions `0640 root:tor-rotator`; directory `0750`.
4. Service hardened: `systemd-analyze security tor-rotator.service` (≈0.4 SAFE expected).
5. Monitoring wired (metrics file and alerts) and log retention decided.

## Choosing a mode

| Situation | Control | SOCKS | systemd |
| --- | --- | --- | --- |
| Debian/Ubuntu packaged Tor | `unix` `/run/tor/control` | `unix` `/run/tor/socks` | unit as shipped (`PrivateNetwork=yes`) |
| Tor with loopback ports | `tcp` 127.0.0.1:9051 | `tcp` 127.0.0.1:9050 | add `tcp-loopback.conf` drop-in |
| Tor in a sidecar container | shared `unix` socket volume | shared `unix` socket, or `tcp` with `allow_non_loopback` | n/a |

## Interpreting results

| `signal_accepted` | `signal_applied` | `verified` | Meaning | Action |
| --- | --- | --- | --- | --- |
| false | false | false | Could not reach or authenticate to Tor. | Check `doctor`'s `control` check. |
| true | false | true/false | Tor acknowledged but did not apply NEWNYM within the window. | Usually concurrent NEWNYM from elsewhere; retry. |
| true | true | false | New circuits, but the exit could not be verified. | Inspect `after.observations`; network, providers or Tor health. |
| true | true | true | Success. `exit_changed` tells you whether the exit IP changed. | — |

`warnings` in a result mean the rotation itself completed but state or metrics were not
persisted (disk full, permissions) or a corrupt state file was reset.

## Tuning

- **`rotation.interval_seconds`**: Tor rate-limits NEWNYM to one every 10 s, and new
  circuits cost the network something; 5–15 minutes suits most uses.
- **`rotation.jitter_seconds`**: removes a predictable cadence (for example 10% of the
  interval).
- **`verify.timeout_seconds`**: the first probe after NEWNYM includes circuit construction;
  15 s is conservative. Lower it only on fast, stable networks.
- **`verify.attempts_after_rotation` / `retry_delay_seconds`**: govern how long a rotation
  keeps trying to verify (and, with `require_exit_change`, to observe a new exit).
- **`rotation.max_consecutive_failures`**: let systemd restart the service (and alert) after
  sustained failure instead of retrying forever.

## Monitoring

Metrics (`runtime.metrics_file`) are rewritten atomically after every rotation:

| Metric | Type | Notes |
| --- | --- | --- |
| `tor_rotator_rotations_total{outcome="succeeded"\|"failed"}` | counter | Lifetime, persisted in state. |
| `tor_rotator_exit_changes_total` | counter | Rotations that verified a different exit. |
| `tor_rotator_consecutive_failures` | gauge | Resets on success. |
| `tor_rotator_last_rotation_timestamp_seconds` | gauge | Last attempt. |
| `tor_rotator_last_success_timestamp_seconds` | gauge | Last success. |
| `tor_rotator_last_rotation_success` | gauge | 1/0. |
| `tor_rotator_last_rotation_exit_changed` | gauge | 1/0. |
| `tor_rotator_last_rotation_duration_seconds` | gauge | Wall time of the last attempt. |
| `tor_rotator_exit_verified` | gauge | 1/0 after the last rotation. |
| `tor_rotator_build_info{version}` | gauge | Always 1. |

Logs are JSON lines on stderr (journald under systemd). Useful fields: `request_id`,
`signal_applied`, `verified`, `exit_changed`, `attempts`, `duration_ms`, `error`.

```bash
journalctl -u tor-rotator -o cat | jq -c 'select(.message=="rotation failed") | {request_id, error}'
```

## Runbook

**`watch` exits with status 1 after `max_consecutive_failures`.** systemd restarts it
(`Restart=on-failure`, rate-limited by `StartLimitBurst`). Run `doctor`, read the last
rotation's `error` with `tor-rotator status`, fix the cause, then
`systemctl reset-failed tor-rotator`.

**Tor-negative observation.** Treat it as an incident: the configured SOCKS endpoint does not
exit through Tor. Stop dependent applications, check `[socks]` against Tor's listeners
(`doctor`'s `socks_listener` check), and confirm what is bound to that port or socket.

**Upgrading.** Install the new version into the venv, run `tor-rotator config` against the
production config, then `systemctl restart tor-rotator`. State files from 1.x are read
transparently (counters start at zero).

**Rolling back.** Reinstall the previous version; state schema 2 files are still readable as
JSON by 1.x's `status`.
