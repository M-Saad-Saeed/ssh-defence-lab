# SSH Defence Lab

A Brunel University of London Computer Science final-year project investigating how OpenSSH source penalties and Fail2ban limit SSH password guessing while preserving access for legitimate users.

**Project status:** The isolated lab, configuration switcher and normal-login checks are working. Live defence validation, the scheduled experiment runner and results analysis are planned.

## Research question

When legitimate SSH connections share a source IP with password guesses, how do OpenSSH's native penalties, Fail2ban and their combined use affect guessing throughput and legitimate access?

The project measures **distinct password guesses evaluated by the server** within a fixed window and **the percentage of scheduled legitimate connections that miss a common completion deadline**. A pilot will determine the offered guessing rate, run length, connection deadline and repetition count.

## Experimental design

| Condition | OpenSSH source penalties | Fail2ban SSH jail |
|---|---|---|
| A · Baseline | Off | Off |
| B · Native penalties | On | Off |
| C · Fail2ban | Off | On |
| D · Combined | On | On |

Each condition is paired with two layouts. In the shared layout, both traffic streams use the same source address. In the separate layout, the legitimate stream uses a second address. This gives **eight main scenarios** and four genuine-only reference runs. The design models what the server observes when traffic shares an address.

## How the lab works

A macOS controller connects to an Ubuntu VM over a VirtualBox host-only network. The controller binds each test connection to the specified source address. SSH server logs verify which address reached the VM. The administrator connects from a separate management address.

| File or directory | Role |
|---|---|
| [server-control.py](server-control.py) | Applies A–D, validates effective settings, records state and restores the previous configuration if a switch fails. |
| [labctl.py](labctl.py) and [Lab Menu.command](Lab%20Menu.command) | Provide status, configuration switching and health checks from the Mac. |
| [ssh_probe.py](ssh_probe.py) and [check-test-access.py](check-test-access.py) | Check normal logins using explicit authentication methods, a pinned host key and source binding. |
| [scenarios.json](scenarios.json) | Records the experiment matrix and the parameters awaiting pilot selection. |
| [fixtures](fixtures/) and [data](data/) | Contain invented authentication logs and deterministic synthetic password candidates. |

## Setup validation completed

- Applied and verified each condition, including effective OpenSSH settings, Fail2ban jail state and the expected firewall table.
- Completed three correct-credential Python login probes per condition.
- Confirmed shared and separate source layouts in server authentication logs.
- Verified the offline Fail2ban filter against four synthetic messages. It matched the two failed logins and ignored the two successful logins.

These checks establish the starting conditions for the study. The next validation milestone is to link one scripted guess to one server-side password evaluation and verify blocking, recovery and reset behaviour with known sequences.

## Run the setup checks

The scripts target a dedicated Ubuntu VM and a macOS controller. See the [lab setup guide](SETUP.md) for the network layout, account roles and local configuration. Once the VM and local credentials are prepared, run:

```sh
zsh "Prepare Test Addresses.command"
zsh "Lab Menu.command"
```

Choose **1** in the menu for the health check. Results from setup checks are written to the local `evidence/` directory.

## References

- [OpenSSH portable 10.2p1 server configuration manual](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/sshd_config.5)
- [Fail2ban 1.1.0 SSH filter](https://github.com/fail2ban/fail2ban/blob/1.1.0/config/filter.d/sshd.conf)
- [Paramiko transport API](https://docs.paramiko.org/en/stable/api/transport.html)
