# Offline fixtures

`filter-check.log` contains four invented messages, including old and newer SSH
daemon names. The installed normal Fail2ban filter should count the two failed
password messages and avoid counting the two successful messages as failures.
This file is passed directly to `fail2ban-regex`; it is never injected into the
live authentication log. Passing this check does not prove live detection or
one-password-request-per-connection accounting.
