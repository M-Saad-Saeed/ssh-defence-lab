# Lab setup

The lab uses a macOS controller, VirtualBox and a dedicated Ubuntu guest. The provisioning script expects Ubuntu 26.04 (Resolute) and the hostname `ssh-defence-lab`. The native penalty settings require an OpenSSH build with `PerSourcePenalties`. Keep the guest on the private lab network during checks.

| Role | Address |
|---|---|
| VM SSH server | `192.168.57.210:22` |
| Mac management source | `192.168.57.1` |
| Password test source | `192.168.57.211` |
| Genuine source | `192.168.57.211` shared or `192.168.57.212` separate |

1. Create the guest and the `labadmin` administrator, configure the host-only subnet and set up the administrator's SSH key. Run `provision-server.sh` as root inside the guest. The script installs the packages, writes a private-only SSH listener configuration and sets up the service.
2. Generate a separate Ed25519 key for `legit_user` and generate independent passwords for both test accounts. Pass a private, mode-600 JSON file to `sudo python3 prepare-test-accounts.py <fixture-file>` inside the guest. The expected fields are `guess_target_password`, `legit_user_password` and `legitimate_public_key`. Both passwords must be at least 24 characters. The script removes its input fixture after a successful setup. The test accounts use forced success-marker sessions with forwarding and TTY allocation disabled.
3. Install `server-control.py` as `/usr/local/sbin/ssh-lab-control` on the guest. Run `sudo /usr/local/sbin/ssh-lab-control use A` and inspect `status` from the guest console. The controller's `use` command switches this same service configuration.
4. On the Mac, copy `ssh_config.example` to `ssh_config` and fill in the absolute local paths. Verify the server host key from the VM console and add the verified key to `.local/known_hosts`. Store the admin key and the genuine test key as `.local/labadmin_ed25519` and `.local/legit_user_ed25519`. The controller reads the guest admin sudo password from `.local/console-password.txt` and the dummy account fixture from `.local/test-fixtures.json`. Restrict the directory to mode 700 and credentials to mode 600.
5. Create an executable `.local/fixture-askpass` script that reads `guess_target_password` from `.local/test-fixtures.json` and writes only that password to stdout. The native SSH access checker calls it locally for a normal login.
6. Create the controller environment and install pinned packages.

   ```sh
   python3.14 -m venv .local/controller-venv
   .local/controller-venv/bin/python -m pip install -r requirements-lock.txt
   zsh "Prepare Test Addresses.command"
   zsh "Lab Menu.command"
   ```

Reapply the source aliases after the private bridge is recreated. Record the applied software versions and configuration before starting a pilot. Keep lab secrets and raw evidence in the ignored local directories.
