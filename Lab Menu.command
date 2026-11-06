#!/bin/zsh
# Mac menu for environment checks; does not run password-guessing workloads.
set -u
cd "${0:A:h}"
python="$PWD/.local/controller-venv/bin/python"
if [[ ! -x "$python" ]]; then
    echo 'The project Python environment is missing. See ENVIRONMENT-GUIDE.md.'
    read -r '?Press Enter to close.'
    exit 1
fi
while true; do
    echo
    echo 'SSH Defence Lab — environment menu'
    echo '1  Check the environment and normal logins'
    echo '2  Show the current protection settings'
    echo '3  Set A: both selected protections off'
    echo '4  Set B: native penalties only'
    echo '5  Set C: Fail2ban only'
    echo '6  Set D: both protections on'
    echo '7  Show the eight-scenario plan'
    echo 'q  Quit'
    echo 'Changing settings restarts lab services. Do not change them during a measurement.'
    read -r 'choice?Choose an option: '
    case "$choice" in
        1) "$python" labctl.py health ;;
        2) "$python" labctl.py status ;;
        3) "$python" labctl.py use A ;;
        4) "$python" labctl.py use B ;;
        5) "$python" labctl.py use C ;;
        6) "$python" labctl.py use D ;;
        7) "$python" labctl.py plan ;;
        q|Q) exit 0 ;;
        *) echo 'Choose 1–7 or q.' ;;
    esac
done
