#!/bin/zsh
# Open the project VM and connect using the separate local lab administrator key.
set -eu
task_lab_dir="${0:A:h}"
task_vbox='/Applications/VirtualBox.app/Contents/MacOS/VBoxManage'
task_vm_state="$("$task_vbox" showvminfo 'SSH-Defence-Lab' --machinereadable | /usr/bin/sed -n 's/^VMState="\(.*\)"/\1/p')"
case "$task_vm_state" in
    poweroff|aborted|saved)
        "$task_vbox" startvm 'SSH-Defence-Lab' --type gui
        ;;
    running) ;;
    *)
        print "The VM is currently $task_vm_state. Check its console in VirtualBox."
        exit 1
        ;;
esac
print 'Connecting to your private SSH lab. Ubuntu may need a moment to boot.'
for task_attempt in {1..18}; do
    if /usr/bin/ssh -F "$task_lab_dir/ssh_config" -o BatchMode=yes ssh-defence-lab true 2>/dev/null; then
        exec /usr/bin/ssh -F "$task_lab_dir/ssh_config" ssh-defence-lab
    fi
    /bin/sleep 5
done
print 'The lab did not become reachable. Check the SSH-Defence-Lab console in VirtualBox.'
read '?Press Enter to close.'
