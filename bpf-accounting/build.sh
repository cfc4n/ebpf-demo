#!/usr/bin/env bash

# Create the Cgroup
sudo mkdir -p /sys/fs/cgroup/unified/cnxct

# Register the current shell PID in the cgroup
echo $$ | sudo tee /sys/fs/cgroup/unified/cnxct/cgroup.procs

# Start an advanced networking command
ping -n www.baidu.com