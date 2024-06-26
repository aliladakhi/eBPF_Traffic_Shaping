ip link set dev enp0s8 xdp off
rm -f /sys/fs/bpf/xdp_prog
ip link show dev enp0s8
