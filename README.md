# eBPF Traffic Shaping Project

## Introduction

This project demonstrates the use of eBPF (extended Berkeley Packet Filter) for traffic shaping. eBPF is a powerful technology that allows running sandboxed programs in the Linux kernel, enabling high-performance packet processing without the need to modify the kernel source code or load kernel modules.

### Why Use eBPF for Traffic Shaping?

eBPF offers several advantages over traditional tools like `tc` (Traffic Control):
- **Performance**: eBPF runs in the kernel, allowing for faster packet processing compared to user-space programs.
- **Flexibility**: eBPF programs can be dynamically loaded and unloaded, making it easier to update and manage traffic shaping policies.
- **Security**: eBPF runs in a sandboxed environment, reducing the risk of compromising the kernel.

## Project Overview

In this project, we implement a simple rate limiter using eBPF that differentiates between high-priority (HP) and low-priority (LP) traffic based on IP addresses and ports. The rate limiter ensures that:
- HP traffic can use up to 100 Mbit/s.
- LP traffic can use up to 20 Mbit/s.
- LP traffic can borrow HP bandwidth if available.

### IP Addresses and Ports

- **HP IP**: 192.168.56.112
  - HP High-Priority Port: 7001
  - HP Low-Priority Port: 7002
- **LP IP**: 192.168.56.113
  - LP High-Priority Port: 7003
  - LP Low-Priority Port: 7004

### Token Buckets

- **HP Token Bucket**: Allows HP traffic to pass up to 100 Mbit/s.
- **LP Token Bucket**: Allows LP traffic to pass up to 20 Mbit/s.
- **Refill Mechanism**: Tokens are refilled every second based on the allowed rate.

## Setup Instructions

### Prerequisites

- Linux system with kernel version 4.15 or higher
- `clang` and `llvm` for compiling eBPF programs
- `libbpf` and `bpftool` for managing eBPF programs
- `iproute2` package for managing network interfaces
- `iperf3` for testing network performance

### Installation

1. **Clone the Repository**:
    ```sh
    git clone https://github.com/aliladakhi/eBPF_Traffic_Shaping.git
    cd eBPF_Traffic_Shaping
    ```

2. **Install Dependencies**:
    ```sh
    sudo apt-get update
    sudo apt-get install clang llvm libbpf-dev libelf-dev iproute2 iperf3 bpftool
    ```

## Usage

1. **Load the eBPF Program**:
    ```sh
    sudo bpftool prog load xdp_rate_limiter.o /sys/fs/bpf/xdp_prog
    ```

2. **Run Network Performance Tests**:
    Use `iperf3` to test network performance and observe traffic shaping:
    ```sh
    iperf3 -c 192.168.56.112 -p 7001  # HP traffic
    iperf3 -c 192.168.56.113 -p 7003  # LP traffic
    ```

3. **Check eBPF Maps Using bpftool**:
    To inspect the eBPF maps and monitor packet counts:
    ```sh
    sudo bpftool map show
    sudo bpftool map dump pinned /sys/fs/bpf/<map_name>
    ```


## Result Files

- **result.txt**: Contains the detailed output of the `iperf3` tests, including throughput and packet drop statistics.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- eBPF community for providing extensive documentation and examples.
- OpenAI for their assistance in drafting this README file.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## Contact

For questions or suggestions, please open an issue on GitHub or contact me at [mohammadalirakrock@gmail.com].
