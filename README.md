# ProbeMonLinux
Captures probe request and response frames sent by 802.11 adapters. Catches cts frames from stations specfied in a csv file.

## Usage
./ProbeMon -m[all, probes, cts] -l[interface] -f[csv file]

The csv file should be in 2 column comma delimited format with target station address first and a text hint: "01:02:03:04:05:06,My iPhone". You can have upto 3 stations/hints.

### Example
./ProbeMon -mcts -lwlan0 -fstations.csv

#### Requirements
Monitor mode capture device and pcap installed

#### Other
Currently working on a scapy injection script
