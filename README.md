# ProbeMonLinux
Captures probe request and response frames sent by 802.11 adapters. Catches cts frames from stations specfied in a csv file. This project is not the same as the Windows version.

## Usage
./ProbeMon -m[all, probes, cts] -l[interface] -f[csv file]

The csv file should be in 2 column comma delimited format with target station address first and a text hint: "01:02:03:04:05:06,My Access Point's Address". You can have upto 3 stations/hints.

### Example
./ProbeMon -mcts -lwlan0 -fstations.csv

#### Requirements
Monitor mode capture device and pcap installed. Tested with Kali 2020-6, AWUS036ACH, Aircrack rtl8812au dkms driver from https://github.com/aircrack-ng/rtl8812au

#### Other
Currently working on a scapy injection script

# inject_rts.py
Inject a rts frame using scapy.

## Usage
inject_rts [interface] [loop delay time in seconds] [loops] [csv file]

### Example
python3 inject_rts.py wlan1 0.10 0 /home/MyHome/macs_scpy.csv

#### Requirements
RTS Injection capable device and scapy installed. Tested with Kali 2020-6, AWUS036ACH, Aircrack rtl8812au dkms driver from https://github.com/aircrack-ng/rtl8812au

