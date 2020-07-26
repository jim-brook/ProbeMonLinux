from __future__ import print_function
from scapy.all import *
import argparse
import csv

class InjectCts:
    Stations = []

    CsvFileName = ""
    TargetMAC = "01:02:03:04:05:06"
    ReplyToMAC = "11:22:33:44:55:66"
    Interface = "wlan0"
    Interval = 0.1
    ContinuousSend = 0
    def __init__(self, iface, dly, loop, csv):
        self.CsvFileName = csv
        self.Interface = iface
        self.Interval = dly
        self.ContinuousSend = loop

    def Start(self):  

        with open(self.CsvFileName) as file:
            reader = csv.reader(file, delimiter = '\n')
            for row in reader:
                col = row[0].split(',')  
                params = StationParams(self.Interface, col[0] , col[1] , self.Interval, self.ContinuousSend)
                self.Stations.append(params)

        if self.ContinuousSend > 0:
            while 1:
                for station in self.Stations:
                    self.SendPkts(station)
        else:
            for station in self.Stations:
                self.SendPkts(station)          
        

    def SendPkts(self, Params):
        WMAC = Dot11(type = 1, subtype = 11, ID=1, SC=1, addr1 = Params.TargetMAC, addr2 = Params.ReplyToMAC)
        WFrame = RadioTap()/WMAC
        sendp(WFrame, iface = Params.Interface, inter = Params.Interval, loop = 0, monitor = True)
        WFrame.show()
        print("\nHexDump of frame:")
        hexdump(WFrame)


class StationParams:
    def __init__(self, iface, targ, reply, intv, cont):
        self.TargetMAC = targ
        self.ReplyToMAC = reply
        self.Interface = iface
        self.Interval = intv
        self.ContinuousSend = cont

if __name__ == "__main__":
    parser = argparse.ArgumentParser("rts_inject")
    parser.add_argument("iface", help="the interface used for injects wlan0, wlan1 ...")
    parser.add_argument("delay", help="delay in seconds between transmissions e.g. 0.1 = 100ms", type=float)
    parser.add_argument("loop", help="looping", type=int)
    parser.add_argument("csv", help="csv file name")

    args = parser.parse_args()    
    inj = InjectCts(args.iface, args.delay, args.loop, args.csv)
    inj.Start()