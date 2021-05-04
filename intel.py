#!/usr/bin/env python3

import argparse

def inputFileJA3(rulePath,output,disable):
    intelRule="JA3 Hash"
    with open(rulePath) as rules:
        for rule in rules:
            if intelRule in rule:
                tempRule = rule.split('content:\"')
                tempRule = str(tempRule[1])
                ja3 = tempRule.split('"')
                sid = rule.split('sid:')
                sid = str(sid[1])
                sid = sid.split(";")
                ja3Intel(ja3[0],output,sid[0],rulePath,disable)


def inputFileIP(rulePath,output,disable):
    intelRule = "alert " + "ip" + " ["
    with open(rulePath) as rules:
        for rule in rules:
            if intelRule in rule:
                tempRule = rule.split('[')
                tempRule = str(tempRule[1])
                ipList = tempRule.split(']')
                ipString = str(ipList[0])
                sidString = str(ipList[1])
                sidEnd = sidString.split('sid:')
                sidEnd = str(sidEnd[1])
                sid = sidEnd.split(';')
                ips = ipString.split(',')
                for ip in ips:
                    ipIntel(ip,output,sid[0],rulePath,disable)
                
def ja3Intel(ja3,output,sid,rulePath,disable):
    intelFormat = ja3 + "\tIntel::JA3\t" + rulePath + " " + sid
    print(intelFormat, file=output)
    print(sid, file=disable)

def ipIntel(ip,output,sid,rulePath,disable):
    # sid = str(sid)
    if ((ip[-3] == '/') or (ip[-2] == '/')):
        intelFormat = ip + "\tIntel::SUBNET\t"  + rulePath + " " + sid
    else:
        intelFormat = ip + "\tIntel::ADDR\t"  + rulePath + " " + sid
    
    print(intelFormat, file=output)
    print(sid, file=disable)
        
def dedup(file):
    lines_seen = set() # holds lines already seen
    outfile = open('disable.conf', 'w')
    for line in open(file, 'r'):
        if line not in lines_seen: # not a duplicate
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-rules', help='Location of Suricata rules to parse', required=True)
    parser.add_argument('-output', help='Location of Intel output', required=True)
    parser.add_argument('-ja3', help="enable JA3 intel need the correct Zeek scripts to support", default=False, action='store_true', required=False)
    args = parser.parse_args()
    intelFile = open(args.output, 'w')
    disable = open("suricata_disable.conf", 'w')
    print("#fields\tindicator\tindicator_type\tmeta.source", file=intelFile)
    inputFileIP(args.rules,intelFile,disable)
    if args.ja3:
        inputFileJA3(args.rules,intelFile,disable)
    intelFile.close
    disable.close
    dedup("suricata_disable.conf")

if __name__ == "__main__":
    main()

