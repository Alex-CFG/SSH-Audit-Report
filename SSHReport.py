import json
import subprocess
import argparse
import csv
import sys

BADALGORITHMS = [
    '3des-cbc',
    'aes128-cbc',
    'aes192-cbc',
    'aes256-cbc',
    'chacha20-poly1305@openssh.com',
    'diffie-hellman-group1-sha1',
    'diffie-hellman-group14-sha1',
    'diffie-hellman-group-exchange-sha1',
    'gss-gex-sha1-*',
    'gss-group1-sha1-*',
    'gss-group14-sha1-*',
    'umac-64-etm@openssh.com',
    'umac-128-etm@openssh.com',
    'hmac-sha2-256-etm@openssh.com',
    'hmac-sha2-512-etm@openssh.com',
    'hmac-sha1-etm@openssh.com',
    'umac-64@openssh.com',
    'hmac-sha1'
]
 
def runSSHAudit(targets):
    try:
        output = subprocess.run(['ssh-audit', '-jj', '-T', targets], capture_output=True, text=True).stdout.strip('\n')
        return json.loads(output)
    except:
        print("Invalid Data")
        return False

def parseAuditSoftware(SSHAuditData):
    hosts = {} 
    for data in SSHAuditData:
        target = data['target']
        hosts[target] = {} 
        hosts[target]['software'] = data['banner']['raw']
        hosts[target]['CVE'] = []
        hosts[target]['cipher'] = []
        hosts[target]['kex'] = []
        hosts[target]['mac'] = []
        if 'cves' in data:
            for CVE in data['cves']:
                hosts[target]['CVE'].append(CVE['name'])
        for kex in data['kex']:
            hosts[target]['kex'].append(kex['algorithm'])
        for mac in data['mac']:
            hosts[target]['mac'].append(mac['algorithm'])
        for cipher in data['enc']:
            hosts[target]['cipher'].append(cipher['algorithm'])
    return hosts

def filterAlgorithms(hosts):
    algoCategory = ['cipher', 'kex', 'mac']
    for host in hosts:
        for category in algoCategory:
            badAlgo = []
            for algo in hosts[host][category]:
                if algo in BADALGORITHMS:
                    badAlgo.append(algo)
                hosts[host][category] = badAlgo
    return hosts
            

def excelOutput(hosts):
    rows = []
    for host in hosts:
        data = []
        data.append(host)
        data.append(hosts[host]['software'])
        data.append(', '.join(hosts[host]['CVE']))
        rows.append(data)

    with open("software.csv", "w", encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(['Host', 'Software', 'CVE'])
        for row in rows:
            writer.writerow(row)

#Duplicate gonna make his better
def excelConfigOutput(hosts):
    rows = []
    for host in hosts:
        data = []
        data.append(host)
        data.append('\n'.join(hosts[host]['cipher']))
        data.append('\n'.join(hosts[host]['kex']))
        data.append('\n'.join(hosts[host]['mac']))
        rows.append(data)

    with open("config.csv", "w", encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(['Host', 'Weak Ciphers', 'Weak Key Exchange Algorithms', 'Weak MAC Algorithms'])
        for row in rows:
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest="subcommand")
    
    softwareParser = subparser.add_parser("software")
    softwareParser.add_argument("hosts",  type=argparse.FileType('r'))

    configParser = subparser.add_parser("config")
    configParser.add_argument("hosts",  type=argparse.FileType('r'))

    if len(sys.argv)==1:
        parser.print_help()
        parser.exit()

    args = parser.parse_args()
    SSHAuditData = runSSHAudit(args.hosts.name)

    if SSHAuditData == False:
        exit(1)

    hosts = parseAuditSoftware(SSHAuditData)

    if args.subcommand == "software":
        excelOutput(hosts)

    if args.subcommand == "config":
        host = filterAlgorithms(hosts)
        excelConfigOutput(hosts)

if __name__ == "__main__":
    main()
