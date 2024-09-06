import json
import subprocess
import argparse
import csv

def runSSHAudit(targets):
    output = subprocess.run(['ssh-audit', '-jj', '-T', targets], capture_output=True, text=True).stdout.strip('\n')
    return json.loads(output)

def parseAudit(SSHAuditData):
    hosts = {} 
    for data in SSHAuditData:
        target = data['target']
        hosts[target] = {} 
        hosts[target]['software'] = data['banner']['raw']
        hosts[target]['CVEs'] = []
        for CVE in data['cves']:
            hosts[target]['CVEs'].append(CVE['name'])
    return hosts

def CanopyOutput(hosts):
    print("""<table style="width: 100%;">""")
    print("<tbody>")
    for host in hosts:
        print("<tr>")
        for detail in host.values():
            print("""<td style="width: 25%;">""", end='')
            if isinstance(detail, list):
                print(', '.join(detail), end='')
            else:
                print(detail, end='')
            print("</td>")
        print("</tr>")
    print("</tbody>")
    print("</table>")

def ExcelOutput(hosts):
    rows = []
    for host in hosts:
        data = []
        data.append(host)
        data.append(hosts[host]['software'])
        data.append(', '.join(hosts[host]['CVEs']))
        rows.append(data)

    with open("output.csv", "w", encoding='UTF8') as f:
        writer = csv.writer(f)
        writer.writerow(['Host', 'Software', 'CVEs'])
        for row in rows:
            writer.writerow(row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hosts",  type=argparse.FileType('r'))
    targets = parser.parse_args().hosts.name
    SSHAuditData = runSSHAudit(targets)
    hosts = parseAudit(SSHAuditData)
    ExcelOutput(hosts)
