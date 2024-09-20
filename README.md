# SSH-Audit-Report

A tool which generates a CSV file containing the SSH version and CVEs associated with the version.

## Prerequisite   

Install the `ssh-audit` tool from [here](https://github.com/jtesta/ssh-audit)

## Usuage

Create a text file with a list of hosts 

For software

```
python3 SSHReport.py software target.txt
```

For configuration

```
python3 SSHReport.py config target.txt
```
