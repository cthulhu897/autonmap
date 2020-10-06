# autonmap
Script to run a trustfull nmap scan against a target or a list of targets

```
git clone --recursive https://github.com/cthulhu897/autonmap.git
```

Run as:
```
sudo /opt/autonmap/autonmap.sh -n <name> -t <target>
```

Examples:
```
sudo /opt/autonmap/autonmap.sh -n localhost -t 127.0.0.1
```

```
sudo /opt/autonmap/autonmap.sh -n myhome -t "-iL myhomestaticipaddreses.txt"
```
