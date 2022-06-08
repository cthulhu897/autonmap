# AutoNmap
Script to run a trustfull nmap scan against a target or a list of targets

------------
## Usage

Clone github repository
```
git clone --recursive https://github.com/Fatake/autonmap.git
```

Run as root:
```
sudo /opt/autonmap/autonmap.sh -o <output_name> -t <target>
```
or
```
sudo ./autonmap.sh -o <output_name> -t <target>
```

------------
## Examples:
```
sudo /opt/autonmap/autonmap.sh -o localhost -t 127.0.0.1
```

```
sudo /opt/autonmap/autonmap.sh -o myhome -t "-iL myhomestaticipaddreses.txt"
```
