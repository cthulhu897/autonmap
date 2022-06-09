# AutoNmap
Script to run a trustfull nmap scan against a target or a list of targets

------------
## Usage

Clone github repository
```
git clone --recursive https://github.com/Fatake/autonmap.git
```

**Help**:

```
sudo ./autonmap.sh -h
```

**Run script**
One target:
```
sudo ./autonmap.sh -o <output_name> -t <target>
```
List of Targets:
```
sudo ./autonmap.sh -o <output_name> -t "-iL tartgets.lts"
```

------------
## Examples:
```
sudo ./autonmap.sh -o localhost -t 127.0.0.1
```

```
sudo ./autonmap.sh -o myhome -t "-iL myhomestaticipaddreses.txt"
```
