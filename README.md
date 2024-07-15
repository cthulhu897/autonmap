
# AutoNmap

AutoNmap is a robust script designed to conduct thorough Nmap scans against specified targets or lists of targets. It wraps Nmap commands into a user-friendly interface, adding error handling and enhanced feedback to improve usability and reliability.

## Getting Started

### Prerequisites

Ensure you have `nmap` and `xsltproc` installed on your system, as these are required for the script to function properly.

### Installation

Clone the GitHub repository to get the latest version of AutoNmap:

```bash
git clone --recursive https://github.com/cthulhu897/autonmap.git
```

Navigate to the directory where the script is located:

```bash
cd autonmap
```

### Usage

Run the script as root to ensure it has the necessary permissions to perform network scans:

```bash
sudo /opt/autonmap/autonmap.sh -o <output_name> -t <target>
```

or from your current directory:

```bash
sudo ./autonmap.sh -o <output_name> -t <target>
```

### Options

- `-h`  : Display help information.
- `-o`  : Specify the base name for files to save scan results.
- `-t`  : Specify the target IP, CIDR, or pass an input file with `-iL file.lst` for complex ranges.

## Examples

Here are some example commands to get you started:

1. **Scan a single IP address:**

   ```bash
   sudo ./autonmap.sh -o localhost -t 127.0.0.1
   ```

2. **Scan multiple IP addresses from a list:**

   ```bash
   sudo ./autonmap.sh -o myhome -t "-iL myhomestaticipaddreses.txt"
   ```

## Output

The script generates several files based on the provided output name, including:
- A list of alive hosts (`<output_name>_alive.lst`)
- Detailed port scans (`<output_name>_ports.nmap`)
- A comprehensive service scan (`<output_name>_final.nmap`)
- An HTML report (`<output_name>_report.html`), providing an easy-to-read overview of the scan results.

## Advanced Configuration

You can modify the TCP and UDP port ranges directly within the script to customize the scope of your scans based on specific requirements or network environments.

## Security Considerations

Ensure you have permission to scan the network and host you target with AutoNmap. Unauthorized scanning can lead to legal repercussions and be considered hostile by network administrators.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your enhancements.

## License

GPL 3.0
