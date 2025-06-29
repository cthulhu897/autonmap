#!/bin/bash
echo -e "
 █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗
███████║██║   ██║   ██║   ██║   ██║██╔██╗ ██║██╔████╔██║███████║██████╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                                            @cthulhu897
"

# Color definitions and log functions
greenColour="\e[0;32m\033[1m"; export greenColour
redColour="\e[0;31m\033[1m"; export redColour
blueColour="\e[0;34m\033[1m"; export blueColour
lightblueColour="\e[0;34m\033[1;34m"; export lightblueColour
yellowColour="\e[0;33m\033[1m"; export yellowColour
purpleColour="\e[0;35m\033[1m"; export purpleColour
turquoiseColour="\e[0;36m\033[1m"; export turquoiseColour
grayColour="\e[0;37m\033[1m"; export grayColour
endColour="\033[0m\e[0m"; export endColour

function log_error() {
    echo -e "[${redColour}❌${endColour}] ${redColour}$1${endColour}"
}
function log_warning() {
    echo -e "[${yellowColour}⚠️${endColour}] $1"
}
function log_success() {
    echo -e "[${greenColour}✅${endColour}] $1"
}
function log_info() {
    echo -e "[${lightblueColour}💬${endColour}] $1"
}
function log_debug() {
    if [[ "${DEBUG}" == "true" ]]; then
        echo -e "[${turquoiseColour}🕷️${endColour}] ${grayColour}$1${endColour}"
    fi
}

# Usage function
usage() {
  echo -e "\n${yellowColour}Usage:${endColour} sudo $0 -o <output_files> -t <target>\n"
  echo -e "${lightblueColour}Options:${endColour}"
  echo -e "\t-h\tDisplay this help message."
  echo -e "\t-o FILE\tSpecify the base name for files to save scan results."
  echo -e "\t-t TARGET\tSpecify the target IP, CIDR, or an input file with \"-iL file.lst\" for complex ranges.\n"
  echo -e "${purpleColour}Note:${endColour} This script acts as a wrapper for Nmap commands; use parameters carefully!\n"
}

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  log_error "Please run as root."
  echo "Example: sudo $0 -h"
  exit 1
fi

# Parse command-line options
while getopts ":t:o:h" opt; do
  case $opt in
    h)
      usage
      exit 0
      ;;
    t)
      TARGET="$OPTARG"
      ;;
    o)
      OUTPUT="$OPTARG"
      ;;
    \?)
      log_error "Invalid option: -$OPTARG"
      usage
      exit 1
      ;;
    :)
      log_error "Option -$OPTARG requires an argument."
      usage
      exit 1
      ;;
  esac
done

# Ensure required options are provided
if [ -z "$TARGET" ] || [ -z "$OUTPUT" ]; then
  log_error "Missing target or output file."
  usage
  exit 1
fi

# Define the directory to store script output
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Begin script operations
log_info "[Phase 1 of 3]"
log_info "Running host discovery..."
DISCOVERY_TCP_PORTS="80,443,22,3389,1723,8080,3306,135,53,143,139,445,110,25,21,23,5432,27017,1521"
DISCOVERY_UDP_PORTS="139,53,67,135,445,1434,138,123,137,161,631"
NMAP_HOST_DISCOVERY_CMD="nmap -vvv -sn -PE -PP -PM -PS${DISCOVERY_TCP_PORTS} -PU${DISCOVERY_UDP_PORTS} $TARGET -oA ${OUTPUT}_hosts -T2 --max-retries 3 --min-rtt-timeout 500ms --max-rtt-timeout 2000ms --initial-rtt-timeout 750ms --min-rate 125 --max-rate 2000 --min-hostgroup 256 --max-hostgroup 1024"
echo $NMAP_HOST_DISCOVERY_CMD
if ! eval "$NMAP_HOST_DISCOVERY_CMD"; then
  log_error "Failed to perform host discovery."
  exit 1
fi

# Extract list of alive hosts
if ! grep "Status: Up" "${OUTPUT}_hosts.gnmap" | cut -d " " -f 2 > "${OUTPUT}_alive.lst"; then
  log_warning "No hosts found up. Exiting."
  exit 1
fi

# # SYN scan
log_info "[Phase 2 of 3]"
log_info "Running SYN scan..."
SYN_SCAN_TCP_PORTS="1-65535"
SYN_SCAN_UDP_PORTS="7,9,11,13,17,19,37,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,213,259-260,427,443,445,464,497,500,514-515,518,520,523,593,623,626,631,749-751,996-999,1022-1023,1025-1030,1194,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,2746,3230-3235,3283,3401,3456,3703,4045,4444,4500,4665-4666,4672,5000,5059-5061,5351,5353,5632,6429,7777,8888,9100-9102,9200,10000,17185,18233,20031,23945,26000-26004,26198,27015-27030,27444,27960-27964,30718,30720-30724,31337,32768-32769,32771,32815,33281,34555,44400,47545,49152-49154,49156,49181-49182,49186,49190-49194,49200-49201,49211,54321,65024"
NMAP_SYN_SCAN_CMD="nmap -vvv -Pn -sS -sU --open -p T:${SYN_SCAN_TCP_PORTS},U:${SYN_SCAN_UDP_PORTS} -oA ${OUTPUT}_ports -iL ${OUTPUT}_alive.lst -T4 --max-retries 2 --min-rtt-timeout 250ms --max-rtt-timeout 1000ms --initial-rtt-timeout 750ms --min-rate 250 --max-rate 2000 --min-hostgroup 256 --max-hostgroup 512 --defeat-rst-ratelimit"
echo $NMAP_SYN_SCAN_CMD
if ! eval "$NMAP_SYN_SCAN_CMD"; then
  log_error "SYN scan failed."
  exit 1
fi

# Detailed scan
log_info "[Phase 3 of 3]"
log_info "Running detailed scan..."
if [ ! -s "${OUTPUT}_ports.nmap" ]; then
  log_warning "No open ports found from SYN scan. Scanning default ports..."
  DETAIL_SCAN_PORTS="T:22,80,443"
else
  OPEN_TCP_PORTS=$(awk '/open/&&/tcp/{print $1}' "${OUTPUT}_ports.nmap" | cut -d '/' -f 1 | sort -u | uniq | paste -sd,)
  OPEN_UDP_PORTS=$(awk '/open/&&/udp/{print $1}' "${OUTPUT}_ports.nmap" | cut -d '/' -f 1 | sort -u | uniq | paste -sd,)
  DETAIL_SCAN_PORTS="T:22,80,443,$OPEN_TCP_PORTS,U:137,161,$OPEN_UDP_PORTS"
fi
# You want to tune this up
# adjust min-max host group acording to your target
# maybe be more polite ?
DETAIL_SCAN_CMD="nmap -vv -Pn -sT -sU --open -sV --version-intensity 2 --script-timeout 120s -sC -O -p $DETAIL_SCAN_PORTS -oA ${OUTPUT}_final -iL ${OUTPUT}_alive.lst -T4 --max-retries 3 --min-rtt-timeout 250ms --max-rtt-timeout 2000ms --initial-rtt-timeout 750ms --min-rate 125 --max-rate 2000 --min-hostgroup 8 --max-hostgroup 256 --max-parallelism 2048  --min-parallelism 8 --defeat-rst-ratelimit"
echo $DETAIL_SCAN_CMD
if ! eval "$DETAIL_SCAN_CMD"; then
  log_error "Detailed scan failed."
  exit 1
fi

# Generate report
log_info "[Converting results]"
log_info "Generating HTML report..."
XSLT_TRANSFORM_CMD="xsltproc -o ${OUTPUT}_report.html ${SCRIPT_DIR}/nmap-bootstrap.xsl/nmap-bootstrap.xsl ${OUTPUT}_final.xml"
echo $XSLT_TRANSFORM_CMD
URL=$(realpath "${OUTPUT}_report.html"); xdg-open $URL || sensible-browser $URL || x-www-browser $URL || gnome-open $URL 
if ! eval "${XSLT_TRANSFORM_CMD}"; then
  log_error "Failed to generate HTML report."
  exit 1
fi
log_success "======================================================================"
log_success "Scan completed and report generated."
log_success "======================================================================"
log_success "--->  file://${URL}"
log_success "======================================================================"
log_success "...wishing you happy findings and easy reporting :)        @cthulhu897"
log_success "======================================================================"

