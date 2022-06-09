#!/bin/bash
usage () {
  echo -e "\n[i] autonmap is designed to run a full host discovery,"
  echo -e "[i] scaning and firgerprinting of wide ranges of systems during a pentest"
  echo -e "[i] It's main goal is to provide a complete portscan that provides all "
  echo -e "[i] the information needed for further phases of a pentest\n\nUsage:"
  echo -e "sudo ./autonmap -o <output_files> -t <target> -h\n"

  echo -e "\t-h \tDisplays this message of use"
  echo -e "\t-o \tFile name to use to save scan related files"
  echo -e "\t-t \tTarget IP,CIDR or pass an input file as \"-iL file.lst\" to scan more complex ranges";
  echo -e "\n[!] Note: This script was written while drunk so a lot of command injection vulns are present by design so dont trust it for public use."
  echo -e "[*] Made with love and tacos by \n-> @cthulhu897 \n->Fatake \n"
}

# Check if root launch
if [ "$EUID" -ne 0 ]
  then echo -e "[!] Please run as root\n[i] check sudo ./autonmap -h"
  exit 1
fi

# Check opts
while getopts ":t:o:h" opt; do
  case $opt in
    # help
    h)
      echo "================================================================================";
      echo "====================================   USAGE   =================================";
      echo "================================================================================";
      usage
      exit 1
      ;;

    # Target
    t)
      echo -e "[+] Target:\t\t $OPTARG" >&2
      TARGET="$OPTARG"
      f_target=true
      ;;

    # output file
    o)
      echo -e "[+] Output Files:\t $OPTARG" >&2
      NAME="$OPTARG"
      f_name=true
      ;;

    \?)
      echo -e "[!] Invalid option:\t -$OPTARG" >&2
      usage
      exit 1
      ;;

    :)
      echo -e "[!] Option -$OPTARG requires an argument." >&2
      usage
      exit 1
      ;;
  esac
done

# check tan output and target is not empty
if [ -z "$f_name" ] || [ -z "$f_target" ]; then
  echo -e "[!] ERROR! \n[i] check ./autonmap -h"
  exit 1;
fi

SAVE_DIR="autonmap_${NAME}"
if [ ! -d "${SAVE_DIR}" ] 
then
  echo "================================================================================";
  echo -e "[*] Creating directory: ${SAVE_DIR}...\n"
  /bin/bash -c "mkdir ${SAVE_DIR}/" 2>/dev/null
  /bin/bash -c  "chown -R 1000:1000 ${SAVE_DIR}/" 2>/dev/null
fi

#Host discovery on top TCP and UDP ports
ALIVEHOSTS="nmap -sn -PE -PP -PM -PS80,443,22,3389,1723,8080,3306,135,53,143,139,445,110,25,21,23,5432,27017,1521 -PU139,53,67,135,445,1434,138,123,137,161,631 $TARGET -oA ${SAVE_DIR}/${NAME}_aliveHosts";
echo "================================================================================";
echo "==========================  H O S T    D I S C O V E R Y  ======================";
echo "================================================================================";
echo "pentester# "$ALIVEHOSTS;
echo -e "================================================================================\n";
eval $ALIVEHOSTS
#Extract list of alive hosts
cat "${SAVE_DIR}/${NAME}_aliveHosts.gnmap" | grep "Status: Up" | cut -d " " -f 2 > "${SAVE_DIR}/${NAME}_hosts".lst;

#Fast full port scan with 65535 tcp ports and top UDP
COMMUN_UDP_PORTS="7,9,11,13,17,19,37,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,213,259-260,427,443,445,464,497,500,514-515,518,520,523,593,623,626,631,749-751,996-999,1022-1023,1025-1030,1194,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,2746,3230-3235,3283,3401,3456,3703,4045,4444,4500,4665-4666,4672,5000,5059-5061,5351,5353,5632,6429,7777,8888,9100-9102,9200,10000,17185,18233,20031,23945,26000-26004,26198,27015-27030,27444,27960-27964,30718,30720-30724,31337,32768-32769,32771,32815,33281,34555,44400,47545,49152-49154,49156,49181-49182,49186,49190-49194,49200-49201,49211,54321,65024"
SYNSCAN="nmap -Pn -sS -sU -p T:1-65535,U:${COMMUN_UDP_PORTS} -T4 --max-retries 2 --min-rtt-timeout 500ms --max-rtt-timeout 2000ms --initial-rtt-timeout 750ms --defeat-rst-ratelimit --min-rate 900 --max-rate 8000 --disable-arp-ping -oA ${SAVE_DIR}/${NAME}_openports -iL ${SAVE_DIR}/${NAME}_hosts.lst -v ";
echo -e "\n\n================================================================================";
echo "================================  S Y N   S C A N  =============================";
echo "================================================================================";
echo "pentester# "$SYNSCAN;
echo -e "================================================================================\n";
eval $SYNSCAN;

#Extract open ports list trimming ending comma
TCPPORTS=$(cat "${SAVE_DIR}/${NAME}_openports.gnmap" | awk -F " " '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print s }' | tr ", " "\n" | grep open | grep tcp | cut -d "/" -f 1 | sort -nu | paste -s -d, - );
UDPPORTS=$(cat "${SAVE_DIR}/${NAME}_openports.gnmap" | awk -F " " '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print s }' | tr ", " "\n" | grep open | grep udp | cut -d "/" -f 1 | sort -nu | paste -s -d, - );

#Final scan full connect and service reconnaissance if<>fi sentece to handle empty strings and keep command integrity
if [ -z "${TCPPORTS}" ]; then
  NMAPSCAN="nmap -Pn -sS -sV -sC -O -A -sU -p T:22,80,443,U:${UDPPORTS} -oA ${SAVE_DIR}/${NAME}_details $TARGET ";
else
  NMAPSCAN="nmap -Pn -sS -sV -sC -O -A -sU -p T:${TCPPORTS},U:${UDPPORTS} -oA ${SAVE_DIR}/${NAME}_details $TARGET ";
fi
echo -e "\n\n================================================================================";
echo "=============================   F U L L    S C A N   ===========================";
echo "================================================================================";
echo "pentester# " $NMAPSCAN;
echo -e "================================================================================\n";
eval $NMAPSCAN;

xsltproc -o "${NAME}_autonmap_report.html" "${DIR}/nmap-bootstrap.xsl/nmap-bootstrap.xsl" "${NAME}_autonmap_servicescan.xml"

echo "[*] D O N E \n"
