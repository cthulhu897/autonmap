#!/bin/bash
f_name=false
f_target=false

usage () {
  echo "./autonmap -n <name> -t <target>"; 
  echo "-n \tName to use to save the scan related files, this script will create a directory to save these files"; 
  echo "-t \tTarget IP CIDR or \"-iL file.lst\" to scan"; 
}

while getopts ":t:n:" opt; do
  case $opt in
    t)
      echo "Target:\t $OPTARG" >&2
	  f_target=true
	  TARGET=$OPTARG
      ;;
	n)
      echo "Name spacified:\t $OPTARG" >&2
	  NAME=$OPTARG
	  f_name=true
      ;;
    \?)
      echo "Invalid option:\t -$OPTARG" >&2
      usage;
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage;
      exit 1
      ;;
  esac
done

if ! $f_name && ! $f_target
then
    echo "-n NAME and -t TARGET must be included to launch an automatic scan" >&2
    exit 1
fi

if [ -d "$DIRECTORY" ]; then
  echo "\n$NAME is a directory that already exists in this system. Please provide another name!\n"
fi

mkdir $NAME

#Host discovery on top ports
nmap -sn -PE -PP -PM -PS1723,8080,3306,135,53,143,139,445,110,3389,25,22,21,443,23,80 -PU139,53,67,135,445,1434,138,123,137,161,631 "$TARGET" -oA "$NAME"/nmap_host-discovery_"$NAME"
cat "$NAME"/nmap_host-discovery_"$NAME".gnmap | grep "Status: Up" | cut -d " " -f 2 > "$NAME"/il_alive_"$NAME".lst

#Fast full port scan with 65535 tcp ports and top UDP
nmap -Pn -sS -sU -p T:1-65535,U:7,9,11,13,17,19,37,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,213,259-260,427,443,445,464,497,500,514-515,518,520,523,593,623,626,631,749-751,996-999,1022-1023,1025-1030,1194,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,2222-2223,2746,3230-3235,3283,3401,3456,3703,4045,4444,4500,4665-4666,4672,5000,5059-5061,5351,5353,5632,6429,7777,8888,9100-9102,9200,10000,17185,18233,20031,23945,26000-26004,26198,27015-27030,27444,27960-27964,30718,30720-30724,31337,32768-32769,32771,32815,33281,34555,44400,47545,49152-49154,49156,49181-49182,49186,49190-49194,49200-49201,49211,54321,65024 --max-retries 2 --min-rtt-timeout 500ms --max-rtt-timeout 2000ms --initial-rtt-timeout 750ms --defeat-rst-ratelimit --min-rate 800 --max-rate 5000 --disable-arp-ping -oA "$NAME"/nmap_full_scan_synudp_"$NAME" -iL "$NAME"/il_alive_"$NAME".lst -v -T4

#Extract open ports list trimming ending comma
TCPPORTS=$(cat "$NAME"/nmap_full_scan_synudp_"$NAME".gnmap | awk -F " " '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print s }' | tr ", " "\n" | grep open | grep tcp | cut -d "/" -f 1 | sort -nu | paste -s -d, - )
UDPPORTS=$(cat "$NAME"/nmap_full_scan_synudp_"$NAME".gnmap | awk -F " " '{ s = ""; for (i = 4; i <= NF; i++) s = s $i " "; print s }' | tr ", " "\n" | grep open | grep udp | cut -d "/" -f 1 | sort -nu | paste -s -d, - )

#Final scan full connect and service reconnaissance if<>fi sentece to handle empty strings and keep command integrity
if [ -z "${TCPPORTS}" ]; then
    NMAPSCAN="nmap -sT -sV -O -A -p T:22,80,443,U:137,161,"$UDPPORTS" $TARGET -oA "$NAME"/nmap_FullScan_"$NAME""
else
	NMAPSCAN="nmap -sT -sV -O -A -p T:22,80,443,"$TCPPORTS",U:137,161,"$UDPPORTS" $TARGET -oA "$NAME"/nmap_FullScan_"$NAME""
fi
echo $NMAPSCAN
eval $NMAPSCAN