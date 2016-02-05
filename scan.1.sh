#!/bin/bash 
IFCOMMAND="/sbin/ifconfig"
NETCOMMAND="/bin/netstat"
PING="/bin/ping"
ARP="/usr/sbin/arp"
EXPR="/usr/bin/expr"
GREP="/bin/grep"
TR="/usr/bin/tr"
CUT="/usr/bin/cut"
AWK="/usr/bin/awk"
ECHO="/bin/echo" 

VERBOSE=0
NUMPING=1
TWAIT=1
SIZE=1
IFCONFIG=`${IFCOMMAND} -a`
NETIFAZ=`${NETCOMMAND} -i | ${GREP} -v lo | ${GREP} -vE 'Kernel|Iface|Tabla' | ${TR}  -s " " " " | ${CUT} -d " " -f 1`
FILE=`date '+%Y%m%d-%H%M%S'`
FILE="${FILE}_NETDISCOVER"


ip(){
    IPHOST=`${EXPR} ${HOST} + ${NETADDRESSN}` 
    IPA=`${EXPR} ${IPHOST} / 16777216`
    AUX=`${EXPR} ${IPHOST} % 16777216`
    IPB=`${EXPR} ${AUX} / 65536` 
    AUX=`${EXPR} ${AUX} % 65536`
    IPC=`${EXPR} ${AUX} / 256`
    IPD=`${EXPR} ${AUX} % 256`
    IP="${IPA}.${IPB}.${IPC}.${IPD}"
    ${PING} -n -c ${NUMPING} $IP -w ${TWAIT} -s ${SIZE}| ${ARP} -an | ${GREP} -vE "incomplete|incompleto" | ${GREP} "(${IP})"  | ${TR}  -s "(" " " |  ${TR}  -s ")" " " | ${CUT} -d" " -f 2,4 | ${AWK} '{ print "\n"$1"|"$2"\n"}'
}

bucleip ()
{
        NUMHOST=`${EXPR} ${NETBRDCASTN} - ${NETADDRESSN}`
        HOST=0
        ${ECHO} "!"
	  while [ ${HOST} -lt ${NUMHOST} ]; do
            let HOST=$HOST+1
            ${ECHO} -n "#"
            ip
        done
        if [ VERBOSE -gt 0  ]
        then
            ${ECHO} "#"
        fi            
}

for line in ${NETIFAZ}; 
do
    RESULTADO=`${IFCOMMAND} ${line} | ${GREP} -E "(inet addr|Direc. inet)"`
    IPA=`${ECHO} ${RESULTADO}  | ${TR}  -s " " " " | ${CUT} -d " " -f 3 | ${CUT} -d: -f 2 | ${CUT} -d. -f 1`
    NETBRDCAST=`${ECHO} ${RESULTADO}  | ${TR}  -s " " " " | ${CUT} -d " " -f 3 | ${CUT} -d: -f 2 `
    if [ "${IPA}" = "" ] 
    then
        ${ECHO} $line NO
    else
        ${ECHO} "Checking $line ..."
        NETADDRESS=`${NETCOMMAND} -rnt | ${GREP} ^${IPA} | ${GREP} ${line} | ${TR}  -s " " " " | ${CUT} -d " " -f 1`
        NETADDRESSN=`${ECHO} ${NETADDRESS} | ${TR}  -s "." " " | ${AWK} '{printf "%d",  $1*16777216+$2*65536+$3*256+$4}'`
	  NETBRDCASTN=`${ECHO} ${NETBRDCAST} | ${TR}  -s "." " " | ${AWK} '{printf "%d",  $1*16777216+$2*65536+$3*256+$4}'`        
        NETMASK=`${NETCOMMAND} -rnt | ${GREP} ^${IPA} | ${GREP} ${line} | ${TR}  -s " " " " | ${CUT} -d " " -f 3`
        NETMASKN=`${ECHO} ${NETMASK} | ${TR}  -s "." " " | ${AWK} '{printf "%d",  $1*16777216+$2*65536+$3*256+$4}'`
        ${ECHO} "$line: ${NETADDRESS}|${NETADDRESSN}|${NETBRDCAST}|${NETBRDCASTN}|${NETMASK}|${NETMASKN}" 
        bucleip
    fi
done
