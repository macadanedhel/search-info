#!/bin/bash 

RESULTSPATH="./results/"
VERBOSE=0
DNS_ONLY=""
ECHO="/bin/echo" 
NSLOOKUP="/usr/bin/nslookup"
GREP="/bin/grep"
TR="/usr/bin/tr"
CUT="/usr/bin/cut"
AWK="/usr/bin/awk"
NMAP="/usr/bin/nmap"
DATE="/bin/date"
MKDIR="/bin/mkdir"
PRINTF="/usr/bin/printf"
PS="/bin/ps"
CUT="/usr/bin/cut"
TR="/usr/bin/tr"
TAIL="/usr/bin/tail"
BASENAME="/usr/bin/basename"
RM="/bin/rm"
# ----------------------------------------------------------------------
#NAME=`${DATE} '+%Y%m%d-%H%M%S'`
NAME=`${DATE} '+%Y%m%d'`
IP=""
FILE="TODO"
PID=`${PS} -ef | ${GREP} $0 | ${TR} -s " " " " | ${CUT} -d " " -f 3 | ${TAIL} -n 1` 
SNAME="$(${BASENAME} $0)"

# ----------------------------------------------------------------------
show_help(){
	${ECHO}
	${ECHO} "-h|?         show this"
	${ECHO} "-s           scan an ip address"
	${ECHO} "-p <pattern> search a pattern name"
	${ECHO} "-f <file>    search in DNS and check 22 port names from a file"
	${ECHO} "-d <file>    search in DNS names from a file"
	${ECHO} "-i <file>    check 22,25,80,443 ip addresses from a file"
	${ECHO}
	exit 0
}
# ----------------------------------------------------------------------
create_results_directory (){
	if [ -d ${RESULTSPATH} ]; then
			${ECHO} ${RESULTSPATH} exists !!!
		else
			${MKDIR} ${RESULTSPATH}
	fi
}
# ----------------------------------------------------------------------
read_file(){
	while read line
	do
		box=$line
		${ECHO} "scanning [${box}]"
		IP=`${NSLOOKUP} ${box} | ${GREP} Address | ${GREP} -v "#" | ${CUT} -d: -f 2 | ${CUT} -d" " -f 2`
		if [ -n "${IP}" ]; then
			${ECHO} "${box} -> (${IP})"
			${ECHO} "${box},${IP}" >> ${RESULTSPATH}${FILE}_results.csv
			if [ -n "${DNS_ONLY}" ]; then
    			${ECHO} "scanning (${IP})"
    			scan_ip
    		fi
    	fi
	done < ${FILE}
}
# ----------------------------------------------------------------------
read_file_ip(){
	while read line
	do
		IP=${line}
		${ECHO} "scanning [${IP}]"
		box=`${NSLOOKUP} ${IP} | ${GREP} = | ${TR} -s " " " " | ${CUT} -d" " -f 3 `
		${ECHO} "${box} -> (${IP})"
		scan_ip
	done < ${FILE}
}
# ----------------------------------------------------------------------
scan_ip (){
	${ECHO} checking ${IP}
	#${NMAP}  -p22 -sV -oX ${RESULTSPATH}${NAME}_${IP}.xml ${IP}
	${NMAP}  -p22,23,25,80,443 -Pn -sV -oX ${RESULTSPATH}${NAME}_${IP}.xml ${IP}
	
}
# ----------------------------------------------------------------------
transformPattern_file (){
	FILE=${PATTERN}
	for i in `seq 1 999`;
    do
# ------------------ PATTERN 2 SEARCH ----------------------------------
		box=`${PRINTF} "${PATTERN}%03d" ${i}`
# ------------------ PATTERN 2 SEARCH ----------------------------------
			${ECHO} "scanning [${box}]"
			IP=`${NSLOOKUP} ${box} | ${GREP} Address | ${GREP} -v "#" | ${CUT} -d: -f 2`
			if [ -n "${IP}" ]; then
				${ECHO} "${box} -> ${IP}"
				${ECHO} "${box},${IP}" >> ${RESULTSPATH}${FILE}_results.csv
				if [ -n "${DNS_ONLY}" ]; then
					${ECHO} "scanning (${IP})"
					scan_ip
				fi
			fi
    done

	}
# ----------------------------------------------------------------------
find_process (){
	if [ -e "/tmp/${SNAME}.pid" ]; then
		${ECHO}
		${ECHO} previous process has an abnormal execution
		${ECHO} please review the log files for further information on the error
		${ECHO}
		exit 0
	else 
		${ECHO} ${PID} > /tmp/${SNAME}.pid
	fi
}
# ----------------------------------------------------------------------
exit_cero (){
	${RM} /tmp/${SNAME}.pid
	${RM} ${NAME}_${SNAME}.log
}
# ----------------------------------------------------------------------
# ----------------------------------------------------------------------
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------

find_process
while getopts "h?s:f:d:p:i:" opt; do
    case "$opt" in
    h|\?)
        show_help
       	;;
    v)  VERBOSE=1
        ;;
    s)  IP=$OPTARG
    	create_results_directory
		scan_ip
		exit_cero 
        ;;
     d) FILE=$OPTARG
     	create_results_directory
     	read_file
     	exit_cero
     	;;
   	 f) FILE=$OPTARG
     	create_results_directory
     	DNS_ONLY="false"
     	read_file
     	exit_cero
     	;;
     p) PATTERN=$OPTARG
     	create_results_directory
     	transformPattern_file
     	exit_cero
     	;;
   	 i) FILE=$OPTARG
     	create_results_directory
     	DNS_ONLY="false"
     	read_file_ip
     	exit_cero
     	;;
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift

show_help



# End of file

