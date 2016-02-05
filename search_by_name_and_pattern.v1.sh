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
#NAME=`${DATE} '+%Y%m%d-%H%M%S'`
NAME=`${DATE} '+%Y%m%d'`
IP=""
PRINTF="/usr/bin/printf"
PS="/bin/ps"
CUT="/usr/bin/cut"
TR="/usr/bin/tr"
TAIL="/usr/bin/tail"
BASENAME="/usr/bin/basename"
RM="/bin/rm"
# ----------------------------------------------------------------------
FILE="TODO"
PID=`${PS} -ef | ${GREP} $0 | ${TR} -s " " " " | ${CUT} -d " " -f 3 | ${TAIL} -n 1` 
SNAME="$(${BASENAME} $0)"
# ----------------------------------------------------------------------
if [ -e "/tmp/${SNAME}.pid" ]; then
	${ECHO}
	${ECHO} previous process has an abnormal execution
	${ECHO} please review the log files for further information on the error
	${ECHO}
	exit 0
else 
	${ECHO} ${PID} > /tmp/${SNAME}.pid
fi
# ----------------------------------------------------------------------
for Ax in {a..z}
do
    for Bx ia {b..z}
	do
		for Cx in {a..z}
		do
			PATTERN="${Ax}${Bx}${Cx}"
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
		done
	done
done
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
				${ECHO} "scanning (${IP})" >> "${NAME}_${SNAME}.log"
				scan_ip
			fi
		fi
done
# ----------------------------------------------------------------------
${RM} /tmp/${SNAME}.pid
${RM} ${NAME}_${SNAME}.log
