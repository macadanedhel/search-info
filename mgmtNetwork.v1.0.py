#!/usr/bin/env python 
# -*- coding: utf-8 -*-

import os, sys, csv, re

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

import argparse
import struct
import socket
import netaddr
import graphviz as gv
import random
import fcntl
import struct
import datetime

#----------------------------------------------------------------------
struct_icmp_type = {
    0: 'Echo Reply',
    1: 'Unassigned',
    2: 'Unassigned',
    3: 'Destination Unreachable',
    4: 'Source Quench',
    5: 'Redirect',
    6: 'Alternate Host Address',
    6: 'Alternate Host Address',
    7: 'Unassigned',
    8: 'Echo',
    9: 'Router Advertisement',
    10: 'Router Selection',
    11: 'Time Exceeded', 
    12: 'Parameter Problem',   
    13: 'Timestamp',
    14: 'Timestamp Reply',
    15: 'Information Request', 
    16: 'Information Reply',
    17: 'Address Mask Request',
    18: 'Address Mask Reply',
    19: 'Reserved (for Security)',
    30: 'Traceroute',
    31: 'Datagram Conversion Error',
    32: 'Mobile Host Redirect',    
    33: 'IPv6 Where-Are-You', 
    34: 'IPv6 I-Am-Here',
    35: 'Mobile Registration Request',   
    36: 'Mobile Registration Reply',
    37: 'Domain Name Request',
    38: 'Domain Name Reply',  
    39: 'SKIP',  
    40: 'Photuris'
}
struct_icmp_code_list = [ 3, 5, 11, 12]
struct_icmp_code = {
    3 : {  
            0: 'Net Unreachable',
            1: 'Host Unreachable',
            2: 'Protocol Unreachable',
            3: 'Port Unreachable',
            4: 'Fragmentation Needed and Don\'t Fragment was Set',
            5: 'Source Route Failed',
            6: 'Destination Network Unknown',
            7: 'Destination Host Unknown',
            8: 'Source Host Isolated',
            9: 'Communication with Destination Network is Administratively Prohibited',
           10: 'Communication with Destination Host is Administratively Prohibited',
           11: 'Destination Network Unreachable for Type of Service',
           12: 'Destination Host Unreachable for Type of Service',
           13: 'Communication Administratively Prohibited',
           14: 'Host Precedence Violation',
           15: 'Precedence cutoff in effect'
        },
    5: {
            0: 'Redirect Datagram for the Network (or subnet)',
            1: 'Redirect Datagram for the Host',
            2: 'Redirect Datagram for the Type of Service and Network',
            3: 'Redirect Datagram for the Type of Service and Host '
        }, 
    11: {
            0: 'Time to Live exceeded in Transit',
            1: 'Fragment Reassembly Time Exceeded'
        },
    12: {
        0: 'Pointer indicates the error',
        1: 'Missing a Required Option',
        2: 'Bad Length'
        }
    }
#---------------------------------------------------------------------

#----------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description ='Process some file.',
    epilog      = 'comments > /dev/null'
)
parser.add_argument('--fVLAN',  '-vf', type=str, help='a VLAN file')
parser.add_argument('--fNI', '-nf', type=str, help='a [ server names|ip address ] file')
parser.add_argument('--fhosts',  '-fh', type=str, help='a Boxes file')
parser.add_argument('--TTL',  '-t', type=str, help='Waiting response')
parser.add_argument('--HOPS',  '-o', type=str, help='Hops')
parser.add_argument('--test', '-tx',  action='store_true', help='Show the paths')
parser.add_argument('--verbose', '-v', action='store_true', help='More data')
parser.add_argument('--moreverbose', '-vv', action='store_true', help='More data')
parser.add_argument('--log', '-lg', action='store_true', help='More data')
parser.add_argument('--morelog', '-llg', action='store_true', help='More data')
parser.add_argument('--graphviz', '-g', action='store_true', help='a graphviz output')
parser.add_argument('--noresolve', '-n', action='store_true', help='a graphviz output')
parser.add_argument('--label', '-l', action='store_true', help='a graphviz output')
parser.add_argument('--CHECK', '-c', type=str, help='a simple tcptraceroute with port 23')
parser.add_argument('--PORT', '-p', type=str, help='port to check in other options')
parser.add_argument('--WAIT', '-w', type=str, help='Number of hops failed to stop')


#----------------------------------------------------------------------
VERBOSE=0
SVERBOSE=0
TTL=1
HOPS=30
FASTER=None
PORT=23
GRAPHVIZ=None
WAITUNTIL=5
GlobalNetworks = []
LABEL=False
LOG=False
MORELOG=False
#----------------------------------------------------------------------

#----------------------------------------------------------------------
def name_time():
    name=datetime.datetime.now()
    return name.strftime("%Y%m%d_%H%M%S")
#----------------------------------------------------------------------
def write_log( string ):
    cadena= str(datetime.datetime.now().isoformat(' '))+"\t"+string
    target.write (cadena+"\n")
#----------------------------------------------------------------------
def get_lan_ip():
    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(
                fcntl.ioctl(s.fileno(), 0x8915,
                struct.pack('256s',ifname[:15]))[20:24])
    ip = socket.gethostbyname(socket.gethostname())

    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass

    return ip
#-----------------------------------------------------------------------
def lookupName( NAME ):
    hostname = NAME.strip()
    ipaddr = None
    try:
        ipaddr = socket.gethostbyname(hostname)
    except socket.error:
        ipaddr = None
    return ipaddr
#-----------------------------------------------------------------------
def lookup( IPADDR ):
    hostname = None
    ipaddr = IPADDR.strip()
    try:
        hostname = socket.gethostbyaddr(ipaddr)[0]
    except socket.error:
        hostname = None
    return hostname
#----------------------------------------------------------------------
def udptracepath (host, port):
    dest_addr = host
    port = port
    max_hops = 10
    route = []
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1
    while True:
        if VERBOSE == "1":
            print "ttl:",ttl,
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_socket.bind(("", port))
        send_socket.sendto("", (dest_addr, port))
        curr_addr = None
        curr_name = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]

            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = "*"

        if VERBOSE:
            print "ttl(%d)\t%s" % (ttl, curr_host)
        else:
            print "#",
        print "eof"

        if  curr_host != "*":
            route.append (curr_addr)

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break
    return route
#-----------------------------------------------------------------------
def IP_ICMP_mgmt (packet, TTL):
    # -----------------------------------
    # MGMT IP
    # -----------------------------------

    eth_length = 0
    ip_header = packet[eth_length:20+eth_length]
    
    #now unpack them :)
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    # Para controlar los icmps que se han lanzado anteriormente por parte de algun router
    # hago un trapi, veo que lo normal es 255 - el numero de salto
    # 255 en ttl=1, 254 en ttl=2 ...
    # Luego 255-(ttl-1) = al valor que deber devolver un router
    # si aparece en ttl 6 -> 255 - (6-1) = 250, un ttl 254, es un "resto"
    # del traceroute anterior y lo descarto
    # tendremos problemas con los configurados con ttl arbitrarios

    TTLcal = 255 - ( TTL - 1 )
    ttl = iph[5]

    if ttl > 255 and ttl > TTLcal:
        if MORELOG:
            write_log ( 'DISCARD PACKET : ' + 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr) + ' Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr) )
        return "*"

    ############# FIN DEL TRAPI ###############
    
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);

    #print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
    if VERBOSE:
        print ' TTL : ' + str(ttl) + ' Source Address : ' + str(s_addr) + ' ',
    
    # -----------------------------------
    # MGMT ICMP
    # -----------------------------------

    u = iph_length 
    icmph_length = 4
    icmp_header = packet[u:u+4]

    #now unpack them :)
    icmph = struct.unpack('!BBH' , icmp_header)
    
    icmp_type = icmph[0]
    code = icmph[1]  
    checksum = icmph[2]
    
    #print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
    if icmp_type in struct_icmp_code_list:
        code = struct_icmp_code[icmp_type][code]

    if VERBOSE:
        print 'Type : ' + struct_icmp_type[icmp_type] + ' Code : ' + str(code) + ' ',

    #h_size = eth_length + iph_length + icmph_length
    #data_size = len(packet) - h_size
    
    #get data from the packet
    #data = packet[h_size:]
    #print 'Data : ' + data
    if MORELOG:
       write_log ( 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr) + ' ICMP Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum) )
    
    return s_addr+str(ttl)+str(icmp_type)+str(code)    
#-----------------------------------------------------------------------
def showFile( FILE ):
    data_list = []
    with open(FILE) as csvfile:
        #networkdata = csv.reader(csvfile, delimiter='\t')
        reader = csv.DictReader(csvfile, delimiter='\t')
        for row in reader:
            #print(row['VLAN ID'], row['VLAN ID de BRS'], row['Nombre de VLAN'], 
            #row['Red'], row['Bits Máscara'], row['Extendida/VLAN Proveedor'], 
            #row['TC'], row['GCC'], row['VG'], row['Gateway'], row['observaiones'])
            AUX = 'TC'
            if (row['TC'].upper) == 'NO':
                AUX='VG'
            data_list.append ( { 
                'vlanid':row['VLAN ID'],
                'name':row['Nombre de VLAN'],
                'netipaddres':row['Red'],
                'mask':row['Bits Máscara'],
                'src':AUX,
                'gateway':row['Gateway'],
                'comments':row['observaiones'] })
    return data_list
#-----------------------------------------------------------------------
def tcptracepath (hostname, host, port):
    dest_addr = host
    port = port
    max_hops = 10
    route = []
    dest_addr = host
    port = port
    max_hops = 10
    icmp = socket.getprotobyname('icmp')
    tcp = socket.getprotobyname('tcp')
    ttl = TTL
    ttl_top = HOPS
    old_message = None
    waituntil = WAITUNTIL
    patience = 0
    curr_host = "%s (%s)" % (hostname, host)
    aux=None
    
    for ttl in range(1, ttl_top):

        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        recv_socket.settimeout(2)
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM, tcp)
        s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        s.settimeout(2)

        curr_addr = None
        curr_name = None
        err = None
        
        try:
            try:
                s.connect((host, port))
            except (socket.error, socket.timeout), msg:
                err = None
                if VERBOSE:
                        print 'ttl=%02d: %s ' % (ttl, msg),
                        if LOG or MORELOG:
                            write_log ( "ttl={0}: {1}".format (ttl, msg) )
                if re.findall('111', str(msg)):
                    err = 111
                    curr_addr = host
                else:
                    try:
                        recv_socket.bind(("", port))
                        packet, curr_addr = recv_socket.recvfrom(1508)
                        curr_addr = curr_addr[0]
                        aux = IP_ICMP_mgmt(packet, ttl)
                        if aux == "*":
                            curr_addr = "*"
                    except socket.timeout:
                        curr_addr = "*"
                        
                if not FASTER:
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = curr_addr
                else:
                    curr_name = curr_addr
                if curr_addr is not None and err != 111:
                    curr_host = "%s (%s)" % (curr_name, curr_addr)
                    if curr_addr == "*":
                        curr_addr = "{0}_*".format( ttl )
                        curr_name = curr_addr
                    route.append ({ 'name': curr_name,
                                    'ipaddr':curr_addr})
                else:
                    curr_host = "*"
                
                if err == 111:
                    curr_host = "%s (%s)" % (curr_name, curr_addr)
                    print "\n\nttl(%d)\t%s OK !!! but reject\n\n" % (ttl, curr_host)
                    if LOG or MORELOG:
                        write_log ( "ttl({0})\t{1} OK !!! but reject".format (ttl, curr_host) )  
                    route.append ({
                        'name': curr_name ,
                        'ipaddr': curr_addr,
                        'status': "REJECT",
                        'port': port
                    })                    
                    break

                print "ttl(%d)\t%s" % (ttl, curr_host)
                if LOG:
                    write_log ( "ttl(%d)\t%s".format (ttl, curr_host) )
                if aux != old_message:
                    old_message = aux
                else:
                    patience = patience +1
                    
                if int(patience) == int(waituntil):
                    print "Fail!!!\n\n"
                    if LOG or MORELOG:
                        write_log ( "Fail !!!" )
                    #route.append ({'name':"unknown",'ipaddr':"0.0.0.0"})
                    route.append ({'name':hostname,'ipaddr':host})
                    break
                else:
                    continue
            except KeyboardInterrupt:
                print '2.- ttl=%02d (KeyboardInterrupt)' % ttl
                break
            if not FASTER:
                try:
                    curr_name = socket.gethostbyaddr(host)[0]
                except socket.error:
                    continue
            if (hostname==  None) and (curr_name == None):
                curr_name = host
            else:
                curr_name = hostname
            route.append ({
                        'name': curr_name ,
                        'ipaddr': host,
                        'status': "OK",
                        'port': port
                    })   
            curr_host = "%s (%s)" % (curr_name, host)
        finally:
            s.close()
            recv_socket.close()
        print "\n\nttl(%d)\t%s OK !!!\n\n" % (ttl, curr_host)
        if LOG or MORELOG:
            write_log ( "ttl({0})\t{1} OK !!!".format (ttl, curr_host) )
        break
    return route
#-----------------------------------------------------------------------
def SimpleFileTraceroute(file, port):
    route=[]
    cont=0;
    with open(file) as csvfile:
        fieldnames = ['name', 'ipaddr']
        networkdata = csv.DictReader(csvfile, fieldnames=fieldnames)
        for row in networkdata:
            print('\nChecking the box [{0}] with ip address :{1} and port {2}/tcp' ).format(row['name'], row['ipaddr'],port)
            if LOG:
                write_log ( "Checking the box [{0}] with ip address :{1} and port {2}/tcp".format(row['name'], row['ipaddr'],port) )
            route.append (tcptracepath ( row['name'], row['ipaddr'], port ))    
    return route
#-----------------------------------------------------------------------
def graphviz_base (graph,dot,myip):
    dot.attr('node', shape='box',fontsize='10', fontname='arial')
    dot.node (myip, myip)
    dot.attr('node', shape='circle',fontsize='10', fontname='arial')
    dot.attr('edge', fontsize='5', fontname='arial')
    src=myip
    aux = []
    cont=0
    numele=0
    _Label=""
    fail = False
    for node in graph:
        if SVERBOSE:
            print "[{0}][{1}]".format(node['ipaddr'],node['name'])
        if re.findall ( "\d+_\*", node['ipaddr'] ):
            if cont == 0:
                nodeJ=src
            # Esta lista es para cuando encuentres un sistema que responda tras ssaltos sin contestar
            aux= ([node['ipaddr'], node['name'],src])
            cont=cont+1
        else:
            if numele==len(graph):
                dot.attr('node', shape='doublecircle',style='filled', color='green')
                print node['ipaddr'], node['name'],
                print node['status'], node['port'],
                dot.node (node['ipaddr'], node['name'])
                if LABEL:
                    _Label=node['ipaddr']
                dot.edge (src,node['ipaddr'],node['ipaddr'])
            else:
                if 'status' in node :
                    if node['status'] == "OK":
                        dot.attr('node', shape='doublecircle',style='filled', color='green')
                    elif node['status'] == "REJECT":
                        dot.attr('node', shape='doublecircle',style='filled', color='red')
                if SVERBOSE:
                    print  (src,"->",node['ipaddr'], node['name'])
                dot.node (node['ipaddr'], node['name'])
                if LABEL:
                    _Label=node['ipaddr']
                dot.edge (src,node['ipaddr'],node['ipaddr'])
                if fail:
                    dot.attr('node', shape='box',style='filled', color='white', fontcolor ='black')
                    
        src=myip
        src=node['ipaddr']
        numele=numele+1;
        if int(cont)==int(WAITUNTIL):
            dot.attr('node', shape='box',style='filled', color='grey')
            dot.node ('0.0.0.0', 'FAIL')
            if LABEL:
                _Label="..."
            if SVERBOSE:
                print  (nodeJ,"|->",'0.0.0.0','FAIL')
            dot.edge (nodeJ,'0.0.0.0','FAIL',_Label )
            src="0.0.0.0"
            dot.attr('node', shape='box',style='filled', color='black', fontcolor ='white')
            fail=True
            cont=0
    return dot
#-----------------------------------------------------------------------
def graphviz_network_simple (graph,ip):
    myip = get_lan_ip()
    dot  = gv.Digraph(comment='The Round Table')
    dot  = graphviz_base ( graph, dot, myip  )
    dot.format = 'svg'
    name="net_{0}_{1}".format(ip,name_time())
    dot.render(name, view=True) 
#-----------------------------------------------------------------------
def graphviz_network_multiple (graph, filename):
    myip = get_lan_ip()
    dot  = gv.Digraph(comment='The Round Table')
    for subgraph in graph:
        dot  = graphviz_base ( subgraph, dot, myip  )
    dot.format = 'svg'
    name="net_{0}_{1}".format(filename,name_time())
    dot.render(name, view=True) 
#-----------------------------------------------------------------------     
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------


args = parser.parse_args()



if args.verbose:
    VERBOSE=1
if args.moreverbose:
    SVERBOSE=1
if args.TTL:
    TTL=int(args.TTL)
if args.label:
    LABEL=True
if args.HOPS:
    HOPS=int(args.TTL)
if args.noresolve:
    FASTER=True 
if args.PORT:
   PORT=int(args.PORT)
if args.graphviz:
   GRAPHVIZ=True
if args.WAIT:
      WAITUNTIL=args.WAIT

if args.log or args.morelog:
    filename =  "log_mgmtND_{0}.log".format(name_time())
    global target
    target = open(filename, 'w')
    if args.log:
        LOG=True
    if args.morelog:
        MORELOG=True

if args.fNI and os.path.exists(args.fNI):
    filename =  "Discover_data_{0}.log".format(name_time())
    global target
    target = open(filename, 'w')
    with open(args.fNI) as filedata:
        for row in filedata:
            if VERBOSE:
                print "Read [{0}]".format( row )
            if re.findall( "(\d{1,3}\.\d{1,3}\.\d{1,4}\.\d{1,3})", row):
                 print 0
                 ipaddr = row.strip()
                 name = lookup ( row )
            else:
                print 1
                name = row.strip()
                ipaddr = lookupName ( row )
            print "Name: {0}\tIPaddr: {1}".format ( name, ipaddr ) 
            write_log ( "{0},{1}".format ( name, ipaddr ) )
    filedata.close()
    target.close()
if VERBOSE:      
    print "\n\nverbose:\t{0}\nTTL:\t{1}\nHOPS:\t{2}".format(VERBOSE,TTL,HOPS)
    print "faster:\t{0}\nport:\t{1}\nwait:\t{2}".format(FASTER,PORT,WAITUNTIL)
    print "Label:\t{0}\tLOG:\t{1}\tMORELOG:\t{2}\n\n\n".format(LABEL,LOG,MORELOG)

if LOG:
    write_log ( "verbose:\t{0}\tTTL:\t{1}\tHOPS:\t{2}".format(VERBOSE,TTL,HOPS))
    write_log ( "faster:\t{0}\tport:\t{1}\twait:\t{2}".format(FASTER,PORT,WAITUNTIL))
    write_log ( "Label:\t{0}\tLOG:\t{1}\tMORELOG:\t{2}\n\n\n".format(LABEL,LOG,MORELOG))
    
if args.fVLAN and os.path.exists(args.fVLAN):
    GlobalNetworks = showFile(args.fVLAN)
    route=[]
    for i in GlobalNetworks:
        if i['gateway']:
            name = lookup(i['gateway'])[0]
            print('\nChecking the box [{0}] with ip address :{1} and port {2}/tcp' ).format(name, i['gateway'],PORT)
            if LOG:
                write_log ( "Checking the box [{0}] with ip address :{1} and port {2}/tcp".format(name, i['gateway'],PORT) )

            route.append (tcptracepath ( name, i['gateway'], PORT ))
    if GRAPHVIZ:
        graphviz_network_multiple ( route, args.fVLAN )  


if args.CHECK:
    curr_name=None
    if not FASTER:
        try:
            curr_name = socket.gethostbyaddr(args.CHECK)[0]
        except socket.error:
            curr_name = args.CHECK
    route=tcptracepath (curr_name, args.CHECK,PORT )
    if GRAPHVIZ:
        graphviz_network_simple ( route,args.CHECK )  

if args.fhosts and os.path.exists(args.fhosts):
    route=SimpleFileTraceroute (args.fhosts, PORT)
    if GRAPHVIZ:
        graphviz_network_multiple ( route )  

if args.log or args.morelog:
    target.close()
