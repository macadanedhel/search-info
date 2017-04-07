# search-info
Scripts que voy utilizando y esas cosas

## pre-fh.1.sh
Script obsoleto pero por si acaso

Opción|¿Qué hace?
------|-----------
s|Lanza a un host/net un nmap -p22,23,25,80,443 -Pn -sV -oX 
d|nslookup a un fichero de nombres
f|nslookup a un fichero de ips
p|nslookup para un patron numérico
i|nmap pero sin dns

Muy guarro todo, las resoluciones ni siquiera van con el nmap, engendro al que se le han ido añadiendo tontás.

## search_by_name_and_pattern.v1.sh

Script para generar y buscar todos los nombres derivados de un patrón. Tienes que tocar en el código.
Este está bien si peta el ordenador, genera log y fichero de pid para ver si ha habido algún lío

## scan.sh

Script para buscar todos los sistemas derivados de la interfaz de red, sacando mac y todas las ips. En bash, sin privilegios, ping,arp y eso

### mgmtNetworkData.v1.0.py
Dibuja un bonito grafo en plan traceroute ....
```
Opción larga | Opción abreviada | Explicación
--fVLAN fichero |-vf| este es para el fichero ese 
--fNI fichero |-nf| fichero con ip o nombres para buscar en el dns
--TTL numero |-t|que cua
--HOPS numero |-o', type=str, help='Hops')
--test|-tx',  action='store_true', help='Show the paths')
--verbose|-v', action='store_true', help='More data')
--moreverbose|-vv', action='store_true', help='More data')
--log|-lg', action='store_true', help='More data')
--morelog|-llg', action='store_true', help='More data')
--graphviz|-g', action='store_true', help='a graphviz output')
--noresolve|-n', action='store_true', help='a graphviz output')
--label|-l', action='store_true', help='a graphviz output')
--CHECK|-c', type=str, help='a simple tcptraceroute with port 23')
--PORT|-p', type=str, help='port to check in other options')
--WAIT|-w', type=str, help='Number of hops failed to stop')
```
