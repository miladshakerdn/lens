#!/bin/bash  -
#===============================================================================
#
#          FILE: cfFindIP.sh
#
#         USAGE: ./cfFindIP.sh [ThreadCount]
#
#   DESCRIPTION: Scan all 1.5 Mil CloudFlare IP addresses
#
#       OPTIONS: ---
#  REQUIREMENTS: ThreadCount (integer Number which defines the parallel processes count)
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Morteza Bashsiz (mb), morteza.bashsiz@gmail.com
#  ORGANIZATION: Linux
#       CREATED: 01/24/2023 07:36:57 PM
#      REVISION:  1 by Nomad
#===============================================================================

set -o nounset                                  # Treat unset variables as an error

# Check if 'parallel', 'timeout', 'nmap' and 'bc' packages are installed
# If they are not,exit the script
if [[ "$(uname)" == "Linux" ]]; then
    command -v parallel >/dev/null 2>&1 || { echo >&2 "I require 'parallel' but it's not installed. Please install it and try again."; exit 1; }
    command -v nmap >/dev/null 2>&1 || { echo >&2 "I require 'nmap' but it's not installed. Please install it and try again."; exit 1; }
    command -v bc >/dev/null 2>&1 || { echo >&2 "I require 'bc' but it's not installed. Please install it and try again."; exit 1; }
		command -v timeout >/dev/null 2>&1 || { echo >&2 "I require 'timeout' but it's not installed. Please install it and try again."; exit 1; }

elif [[ "$(uname)" == "Darwin" ]];then
    command -v parallel >/dev/null 2>&1 || { echo >&2 "I require 'parallel' but it's not installed. Please install it and try again."; exit 1; }
    command -v nmap >/dev/null 2>&1 || { echo >&2 "I require 'nmap' but it's not installed. Please install it and try again."; exit 1; }
    command -v bc >/dev/null 2>&1 || { echo >&2 "I require 'bc' but it's not installed. Please install it and try again."; exit 1; }
    command -v gtimeout >/dev/null 2>&1 || { echo >&2 "I require 'gtimeout' but it's not installed. Please install it and try again."; exit 1; }
fi

threads="$1"
config="$2"

# Check if the user entered the number of threads
if [[ -z "$threads" ]]
then
	echo "Please enter the number of threads"
	exit 1
fi

# check https://asnlookup.com/asn/AS209242/ for the latest CloudFlare ASN
cloudFlareASNList=( AS209242 )
# cloudFlareASNList=( AS209242 AS13335 AS1333 AS1334 AS1335 AS1336 AS1337 AS1338 AS1339 AS1340 AS1341 AS1342 AS1343 AS1344 AS1345 AS1346 AS1347 AS1348 AS1349 AS1350 AS1351 AS1352 AS1353 AS1354 AS1355 AS1356 AS1357 AS1358 AS1359 AS1360 AS1361 AS1362 AS1363 AS1364 AS1365 AS1366 AS1367 AS1368 AS1369 AS1370 AS1371 AS1372 AS1373 AS1374 AS1375 AS1376 AS1377 AS1378 AS1379 AS1380 AS1381 AS1382 AS1383 AS1384 AS1385 AS1386 AS1387 AS1388 AS1389 AS1390 AS1391 AS1392 AS1393 AS1394 AS1395 AS1396 AS1397 AS1398 AS1399 AS1400 AS1401 AS1402 AS1403 AS1404 AS1405 AS1406 AS1407 AS1408 AS1409 AS1410 AS1411 AS1412 AS1413 AS1414 AS1415 AS1416 AS1417 AS1418 AS1419 AS1420 AS1421 AS1422 AS1423 AS1424 AS1425 AS1426 AS1427 AS1428 AS1429 AS1430 AS1431 AS1432 AS1433 AS1434 AS1435 AS1436 AS1437 AS1438 AS1439 AS1440 AS1441 AS1442 AS1443 AS1444 AS1445 AS1446 AS1447 AS1448 AS1449 AS1450 AS1451 AS1452 AS1453 AS1454 AS1455 AS1456 AS1457 AS1458 AS1459 AS1460 AS1461 AS1462 AS1463 AS1464 AS1465 AS1466 AS1467 AS1468 AS1469 AS1470 AS1471 AS1472 AS1473 AS1474 AS1475 AS1476 AS1477 AS1478 AS1479 AS1480 AS1481 AS1482 AS1483 AS1484 AS1485 AS1486 AS1487 AS1488 AS1489 AS1490 AS1491 AS1492 AS1493 AS1494 AS1495 AS1496 AS1497 AS1498 AS1499 AS150 )
cloudFlareOkList=(31 45 66 80 89 103 104 108 141 147 154 159 168 170 185 188 191 192 193 194 195 199 203 205 212)
# get the current date and time
now=$(date +"%Y%m%d-%H%M%S")
# get the script directory
scriptDir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# get the result directory
resultDir="$scriptDir/../result"
# get the result directory
resultFile="$resultDir/$now-result.cf"
# get the config directory
configDir="$scriptDir/../config"

# initialize the config variables
configId="NULL"
configHost="NULL"
configPath="NULL"
configServerName="NULL"

# Check if config file exists
if [[ -f "$config" ]]
then
	# read the config file
	echo "reading config ..."
	# get the config id
	configId=$(grep "^id" "$config" | awk -F ":" '{ print $2 }' | sed "s/ //g")
	# get the config host, v2ray server ip or domain
	configHost=$(grep "^Host" "$config" | awk -F ":" '{ print $2 }' | sed "s/ //g")
	# get the config path
	configPath=$(grep "^path" "$config" | awk -F ":" '{ print $2 }' | sed "s/ //g")
	# get the config server name, its random string and used for domain fronting
	configServerName=$(grep "^serverName" "$config" | awk -F ":" '{ print $2 }' | sed "s/ //g")
	# check if config is correct
	if ! [[ "$configId" ]] || ! [[ $configHost ]] || ! [[ $configPath ]] || ! [[ $configServerName ]]
	then
		echo "config is not correct"
		exit 1
	fi
else
	echo "config file does not exist $config"
	exit 1
fi

#check if expected output folder exists and create if it's not availbe
if [ ! -d "$resultDir" ]; then
    mkdir -p "$resultDir"
fi
if [ ! -d "$configDir" ]; then
    mkdir -p "$configDir"
fi

# Function fncCheckSubnet
# Check Subnet
function fncCheckSubnet {
	local ipList scriptDir resultFile timeoutCommand domainFronting
	ipList="$1"
	resultFile="$2"
	scriptDir="$3"
	configId="$4"
	configHost="$5"
	configPath="$6"
	configServerName="$7"
	configDir="$scriptDir/../config"
	# set proper command for linux
	if command -v timeout >/dev/null 2>&1; 
	then
	    timeoutCommand="timeout"
	else
		# set proper command for mac
		if command -v gtimeout >/dev/null 2>&1; 
		then
		    timeoutCommand="gtimeout"
		else
		    echo >&2 "I require 'timeout' command but it's not installed. Please install 'timeout' or an alternative command like 'gtimeout' and try again."
		    exit 1
		fi
	fi
	for ip in ${ipList}
		do
			# timeout 1 bash -c "</dev/tcp/216.120.181.237/443" > /dev/null 2>&1;
			if $timeoutCommand 1 bash -c "</dev/tcp/$ip/443" > /dev/null 2>&1;
			then
				domainFronting=$($timeoutCommand 2 curl -s -w "%{http_code}\n" --tlsv1.2 -servername fronting.sudoer.net -H "Host: fronting.sudoer.net" --resolve fronting.sudoer.net:443:"$ip" https://fronting.sudoer.net -o /dev/null | grep '200')
				if [[ "$domainFronting" == "200" ]]
				then
					ipConfigFile="$configDir/config.json.$ip"
					cp "$scriptDir"/config.json.temp "$ipConfigFile"
					sed -i "s/IP.IP.IP.IP/$ip/g" "$ipConfigFile"
					ipO1=$(echo "$ip" | awk -F '.' '{print $1}')
					ipO2=$(echo "$ip" | awk -F '.' '{print $2}')
					ipO3=$(echo "$ip" | awk -F '.' '{print $3}')
					ipO4=$(echo "$ip" | awk -F '.' '{print $4}')
					port=$((ipO1 + ipO2 + ipO3 + ipO4))
					sed -i "s/PORTPORT/3$port/g" "$ipConfigFile"
					sed -i "s/IDID/$configId/g" "$ipConfigFile"
					sed -i "s/HOSTHOST/$configHost/g" "$ipConfigFile"
					sed -i "s/ENDPOINTENDPOINT/$configPath/g" "$ipConfigFile"
					sed -i "s/RANDOMHOST/$configServerName/g" "$ipConfigFile"
					# shellcheck disable=SC2009
					pid=$(ps aux | grep config.json."$ip" | grep -v grep | awk '{ print $2 }')
					if [[ "$pid" ]]
					then
						kill -9 "$pid"
					fi
					nohup "$scriptDir"/v2ray -c "$ipConfigFile" > /dev/null &
					sleep 2
					timeMil=$($timeoutCommand 2 curl -x "socks5://127.0.0.1:3$port" -s -w "TIME: %{time_total}\n" https://scan.sudoer.net | grep "TIME" | tail -n 1 | awk '{print $2}' | xargs -I {} echo "{} * 1000 /1" | bc )
					# shellcheck disable=SC2009
					pid=$(ps aux | grep config.json."$ip" | grep -v grep | awk '{ print $2 }')
					if [[ "$pid" ]]
					then
						kill -9 "$pid" > /dev/null 2>&1
					fi
					if [[ "$timeMil" ]] 
					then
						echo "OK $ip ResponseTime $timeMil" 
						echo "$timeMil $ip" >> "$resultFile"
					else
						echo "FAILED $ip"
					fi
				else
					echo "FAILED $ip"
				fi
			else
				echo "FAILED $ip"
			fi
	done
}
# End of Function fncCheckSubnet
export -f fncCheckSubnet

echo "" > "$resultFile"

for asn in "${cloudFlareASNList[@]}"
do
	cloudFlareIpList=$(curl -s https://asnlookup.com/asn/"$asn"/ | grep "^<li><a href=\"/cidr/.*0/" | awk -F "cidr/" '{print $2}' | awk -F "\">" '{print $1}' | grep -E -v     "^8\.|^1\.")
	# Examples of commands to get cloudflare ASN list
	# curl -s https://asnlookup.com/asn/AS209242 show all cloudflare ASN
	# output is like this: HTML code 

	# shellcheck disable=SC2086
	for subNet in ${cloudFlareIpList}
	do
		killall v2ray > /dev/null 2>&1
		# make ip list 216.120.180.0/23
		ipList=$(nmap -sL -n "$subNet" | awk '/Nmap scan report/{print $NF}')
		parallel -j "$threads" fncCheckSubnet ::: "$ipList" ::: "$resultFile" ::: "$scriptDir" ::: "$configId" ::: "$configHost" ::: "$configPath" ::: "$configServerName"
		killall v2ray > /dev/null 2>&1
	done
done

sort -n -k1 -t, "$resultFile" -o "$resultFile"
