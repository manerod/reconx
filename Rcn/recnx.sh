# !/bin/bash

RED="\033[0;31m" 		# Error / Issues
GREEN="\033[0;32m"		# Successful       
BOLD="\033[01;01m"    		# Highlight
WHITE="\033[1;37m"		# BOLD
YELLOW="\033[1;33m"		# Warning
LGRAY="\033[0;37m"		# Light Gray
LRED="\033[1;31m"		# Light Red
LGREEN="\033[1;32m"		# Light GREEN
LBLUE="\033[1;34m"		# Light Blue
LPURPLE="\033[1;35m"		# Light Purple
LCYAN="\033[1;36m"		# Light Cyan
SORANGE="\033[0;33m"		# Standar Orange
SBLUE="\033[0;34m"		# Standar Blue
SPURPLE="\033[0;35m"		# Standar Purple      
SCYAN="\033[0;36m"		# Standar Cyan
DGRAY="\033[1;30m"		# Dark Gray


printf "\n"
printf "╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋
╋╋╋╋╋┏━━━┓╋╋╋╋╋╋╋╋┏━┓┏━┓╋╋╋╋╋╋╋╋╋
╋╋╋╋╋┃┏━┓┃╋╋╋╋╋╋╋╋┗┓┗┛┏┛╋╋╋╋╋╋╋╋
╋╋╋╋╋┃┗━┛┣━━┳━━┳━┓╋┗┓┏┛╋╋╋╋╋╋╋╋
╋╋╋╋╋┃┏┓┏┫┃━┫┏━┫┏┓┓┏┛┗┓╋╋╋╋╋╋╋╋
╋╋╋╋╋┃┃┃┗┫┃━┫┗━┫┃┃┣┛┏┓┗╋╋╋╋╋╋╋╋┓
╋╋╋╋╋┗┛┗━┻━━┻━━┻┛┗┻━┛┗━┛╋╋╋╋╋╋╋╋╋
╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋╋"
printf "\n"
printf "\n"




	begin=$(date +"%s")
	now=$(date +"%Y%m%d%H%M%S")
	mkdir -p ~/Desktop/recon/$1/
	cd ~/Desktop/recon/$1/

#1 -Subdomain
	echo -e "${SPURPLE} Url: $1 $2\033[0m" | tee -a salida.txt
	echo -e "${SCYAN}************ Starting Scrapping... ************\033[0m" | tee -a salida.txt

	echo -e "${LGREEN}Doing Amass...\033[0m" | tee -a salida.txt
	amass enum -active -d $1 -o amass$1.txt > /dev/null 2>&1

	echo -e "${LGREEN}Doing Subfinder...\033[0m" | tee -a salida.txt
	subfinder -d $1 -o subfinder$1.txt > /dev/null 2>&1

	echo -e "${LGREEN}Doing Subscraper...\033[0m" | tee -a salida.txt
        cd ~/tools/subscraper && python3 subscraper.py -u $1 -o ~/Desktop/recon/$1/subscraper$1.txt > /dev/null 2>&1
	cd ~/Desktop/recon/$1/

	echo -e "${LGREEN}Doing Github Subdomains...\033[0m" | tee -a salida.txt
        cd ~/tools/github-search  && python3 github-subdomains.py -d $1 |tee -a ~/Desktop/recon/$1/githubsubdomains$1.txt > /dev/null 2>&1
        cd ~/Desktop/recon/$1/

	# junto los resultados, quito dominios que no sirven
	cat amass$1.txt subfinder$1.txt subscraper$1.txt githubsubdomains$1.txt  | grep "\.$1\|^$1" > subdominios$1.txt
	# borro los archivos temporales
	rm -f amass$1.txt subfinder$1.txt subscraper$1.txt githubsubdomains$1.txt  2> /dev/null
	# los ordeno y quito dominios duplicados
	sort -u -o subdominios$1.txt subdominios$1.txt

	if [[ -f subdominios$1.txt && ! -s subdominios$1.txt ]]; then
		echo -e "${SPURPLE}*********** No domains ************\033[0m" | tee -a salida.txt
		echo -e "${SPURPLE}***********************************************\033[0m" | tee -a salida.txt
		return
	fi

#2-Dnsgen
	echo -e "\e[32m\tDnsgen.. \033[0m" | tee -a salida.txt
	dnsgen subdominios$1.txt>dnsgen$1.txt
	cat dnsgen$1.txt | grep "\.$1\|^$1" | sort -u >> dnsgen$1.txt
		# de la lista de alternativos (son aquellos no listados/ocultos, hay mas chances de que no estén testeados), quito los originales
		touch dnsgen2$1.txt
		cat subdominios$1.txt | while read dom; do
			esta=$(cat dnsgen$1.txt | grep -ix "$dom")
			if [ -z "$esta" ]; then
				echo "$dom" >> dnsgen2$1.txt
			fi
		done
		mv dnsgen2$1.txt dnsgen$1.txt
		count=$(cat "dnsgen$1.txt" | wc -l)
		echo -e "\e[32m\tGenerated $count alternative domains...\033[0m" | tee -a salida.txt

#3-Resolvemos Dns

	if [[ -f altdns$1.txt && -s altdns$1.txt ]]; then
		echo -e "\e[32m\tDoing ShuffleDns to alternative domains...\033[0m" | tee -a salida.txt
		shuffledns -d $1 -list dnsgen$1.txt -r ~/tools/fresh.py/resolvers.txt -silent -o dnsgenresolved$1.txt
		count=$(cat "dnsgenresolved$1.txt" | wc -l)
		echo -e "\e[32m\t$count alternative domains resolved...\033[0m" | tee -a salida.txt
	fi

	rm dnsgen$1.txt 2> /dev/null
	echo -e "\e[32m************ DNS Resolving done... ************\033[0m" | tee -a salida.txt

#4-Probamos los vivos

	echo -e "\e[32m********** Starting Alive Checking... *********\033[0m" | tee -a salida.txt
	echo -e "\e[32m\tDoing httpx...\033[0m" | tee -a salida.txt
	httpx -l subdominios$1.txt -silent -o subdominiosvivos$1.txt


#5-Nmap
#--Preparamos el txt para el nmap

	if [[ -f dnsgenresolved$1.txt && -s dnsgenresolved$1.txt ]]; then

		cat subdominios$1.txt dnsgenresolved$1.txt > prenmap$1.txt

	fi

#--Nmap
	echo -e "\e[32m\tDoing Nmap to check if alive...\033[0m" | tee -a salida.txt
	nmap -sP -T5 -iL prenmap$1.txt > nmaptemp$1.txt < /dev/null 2>&1
# --extract ip and order/unique them

	cat nmaptemp$1.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > nmapips$1.txt
	sort -u -o nmapips$1.txt nmapips$1.txt

# --vuelo ip privadas, 0.0.0.0 (a veces aparece y el scan tarda mucho) y lineas en blanco. https://en.wikipedia.org/wiki/Private_network

	sed -i -E '/192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|127.0.0.1|0.0.0.0|100\.[6789]|100\.1[01][0-9]\.|100\.12[0-7]\.|^$/d' 4nmapips$1.txt

# --cuento la cantidad de alive hosts y la cantidad de IP únicas encontradas

	count=$(grep -c "Host is up" nmaptemp$1.txt)
	ips=$(wc -l nmapips$1.txt | awk '{ print $1 }')
	echo -e "\e[32m\t$count domains pointing to $ips IP addresses\033[0m" | tee -a salida.txt
	echo -e "\e[32m************ Alive Checking done... ***********\033[0m" | tee -a salida.txt


