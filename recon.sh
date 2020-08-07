#!/bin/bash

######################################################
# --------------> K1NSBRU RECON v0.2 <-------------- #
######################################################
################### Change Log #######################
# Ver    Date     Description                        #
# 0.1  26-Jul-20  Initial version (subdomain finder) #
# 0.2  27-Jul-20  Excl subdomains, check if alive,   #
#                  check takeovers, get screenshots, #
#                  execute waybackrecon.             #
# 0.3  28-Jul-20  Adding directory search            #
######################################################

######################################################
################### Customizing ######################
token_telegram="<telegrom_token>"
chatid="<telegram_channel_id>"
token_virustotal="<virustotal_token>"
token_spyse="<spyse_token>"
token_securitytrails="<securitytrails_token>"
error=`tput setaf 1`
success=`tput setaf 2`
warning=`tput setaf 3`
reset=`tput sgr0`


######################################################
##################### Global #########################
SECONDS=0
domain=
subreport=
todate=$(date +"%Y-%m-%d")
path=$(pwd)
foldername=recon-$todate


######################################################
################## Input handling ####################
while getopts ":d:e:r:w:" o; do
    case "${o}" in
        d)
            domain=${OPTARG}
            ;;
       e)
            set -f
 	        IFS=","
	        excluded+=($OPTARG)
	        unset IFS
            ;;
	    r)
            subreport+=("$OPTARG")
            ;;
#        w)  
#            rm -r ./$domain/$foldername
#            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND - 1))

if [ -z "${domain}" ] && [[ -z ${subreport[@]} ]]; then
   usage; exit 1;
fi

######################################################
#################### Functions #######################
usage() { 
	echo -e "Usage: ./k1nsbru-recon.sh -d domain.com [-w] [-e excluded.domain.com[,other.domain.com]]\nOptions:\n  -e\tspecify excluded subdomains\n " 1>&2; exit 1; 
}


logo(){
    echo "${warning}
+----------------------------------------------------+
+---------------> K1NSBRU RECON TOOL <---------------+
+----------------------------------------------------+${reset}"
}


check_known_target(){
  if [ -d "./$domain" ]
  then
    echo "This is a known target."
  else
    mkdir ./$domain
  fi    
}


create_structure(){
#### TEMP
    if [ -d "./$domain/$foldername" ]
    then
        rm -r ./$domain/$foldername
    fi

    mkdir ./$domain/$foldername
    touch ./$domain/$foldername/subdomains.txt

  mkdir ./$domain/$foldername/aqua_out
  mkdir ./$domain/$foldername/aqua_out/parsedjson
  mkdir ./$domain/$foldername/wayback-data/
  mkdir ./$domain/$foldername/dir-search/  
}


find_subdomains(){
    echo "[+]   $(date +"%I:%M:%S") Gathering subdomains"

    ### Sublist3r
    python ~/tools/Sublist3r/sublist3r.py -d $domain -t 10 -v -o ./$domain/$foldername/subdomain_1.txt > /dev/null
    echo "      $(date +"%I:%M:%S") Sublist3r obtained $(wc -l ./$domain/$foldername/subdomain_1.txt | cut -d " " -f 1)"

    ### AssettFinder
    assetfinder $domain | grep $domain | grep -v '^*' | sort -u > ./$domain/$foldername/subdomain_2.txt
    echo "      $(date +"%I:%M:%S") AssettFinder obtained $(wc -l ./$domain/$foldername/subdomain_2.txt | cut -d " " -f 1)"

    ### VirusTotal API
    curl --request GET --url "https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=30" --header "x-apikey: ${token_virustotal}" --silent > ./$domain/$foldername/temp_api.txt
    url=$(cat ./$domain/$foldername/temp_api.txt | jq '.links.next' | sed 's/"//g')
    while ! [ -z $url ]; do
       # Move retrieved into container
        cat ./$domain/$foldername/temp_api.txt | jq '.data[].id' | sed 's/"//g' >> ./$domain/$foldername/subdomain_3.txt
        # Make next call
        curl --request GET --url $url --header "x-apikey: ${token_virustotal}" --silent > ./$domain/$foldername/temp_api.txt
        # Check if next call is required
        url=$(cat ./$domain/$foldername/temp_api.txt | jq '.links.next' | sed 's/"//g')
    done
    cat ./$domain/$foldername/temp_api.txt | jq '.data[].id' | sed 's/"//g' >> ./$domain/$foldername/subdomain_3.txt
    rm ./$domain/$foldername/temp_api.txt
    echo "      $(date +"%I:%M:%S") VirusTotal API obtained $(wc -l ./$domain/$foldername/subdomain_3.txt | cut -d " " -f 1)"

    ### Spyse API
    curl --request GET --url "https://api.spyse.com/v3/data/domain/subdomain?domain=${domain}&limit=100" --header "Authorization: Bearer ${token_spyse}" --silent > ./$domain/$foldername/temp_api.txt
    cat ./$domain/$foldername/temp_api.txt | jq '.data.items[].name' | sed 's/"//g' >> ./$domain/$foldername/subdomain_4.txt
    rm ./$domain/$foldername/temp_api.txt
    echo "      $(date +"%I:%M:%S") Spyse API obtained $(wc -l ./$domain/$foldername/subdomain_4.txt | cut -d " " -f 1)"

    ### SecurityTrails API
    curl --request GET --url "https://api.securitytrails.com/v1/domain/${domain}/subdomains" --header "apikey: ${token_securitytrails}" --silent > ./$domain/$foldername/temp_api.txt
    cat ./$domain/$foldername/temp_api.txt | jq '.subdomains[]' | sed 's/"//g' | sed -e "s/$/.$domain/" >> ./$domain/$foldername/subdomain_5.txt
    rm ./$domain/$foldername/temp_api.txt
    echo "      $(date +"%I:%M:%S") SecurityTrails API obtained $(wc -l ./$domain/$foldername/subdomain_5.txt | cut -d " " -f 1)"

    ### Consolidate and remove duplicates
    cat ./$domain/$foldername/subdomain_1.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_2.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_3.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_4.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_5.txt >> ./$domain/$foldername/temp.txt
    sort -u ./$domain/$foldername/temp.txt > ./$domain/$foldername/subdomains.txt
    echo "[==>] $(date +"%I:%M:%S") A total of ${success}$(wc -l ./$domain/$foldername/subdomains.txt | cut -d " " -f 1) discovered${reset} subdomains"

    ### Delete partial files
    rm ./$domain/$foldername/temp.txt
    rm ./$domain/$foldername/subdomain_1.txt
    rm ./$domain/$foldername/subdomain_2.txt
    rm ./$domain/$foldername/subdomain_3.txt
    rm ./$domain/$foldername/subdomain_4.txt
    rm ./$domain/$foldername/subdomain_5.txt
}


exclude_subdomains(){
    if ! [ -z "${excluded}" ]; then
        echo "[+]   $(date +"%I:%M:%S") Excluding requested subdomains"
        IFS=$'\n'
        # prints the $excluded array to excluded.txt with newlines
        printf "%s\n" "${excluded[*]}" > ./$domain/$foldername/subdomains_excluded.txt
        # this form of grep takes two files, reads the input from the first file, finds in the second file and removes
        grep -vFf ./$domain/$foldername/subdomains_excluded.txt ./$domain/$foldername/subdomains.txt > ./$domain/$foldername/subdomains_temp.txt
        mv ./$domain/$foldername/subdomains_temp.txt ./$domain/$foldername/subdomains.txt
        unset IFS
        echo "      $(date +"%I:%M:%S") A total of ${error}$(wc -l ./$domain/$foldername/subdomains_excluded.txt | cut -d " " -f 1) excluded${reset} subdomains"
    fi
}


filter_alive_subdomains(){
    echo "[+]   $(date +"%I:%M:%S") Probing for live hosts"
    cat ./$domain/$foldername/subdomains.txt | httprobe -c 50 -t 3000 >> ./$domain/$foldername/responsive.txt
    cat ./$domain/$foldername/responsive.txt | sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | sort -u | while read line; do
        probeurl=$(cat ./$domain/$foldername/responsive.txt | sort -u | grep -m 1 $line)
        echo "$probeurl" >> ./$domain/$foldername/urllist.txt
    done
    echo "$(cat ./$domain/$foldername/urllist.txt | sort -u)" > ./$domain/$foldername/urllist.txt
    rm ./$domain/$foldername/responsive.txt
    echo  "[==>] $(date +"%I:%M:%S") A total of ${success}$(wc -l ./$domain/$foldername/urllist.txt | cut -d " " -f 1) alive${reset} subdomains were found${reset}"
}


check_takeover(){
    echo "[+]   $(date +"%I:%M:%S") Checking for possible subdomain takeover"
    if [ ! -f "./$domain/$foldername/potential_takeovers.txt" ];then
        touch ./$domain/$foldername/potential_takeovers.txt
    fi
    subjack -w ./$domain/$foldername/potential_takeovers.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -o ./$domain/$foldername/potential_takeovers.txt
}


take_screenshot(){
    echo "[+]   $(date +"%I:%M:%S") Starting aquatone scan, this could take a few minutes"
    cat ./$domain/$foldername/urllist.txt | aquatone -out ./$domain/$foldername/aqua_out -threads 20 -silent >> ./$domain/$foldername/aqua_out/error_log.txt
}


waybackrecon() {
    echo "[+]   $(date +"%I:%M:%S") Scrapping wayback for data"
    touch ./$domain/$foldername/wayback-data/temp.txt
    interlace -tL ./$domain/$foldername/urllist.txt -threads 20 -c "echo _target_ | waybackurls >> ./$domain/$foldername/wayback-data/temp.txt" --silent > /dev/null
    sort -u ./$domain/$foldername/wayback-data/temp.txt > ./$domain/$foldername/wayback-data/waybackurls.txt
    rm ./$domain/$foldername/wayback-data/temp.txt

    cat ./$domain/$foldername/wayback-data/waybackurls.txt  | sort -u | unfurl --unique keys > ./$domain/$foldername/wayback-data/paramlist.txt
    [ -s ./$domain/$foldername/wayback-data/paramlist.txt ] && echo "      $(date +"%I:%M:%S") Wordlist saved"

    cat ./$domain/$foldername/wayback-data/waybackurls.txt  | sort -u | grep -P "\w+\.js(\?|$) | sort -u " > ./$domain/$foldername/wayback-data/jsurls.txt
    [ -s ./$domain/$foldername/wayback-data/jsurls.txt ] && echo "      $(date +"%I:%M:%S") JS Urls saved"

    cat ./$domain/$foldername/wayback-data/waybackurls.txt  | sort -u | grep -P "\w+\.php(\?|$) | sort -u " > ./$domain/$foldername/wayback-data/phpurls.txt
    [ -s ./$domain/$foldername/wayback-data/phpurls.txt ] && echo "      $(date +"%I:%M:%S") PHP Urls saved"

    cat ./$domain/$foldername/wayback-data/waybackurls.txt  | sort -u | grep -P "\w+\.aspx(\?|$) | sort -u " > ./$domain/$foldername/wayback-data/aspxurls.txt
    [ -s ./$domain/$foldername/wayback-data/aspxurls.txt ] && echo "      $(date +"%I:%M:%S") ASP Urls saved"

    cat ./$domain/$foldername/wayback-data/waybackurls.txt  | sort -u | grep -P "\w+\.jsp(\?|$) | sort -u " > ./$domain/$foldername/wayback-data/jspurls.txt
    [ -s ./$domain/$foldername/wayback-data/jspurls.txt ] && echo "      $(date +"%I:%M:%S") JSP Urls saved"
}


directory_search(){
    echo "[+]   $(date +"%I:%M:%S") Starting directory search, this could take a while!"
    dirsearchThreads=150
    dirsearchWordlist=~/tools/dirsearch/db/dicc.txt
    python3 ~/tools/dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar,bak,txt -w $dirsearchWordlist -t $dirsearchThreads -L ./$domain/$foldername/urllist.txt --plain-text-report=./$domain/$foldername/dir-search/target_paths.txt > /dev/null
    cat ./$domain/$foldername/dir-search/target_paths.txt | grep 200 | sort -u >./$domain/$foldername/dir-search/target_paths_200.txt
}


main(){
    ### Presentation
    clear
    logo
    
    ### Preparation
    check_known_target
    create_structure

    ### Recon!
    find_subdomains
    exclude_subdomains
    filter_alive_subdomains
    check_takeover
    take_screenshot
    waybackrecon
    directory_search

    ### Wrap-up
    duration=$SECONDS
    echo "[==>] $(date +"%I:%M:%S") Scan completed in : $(($duration / 60)) minutes and $(($duration % 60)) seconds."
    stty sane
    tput sgr0
    curl -s -X POST "https://api.telegram.org/bot${token_telegram}/sendMessage" -d chat_id="${chatid}" -d text="Recon script on ${domain} has finished in $(($duration / 60)) minutes and $(($duration % 60)) seconds." >/dev/null 2>/dev/null
}

######################################################
###################### Main ##########################
main $domain
