#!/bin/bash

######################################################
# --------------> K1NSBRU VULNS v0.1 <-------------- #
######################################################
################### Change Log #######################
# Ver    Date     Description                        #
# 0.1  06-Aug-20  Initial version (subdomain finder) #
######################################################

######################################################
##################### TO DOs #########################
# #                                                  #
######################################################


######################################################
################### Customizing ######################
token_telegram="<telegrom_token>"
chatid="<telegram_channel_id>"
error=`tput setaf 1`
success=`tput setaf 2`
warning=`tput setaf 3`
reset=`tput sgr0`


######################################################
##################### Global #########################
SECONDS=0
domain=
subdomains_file=
todate=$(date +"%Y-%m-%d")
path=$(pwd)
foldername=recon-$todate


######################################################
################## Input handling ####################
while getopts ":d:f:" o; do
    case "${o}" in
        d)
            domain=${OPTARG}
            ;;
        f)
            subdomains_file=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND - 1))

if [ -z "${domain}" ] || [ -z "${subdomains_file}" ]; then
   usage; exit 1;
fi

######################################################
#################### Functions #######################
usage() { 
	echo -e "Usage: ./k1nsbru-vuln.sh -d domain.com -f ./path/to/subdomains\n " 1>&2; exit 1; 
}


logo(){
    echo "${warning}
+----------------------------------------------------+
+---------------> K1NSBRU VULNS TOOL <---------------+
+----------------------------------------------------+${reset}"
}


create_structure(){
    if [ ! -d "./$domain" ]
    then
        mkdir ./$domain
    fi

    if [ ! -d "./$domain/$foldername" ]
    then
        mkdir ./$domain/$foldername
    fi

    rm -r ./$domain/$foldername/vulns
    mkdir ./$domain/$foldername/vulns
}


extract_subdomain(){
    # To remove prefix: sed 's/https\?:\/\///' 
    # To remove suffix: sed -e "s/.${domain}$//"
    echo $1 | sed 's/https\?:\/\///' | sed -e "s/.${domain}$//"
}

search_vulns(){
    cat ${subdomains_file} | sed 's/https\?:\/\///' > ./$domain/$foldername/vulns/temp_url.txt
    interlace -tL ./$domain/$foldername/vulns/temp_url.txt -threads 10 -c "nikto --host _target_ >> ./$domain/$foldername/vulns/_target_.txt" -v
    rm ./$domain/$foldername/vulns/temp_url.txt
}


main(){
    ### Presentation
    clear
    logo
    
    ### Preparation
    create_structure

    ### Check for vulns!
    search_vulns

    ### Wrap-up
    duration=$SECONDS
    echo "[==>] $(date +"%I:%M:%S") Scan completed in : $(($duration / 60)) minutes and $(($duration % 60)) seconds."
    stty sane
    tput sgr0
    curl -s -X POST "https://api.telegram.org/bot${token_telegram}/sendMessage" -d chat_id="${chatid}" -d text="Vuln scan script has finished in $(($duration / 60)) minutes and $(($duration % 60)) seconds." >/dev/null 2>/dev/null
}

######################################################
###################### Main ##########################
main
