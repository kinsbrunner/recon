#!/bin/bash

######################################################
# --------------> K1NSBRU RECON v0.5 <-------------- #
######################################################
################### Change Log #######################
# Ver    Date     Description                        #
# 0.1  26-Jul-20  Initial version (subdomain finder) #
# 0.2  27-Jul-20  Excl subdomains, check if alive,   #
#                  check takeovers, get screenshots, #
#                  execute waybackrecon.             #
# 0.3  28-Jul-20  Adding directory search            #
# 0.4  09-Ago-20  Improving subdo enumeration        #
# 0.5  11-Ago-20  Adding .tokens file, github subdo  #
#                  scrapping script, file for github #
#                  manual checks and, adding nuclei. #
######################################################

######################################################
##################### TO DOs #########################
# # Adding Nikto                                     #
# # Take rejected subdomains from file               #
# # Adding interlace to improve performance          #
# # AWS and GCP bucket research                      #
# # Adding Masscan                                   #
# # Saving results into the cloud                    #
# # Handling errors on a better way                  #
# # Handling conditionals and improving messages     #
# # Adding DNS and certs related stuff               #
# # Adding options to only run certain features      #
# #                                                  #
######################################################


######################################################
################### Customizing ######################
tokens_filepath="../.tokens" #placed on a higher directory to avoid commiting by error
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
while getopts ":d:e:r:" o; do
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
    mkdir ./$domain/$foldername/screenshots
    mkdir ./$domain/$foldername/wayback-data/
    mkdir ./$domain/$foldername/dir-search/
    mkdir ./$domain/$foldername/vulns
    mkdir ./$domain/$foldername/vulns/nuclei
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
    token_virustotal=$(cat ${tokens_filepath} | grep VIRUSTOTAL | cut -d "=" -f 2)
    if [ ! -z "$token_virustotal" ]
    then
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
    else
        touch ./$domain/$foldername/subdomain_3.txt
    fi

    ### Spyse API
    token_spyse=$(cat ${tokens_filepath} | grep SPYSE | cut -d "=" -f 2)
    if [ ! -z "$token_spyse" ]
    then
        curl --request GET --url "https://api.spyse.com/v3/data/domain/subdomain?domain=${domain}&limit=100" --header "Authorization: Bearer ${token_spyse}" --silent > ./$domain/$foldername/temp_api.txt
        cat ./$domain/$foldername/temp_api.txt | jq '.data.items[].name' | sed 's/"//g' >> ./$domain/$foldername/subdomain_4.txt
        rm ./$domain/$foldername/temp_api.txt
        echo "      $(date +"%I:%M:%S") Spyse API obtained $(wc -l ./$domain/$foldername/subdomain_4.txt | cut -d " " -f 1)"
    else
        touch ./$domain/$foldername/subdomain_4.txt
    fi

    ### SecurityTrails API
    token_securitytrails=$(cat ${tokens_filepath} | grep SECURITYTRAILS | cut -d "=" -f 2)
    if [ ! -z "$token_securitytrails" ]
    then
        curl --request GET --url "https://api.securitytrails.com/v1/domain/${domain}/subdomains" --header "apikey: ${token_securitytrails}" --silent > ./$domain/$foldername/temp_api.txt
        cat ./$domain/$foldername/temp_api.txt | jq '.subdomains[]' | sed 's/"//g' | sed -e "s/$/.$domain/" >> ./$domain/$foldername/subdomain_5.txt
        rm ./$domain/$foldername/temp_api.txt
        echo "      $(date +"%I:%M:%S") SecurityTrails API obtained $(wc -l ./$domain/$foldername/subdomain_5.txt | cut -d " " -f 1)"
    else
        touch ./$domain/$foldername/subdomain_5.txt
    fi

    ### Github subdomains
    token_github=$(cat ${tokens_filepath} | grep GITHUB | cut -d "=" -f 2)
    if [ ! -z "$token_github" ]
    then
        python3 ~/tools/github-subdomains.py -d $domain -t ${token_github} > ./$domain/$foldername/subdomain_6.txt
        echo "      $(date +"%I:%M:%S") Github_Subdomains obtained $(wc -l ./$domain/$foldername/subdomain_6.txt | cut -d " " -f 1)"
    else
        touch ./$domain/$foldername/subdomain_6.txt
    fi

    ### Consolidate and remove duplicates
    cat ./$domain/$foldername/subdomain_1.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_2.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_3.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_4.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_5.txt >> ./$domain/$foldername/temp.txt
    cat ./$domain/$foldername/subdomain_6.txt >> ./$domain/$foldername/temp.txt
    sort -u ./$domain/$foldername/temp.txt > ./$domain/$foldername/subdomains.txt
    echo "[==>] $(date +"%I:%M:%S") A total of ${success}$(wc -l ./$domain/$foldername/subdomains.txt | cut -d " " -f 1) discovered${reset} subdomains"

    ### Subdomain bruteforcing
## Commenting out as it was taking too long, will re-enable on VPS run!
#    altdns -i ./$domain/$foldername/subdomains.txt -o ./$domain/$foldername/data_output -w ~/tools/recon/patterns.txt -r -s ./$domain/$foldername/subdomain_bruteforcing.txt
#    echo "      $(date +"%I:%M:%S") Subdomain bruteforcing obtained $(wc -l ./$domain/$foldername/subdomain_bruteforcing.txt | cut -d " " -f 1)"

    ### Delete partial files
    rm ./$domain/$foldername/temp.txt
    rm ./$domain/$foldername/subdomain_1.txt
    rm ./$domain/$foldername/subdomain_2.txt
    rm ./$domain/$foldername/subdomain_3.txt
    rm ./$domain/$foldername/subdomain_4.txt
    rm ./$domain/$foldername/subdomain_5.txt
    rm ./$domain/$foldername/subdomain_6.txt
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
        echo "$probeurl" >> ./$domain/$foldername/alive.txt
    done
    echo "$(cat ./$domain/$foldername/alive.txt | sort -u)" > ./$domain/$foldername/alive.txt
    rm ./$domain/$foldername/responsive.txt
    echo  "[==>] $(date +"%I:%M:%S") A total of ${success}$(wc -l ./$domain/$foldername/alive.txt | cut -d " " -f 1) alive${reset} subdomains were found${reset}"
}


check_takeover(){
    echo "[+]   $(date +"%I:%M:%S") Checking for possible subdomain takeover"
    if [ ! -f "./$domain/$foldername/vulns/potential_takeovers.txt" ];then
        touch ./$domain/$foldername/vulns/potential_takeovers.txt
    fi
    subjack -w ./$domain/$foldername/vulns/potential_takeovers.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -o ./$domain/$foldername/potential_takeovers.txt
}


take_screenshot(){
    echo "[+]   $(date +"%I:%M:%S") Starting aquatone scan, this could take a few minutes"
    cat ./$domain/$foldername/alive.txt | aquatone -out ./$domain/$foldername/screenshots -threads 20 -silent >> ./$domain/$foldername/screenshots/error_log.txt
}


waybackrecon() {
    echo "[+]   $(date +"%I:%M:%S") Scrapping wayback for data"
    touch ./$domain/$foldername/wayback-data/temp.txt
    interlace -tL ./$domain/$foldername/alive.txt -threads 20 -c "echo _target_ | waybackurls >> ./$domain/$foldername/wayback-data/temp.txt" --silent > /dev/null
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
    python3 ~/tools/dirsearch/dirsearch.py -e php,asp,aspx,jsp,html,zip,jar,bak,txt -w $dirsearchWordlist -t $dirsearchThreads -L ./$domain/$foldername/alive.txt --plain-text-report=./$domain/$foldername/dir-search/target_paths.txt > /dev/null
    cat ./$domain/$foldername/dir-search/target_paths.txt | grep 200 | sort -u >./$domain/$foldername/dir-search/target_paths_200.txt
}


manual_github_check(){
    echo "[+]   $(date +"%I:%M:%S") Generating manual github links generated on 'github_links_check.txt'"

    echo "https://github.com/search?q=%22${domain}%22+password&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+npmrc%20_auth&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+dockercfg&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+pem%20private&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+id_rsa&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+aws_access_key_id&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+s3cfg&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+htpasswd&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+git-credentials&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+bashrc%20password&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+sshd_config&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+xoxp%20OR%20xoxb%20OR%20xoxa&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+SECRET_KEY&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+client_secret&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+sshd_config&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+github_token&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+api_key&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+FTP&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+app_secret&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+passwd&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+.env&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+.exs&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+beanstalkd.yml&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+deploy.rake&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+mysql&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+credentials&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+PWD&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+deploy.rake&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+.bash_history&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+.sls&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+secrets&type=Code" >> ./$domain/$foldername/github_links_check.txt
    echo "https://github.com/search?q=%22${domain}%22+composer.json&type=Code" >> ./$domain/$foldername/github_links_check.txt
}


nuclei_templates(){
    echo "[+]   $(date +"%I:%M:%S") Starting Nuclei templates"
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/basic-detections/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/basic-detections.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/brute-force/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/brute-force.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/subdomain-takeover/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/subdomain-takeover.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/cves/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/cves.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/files/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/files.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/panels/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/panels.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/security-misconfiguration/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/security-misconfiguration.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/technologies/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/technologies.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/tokens/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/tokens.txt > /dev/null
    nuclei -l ./$domain/$foldername/alive.txt -t "/root/tools/nuclei-templates/vulnerabilities/*.yaml" -c 60 -silent -o ./$domain/$foldername/vulns/nuclei/vulnerabilities.txt > /dev/null
}


cms_detection(){
    echo "[+]   $(date +"%I:%M:%S") Running CMS detection" 
    whatweb -i ./$domain/$foldername/alive.txt --quiet --log-verbose=./$domain/$foldername/vulns/whatweb.txt
}


main(){
    ### Presentation
    clear
    logo
    
    ### Preparation
    check_known_target
    create_structure

    ### Recon!
    manual_github_check
    find_subdomains
    exclude_subdomains
    filter_alive_subdomains
    check_takeover
    take_screenshot
    waybackrecon
    directory_search

    ### Vulns check
    cms_detection
    nuclei_templates

    ### Wrap-up
    duration=$SECONDS
    echo "[==>] $(date +"%I:%M:%S") Scan completed in : $(($duration / 60)) minutes and $(($duration % 60)) seconds."
    stty sane
    tput sgr0

    token_telegram=$(cat ${tokens_filepath} | grep TELEGRAM | cut -d "=" -f 2)
    channel_telegram=$(cat ${tokens_filepath} | grep CHATID | cut -d "=" -f 2)
    if [ ! -z "$token_telegram" ] && [ ! -z "$channel_telegram" ]
    then
        curl -s -X POST "https://api.telegram.org/bot${token_telegram}/sendMessage" -d chat_id="${channel_telegram}" -d text="Recon script on ${domain} has finished in $(($duration / 60)) minutes and $(($duration % 60)) seconds." >/dev/null 2>/dev/null
    fi
}

######################################################
###################### Main ##########################
main $domain
