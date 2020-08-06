# Recon Toolbelt

This repository contains a set of tools used for bug hunting:

- **recon.sh**: contains a script that, give a domain, does subdomain enumeration, checks whether subdomains are alive, checks for possible takeovers, takes screenshots, and does a directory search. All the outputs of the different tools are condensed and presented on a tidy folder. Once the recon tool finishes executing, it sends a Telegram message informing this.
- **vuln.sh**: given a list of subdomains/domains, the script does some vulnerabilities check and sends a Telegram message once it has finished.
- **services.sh**: given a list of subdomains/domains, the script does a port scanning and sends a Telegram message once it has finished.
