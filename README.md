# Recon Toolbelt

This repository contains some scripts I use for bug hunting:

- **recon.sh**: contains a script that, give a domain, does subdomain enumeration, checks whether subdomains are alive, checks for possible takeovers, takes screenshots, does a directory search, does a CMS detection and runs various of Nuclei's templates. All the outputs of the different tools are condensed and presented on a tidy folder. Once the recon tool finishes executing, it sends a Telegram message informing this. A '.tokens' file should be placed on the parent directory holding all the required API keys.

- **new_machine.sh**: contains a script that installs many of the most used scripts, utilities and dictionaries in order to quickly set up a new workspace.