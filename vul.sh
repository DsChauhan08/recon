#!/bin/bash
set -euo pipefail

VERSION="2.0.0"
CONFIG_FILE="$HOME/.config/recon-tui/config.yaml"
LOG_FILE="$HOME/.local/share/recon-tui/logs/recon.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
NC='\033[0m'

log() { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

init_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")" "$(dirname "$LOG_FILE")" "$(dirname "$CONFIG_FILE")/templates" "$(dirname "$CONFIG_FILE")/wordlists" 2>/dev/null
    
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'EOF'
# Recon TUI Configuration v2.0
# Edit this file to customize tool behavior

general:
  theme: "cyber"
  log_level: "info"
  output_format: "json"
  parallel_scans: 4
  timeout: 300
  verify_ssl: false

paths:
  output_dir: "./recon_output"
  tools_dir: "$HOME/.local/bin/recon-tools"
  wordlists: "$HOME/.local/share/recon-tui/wordlists"
  nuclei_templates: "$HOME/.local/share/recon-tui/templates"

scan:
  subdomain_threads: 50
  port_threads: 100
  http_threads: 25
  timeout_per_host: 10
  retries: 2

categories:
  subdomain_enumeration: true
  port_scanning: true
  web_analysis: true
  vulnerability_scanning: true
  osint: true
  password_audit: false

notifications:
  sound: false
  desktop: false
  webhook: ""
EOF
        success "Created config: $CONFIG_FILE"
    fi
}

load_config() {
    if command -v yq &>/dev/null; then
        eval "$(yq eval -o=shell "$CONFIG_FILE" 2>/dev/null || echo 'true')"
    fi
    
    OUTPUT_DIR="${scan_output_dir:-./recon_output}"
    mkdir -p "$OUTPUT_DIR"
}

TOOLS=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["assetfinder"]="go install -v github.com/tomnomnom/assetfinder@latest"
    ["sublist3r"]="pip3 install sublist3r 2>/dev/null || git clone https://github.com/aboul3la/Sublist3r && cd Sublist3r && pip3 install -r requirements.txt"
    ["amass"]="go install -v github.com/owasp/amass/v3/...@latest"
    ["findomain"]="curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip && unzip -o findomain-linux.zip && mv findomain /usr/local/bin/"
    ["crt.sh"]="curl -s \"https://crt.sh/?q=%25.\$TARGET&output=json\" | jq -r '.[].name_value' 2>/dev/null"
    ["censys"]="pip3 install censys 2>/dev/null || true"
    ["shodan"]="pip3 install shodan 2>/dev/null || true"
    ["virustotal"]="pip3 install vt-py 2>/dev/null || true"
    ["chaos"]="go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    ["subzy"]="go install -v github.com/subzy/checker@latest"
    ["sub404"]="git clone https://github.com/sub404/Sub404 && cd Sub404 && pip3 install -r requirements.txt"
    ["aquatone"]="go install -v github.com/michenriksen/aquatone@latest"
    ["gowitness"]="go install -v github.com/sensepost/gowitness@latest"
    ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    ["masscan"]="sudo dnf install -y masscan 2>/dev/null || sudo apt-get install -y masscan 2>/dev/null || true"
    ["nmap"]="sudo dnf install -y nmap 2>/dev/null || sudo apt-get install -y nmap 2>/dev/null || true"
    ["rustscan"]="curl -LO https://github.com/RustScan/RustScan/releases/latest/download/rustscan.deb && dpkg -i rustscan.deb 2>/dev/null || true"
    ["dnx"]="go install -v github.com/projectdiscovery/dnx/cmd/dnx@latest"
    ["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["fierce"]="pip3 install fierce 2>/dev/null || true"
    ["dnsrecon"]="pip3 install dnsrecon 2>/dev/null || sudo apt-get install -y dnsrecon 2>/dev/null || true"
    ["dnschef"]="pip3 install dnschef 2>/dev/null || true"
    ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["nuclei-templates"]="nuclei -update-templates 2>/dev/null || git clone https://github.com/projectdiscovery/nuclei-templates ~/.local/share/nuclei-templates"
    ["nvd"]="go install -v github.com/projectdiscovery/nvd-cve-checker/cmd/nvd@latest"
    ["osv-scanner"]="go install -v github.com/google/osv-scanner@latest"
    ["trivy"]="curl -LO https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.48.0_Linux-64bit.deb && dpkg -i trivy_0.48.0_Linux-64bit.deb 2>/dev/null || true"
    ["semgrep"]="pip3 install semgrep 2>/dev/null || true"
    ["bandit"]="pip3 install bandit 2>/dev/null || true"
    ["trufflehog"]="go install -v github.com/trufflesecurity/trufflehog/v3@latest"
    ["gitleaks"]="go install -v github.com/gitleaks/gitleaks/v8@latest"
    ["gitguardian"]="pip3 install ggshield 2>/dev/null || true"
    ["secretlint"]="npm install -g @secretlint/secretlint 2>/dev/null || true"
    ["dotenv-linter"]="cargo install dotenv-linter 2>/dev/null || true"
    ["commitlint"]="npm install -g @commitlint/cli @commitlint/config-conventional 2>/dev/null || true"
    ["dcodein"]="go install -v github.com/michenriksen/dcodein@latest"
    ["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
    ["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
    ["gauplus"]="git clone https://github.com/3xp0rt/gauPlus && cd gauPlus && go build"
    ["hakrawler"]="go install -v github.com/hakluke/hakrawler@latest"
    ["gospider"]="go install -v github.com/jaeles-project/gospider@latest"
    ["photon"]="pip3 install photon 2>/dev/null || true"
    ["eyewitness"]="git clone https://github.com/FortyNorthSecurity/EyeWitness && cd EyeWitness && pip3 install -r requirements.txt"
    ["webscreenshot"]="pip3 install webscreenshot 2>/dev/null || true"
    ["cuttles"]="git clone https://github.com/grepDevX/cuttles && cd cuttles && pip3 install -r requirements.txt"
    ["dirsearch"]="git clone https://github.com/maurosoria/dirsearch && cd dirsearch && pip3 install -r requirements.txt"
    ["gobuster"]="go install -v github.com/OJ/gobuster/v3@latest"
    ["ffuf"]="go install -v github.com/ffuf/ffuf/v2@latest"
    ["feroxbuster"]="curl -LO https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster.zip && unzip -o feroxbuster.zip && mv feroxbuster /usr/local/bin/"
    ["dirb"]="sudo apt-get install -y dirb 2>/dev/null || true"
    ["wpscan"]="gem install wpscan 2>/dev/null || true"
    ["cmsmap"]="pip3 install cmsmap 2>/dev/null || true"
    ["joomscan"]="git clone https://github.com/rezasp/joomscan && cd joomscan && pip3 install -r requirements.txt"
    ["droopescan"]="pip3 install droopescan 2>/dev/null || true"
    ["nikto"]="sudo apt-get install -y nikto 2>/dev/null || true"
    ["wapiti"]="pip3 install wapiti3 2>/dev/null || true"
    ["skipfish"]="sudo apt-get install -y skipfish 2>/dev/null || true"
    ["arachni"]="curl -LO https://github.com/Arachni/arachni/releases/latest/download/arachni-1.6.1.3-0.6.3.1-linux-x86_64.zip && unzip -o arachni-*.zip"
    ["zap"]="curl -LO https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_Linux.tar.gz && tar -xzf ZAP_2_14_0_Linux.tar.gz"
    ["burp-suite"]="curl -LO https://portswigger.net/burp/releases/latest?type=jar"
    ["whatweb"]="pip3 install whatweb 2>/dev/null || sudo apt-get install -y whatweb 2>/dev/null || true"
    ["wafw00f"]="pip3 install wafw00f 2>/dev/null || true"
    ["whatcms"]="pip3 install whatcms 2>/dev/null || true"
    ["builtwith"]="pip3 install builtwith 2>/dev/null || true"
    ["netcraft"]="curl -s \"https://www.netcraft.com/internet-data-loader/\" | head -1"
    ["whois"]="sudo dnf install -y whois 2>/dev/null || sudo apt-get install -y whois 2>/dev/null || true"
    ["theharvester"]="pip3 install theHarvester 2>/dev/null || true"
    ["metasploit"]="curl -LO https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfconsole.erb && chmod +x msfconsole.erb && mv msfconsole.erb /usr/local/bin/msfconsole"
    ["maltego"]="curl -LO https://www.maltego.com/redirect/?type=linux"
    ["recon-ng"]="git clone https://github.com/lanmaster53/recon-ng && cd recon-ng && pip3 install -r requirements.txt"
    ["spiderfoot"]="git clone https://github.com/smicallef/spiderfoot && cd spiderfoot && pip3 install -r requirements.txt"
    ["sn1per"]="git clone https://github.com/1N3/Sn1per && cd Sn1per && chmod +x install.sh && ./install.sh"
    ["x1"]="git clone https://github.com/fyoorer/x1 && cd x1 && chmod +x x1.sh"
    ["knockpy"]="git clone https://github.com/guelfoweb/knock && cd knock && pip3 install -r requirements.txt"
    ["enumall"]="git clone https://github.com/jhaddix/domain && cd domain && pip3 install -r requirements.txt"
    ["altdns"]="pip3 install altdns 2>/dev/null || true"
    ["dnsgen"]="pip3 install dnsgen 2>/dev/null || true"
    ["gotator"]="go install -v github.com/Josue87/gotator@latest"
    ["permute"]="go install -v github.com/ameenmaqsood/permute@latest"
    ["massdns"]="git clone https://github.com/blechschmidt/massdns && cd massdns && make && cp bin/massdns /usr/local/bin/"
    ["dnsvalidator"]="git clone https://github.com/vortexau/dnsvalidator && cd dnsvalidator && pip3 install -r requirements.txt"
    ["dnsrecon"]="pip3 install dnsrecon 2>/dev/null || sudo apt-get install -y dnsrecon 2>/dev/null || true"
    ["dnschef"]="pip3 install dnschef 2>/dev/null || true"
    ["fierce"]="pip3 install fierce 2>/dev/null || true"
    ["dnsmap"]="sudo apt-get install -y dnsmap 2>/dev/null || true"
    ["dnssec"]="sudo apt-get install -y dnssec-tools 2>/dev/null || true"
    ["ldns"]="sudo apt-get install -y ldns-utils 2>/dev/null || true"
    ["dnswalk"]="sudo apt-get install -y dnswalk 2>/dev/null || true"
    ["dnstracer"]="sudo apt-get install -y dnstracer 2>/dev/null || true"
    ["dnsgrep"]="go install -v github.com/cihanmegdul/dnsgrep@latest"
    ["cloudflare"]="pip3 install cloudflare 2>/dev/null || true"
    ["aws"]="pip3 install awscli 2>/dev/null || true"
    ["azure"]="pip3 install azure-cli 2>/dev/null || true"
    ["gcloud"]="curl https://sdk.cloud.google.com | bash"
    ["github-subdomains"]="go install -v github.com/gwen001/github-subdomains@latest"
    ["github-endpoints"]="go install -v github.com/gwen001/github-endpoints@latest"
    ["gitlab-subdomains"]="go install -v github.com/gwen001/gitlab-subdomains@latest"
    ["bitbucket-subdomains"]="git clone https://github.com/gwen001/bitbucket-subdomains"
    ["censys-subdomains"]="go install -v github.com/censys/censys-subdomains@latest"
    ["shodan-cli"]="pip3 install shodan 2>/dev/null || true"
    ["shodan-filter"]="go install -v github.com/owasp/shodan-filter@latest"
    ["binaryedge"]="pip3 install binaryedge 2>/dev/null || true"
    ["securitytrails"]="pip3 install securitytrails 2>/dev/null || true"
    ["viewdns"]="pip3 install viewdns 2>/dev/null || true"
    ["reverse-whois"]="pip3 install reverse-whois 2>/dev/null || true"
    ["whoisxmlapi"]="pip3 install whoisxmlapi 2>/dev/null || true"
    ["fullhunt"]="go install -v github.com/fullhunt/fullhunt@latest"
    ["leakix"]="go install -v github.com/hapoul/leakix-client@latest"
    ["pixelhunter"]="git clone https://github.com/BitTheByte/PixelHunter && cd PixelHunter && pip3 install -r requirements.txt"
    ["pwned"]="pip3 install pwned 2>/dev/null || true"
    ["breach-parse"]="git clone https://github.com/hmaverickadams/Breach-Parse && cd Breach-Parse && chmod +x breach-parse.sh"
    ["shh"]="git clone https://github.com/ndrix/shh && cd shh && gem build shh.gemspec && gem install shh-*.gem"
    ["pastehunter"]="git clone https://github.com/killswitch-GUI/PasteHunter && cd PasteHunter && pip3 install -r requirements.txt"
    ["dorks-hunter"]="git clone https://github.com/opsdisk/dorks_hunter && cd dorks_hunter && pip3 install -r requirements.txt"
    ["goohak"]="git clone https://github.com/1N3/Goohak && cd Goohak && chmod +x goohak.sh"
    ["google-dorks"]="git clone https://github.com/ebrii/google-dorks && cd google-dorks && chmod +x google-dorks.sh"
    ["dorker"]="git clone https://github.com/cyberpwn/dorker && cd dorker && pip3 install -r requirements.txt"
    ["dorkScanner"]="git clone https://github.com/NullArray/DorkScanner && cd DorkScanner && pip3 install -r requirements.txt"
    ["searchsploit"]="sudo apt-get install -y exploitdb 2>/dev/null || true"
    ["cve-search"]="git clone https://github.com/cve-search/cve-search && cd cve-search && pip3 install -r requirements.txt"
    ["cvemap"]="go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
    ["cvebin"]="go install -v github.com/projectdiscovery/cvebin/cmd/cvebin@latest"
    ["cvelib"]="pip3 install cvelib 2>/dev/null || true"
    ["opencve"]="pip3 install opencve 2>/dev/null || true"
    ["vulners"]="pip3 install vulners 2>/dev/null || true"
    ["vulncode-db"]="git clone https://github.com/google/vulncode-db && cd vulncode-db && pip3 install -r requirements.txt"
    ["osv"]="pip3 install osv 2>/dev/null || true"
    ["nvt"]="pip3 install nvt 2>/dev/null || true"
    ["syft"]="curl -LO https://github.com/anchore/syft/releases/latest/download/syft_0.96.0_linux_amd64.deb && dpkg -i syft_*.deb 2>/dev/null || true"
    ["grype"]="curl -LO https://github.com/anchore/grype/releases/latest/download/grype_0.72.0_linux_amd64.deb && dpkg -i grype_*.deb 2>/dev/null || true"
    ["clair"]="curl -LO https://github.com/quay/clair/releases/latest/download/clair_4.8.0_linux_amd64.zip && unzip -o clair-*.zip"
    ["trivy"]="curl -LO https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.48.0_Linux-64bit.deb && dpkg -i trivy_*.deb 2>/dev/null || true"
    ["zmap"]="git clone https://github.com/zmap/zmap && cd zmap && ./configure && make && sudo make install"
    ["autorecon"]="git clone https://github.com/Tib3rius/AutoRecon && cd AutoRecon && pip3 install -r requirements.txt"
    ["netcat"]="sudo apt-get install -y netcat-openbsd 2>/dev/null || sudo dnf install -y nmap-ncat 2>/dev/null || true"
    ["p0f"]="sudo apt-get install -y p0f 2>/dev/null || true"
    ["xprobe2"]="sudo apt-get install -y xprobe2 2>/dev/null || true"
    ["shodan-cli"]="pip3 install shodan 2>/dev/null || true"
    ["censys-cli"]="pip3 install censys 2>/dev/null || true"
    ["nikto"]="sudo apt-get install -y nikto 2>/dev/null || true"
    ["dirb"]="sudo apt-get install -y dirb 2>/dev/null || true"
    ["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
    ["commoncrawl"]="curl -s \"https://index.commoncrawl.org/collinfo.json\" 2>/dev/null | jq -r '.[].cdx_api' | head -1"
    ["dnsenum"]="git clone https://github.com/fwaeytens/dnsenum && cd dnsenum && pip3 install -r requirements.txt"
    ["dnstwist"]="pip3 install dnstwist 2>/dev/null || true"
    ["dnsdumpster"]="curl -s \"https://dnsdumpster.com/\" | head -1 || true"
    ["mxtoolbox"]="curl -s \"https://mxtoolbox.com/\" | head -1 || true"
    ["domaintools"]="pip3 install domaintools 2>/dev/null || true"
    ["passivetotal"]="pip3 install passivetotal 2>/dev/null || true"
    ["virustotal"]="pip3 install vt-py 2>/dev/null || true"
    ["cuckoosandbox"]="git clone https://github.com/cuckoosandbox/cuckoo && cd cuckoo && pip3 install -r requirements.txt"
    ["wireshark"]="sudo apt-get install -y wireshark 2>/dev/null || sudo dnf install -y wireshark 2>/dev/null || true"
    ["tcpdump"]="sudo apt-get install -y tcpdump 2>/dev/null || true"
    ["zeek"]="sudo apt-get install -y zeek 2>/dev/null || true"
    ["snort"]="sudo apt-get install -y snort 2>/dev/null || true"
    ["suricata"]="sudo apt-get install -y suricata 2>/dev/null || true"
    ["ntopng"]="sudo apt-get install -y ntopng 2>/dev/null || true"
    ["arp-scan"]="sudo apt-get install -y arp-scan 2>/dev/null || true"
    ["enum4linux"]="git clone https://github.com/CiscoCXSecurity/enum4linux && cd enum4linux && chmod +x enum4linux.pl"
    ["smbclient"]="sudo apt-get install -y smbclient 2>/dev/null || true"
    ["ldapsearch"]="sudo apt-get install -y ldap-utils 2>/dev/null || true"
    ["snmpwalk"]="sudo apt-get install -y snmp 2>/dev/null || true"
    ["rdpscan"]="git clone https://github.com/rapid7/rdpscan && cd rdpscan && go build"
    ["bluetoothctl"]="sudo apt-get install -y bluez 2>/dev/null || true"
    ["kismet"]="sudo apt-get install -y kismet 2>/dev/null || true"
    ["zoomeye"]="pip3 install zoomeye 2>/dev/null || true"
    ["emailrep"]="curl -s \"https://emailrep.io/\" | head -1 || true"
    ["urlcrazy"]="sudo apt-get install -y urlcrazy 2>/dev/null || true"
    ["subjack"]="go install -v github.com/haccer/subjack@latest"
    ["selenium"]="pip3 install selenium 2>/dev/null || true"
    ["puppeteer"]="npm install -g puppeteer 2>/dev/null || true"
    ["unicornscan"]="sudo apt-get install -y unicornscan 2>/dev/null || true"
    ["certspotter"]="curl -LO https://github.com/SSLMate/certspotter/releases/latest/download/certspotter_linux_amd64.zip && unzip -o certspotter_*.zip"
    ["pipl"]="pip3 install pipl 2>/dev/null || true"
    ["intelligencex"]="curl -s \"https://intelx.io/\" | head -1 || true"
    ["phishtool"]="git clone https://github.com/phishtool/phishtool-cli && cd phishtool-cli && pip3 install -r requirements.txt"
    ["mitmproxy"]="pip3 install mitmproxy 2>/dev/null || true"
    ["aircrack-ng"]="sudo apt-get install -y aircrack-ng 2>/dev/null || true"
    ["osint-framework"]="git clone https://github.com/lockfale/OSINT-Framework && cd OSINT-Framework"
    ["hybrid-analysis"]="curl -s \"https://hybrid-analysis.com/\" | head -1 || true"
    ["abuseipdb"]="curl -s \"https://www.abuseipdb.com/\" | head -1 || true"
    ["safebrowsing"]="pip3 install google-cloud-safebrowsing 2>/dev/null || true"
    ["mention"]="curl -s \"https://mention.com/\" | head -1 || true"
    ["social-searcher"]="curl -s \"https://www.social-searcher.com/\" | head -1 || true"
    ["twint"]="pip3 install twint 2>/dev/null || true"
    ["exiftool"]="sudo apt-get install -y exiftool 2>/dev/null || true"
    ["foca"]="git clone https://github.com/ElevenPaths/FOCA && cd FOCA"
    ["github-code-search"]="curl -s \"https://github.com/search\" | head -1 || true"
    ["sourcegraph"]="curl -s \"https://sourcegraph.com/\" | head -1 || true"
    ["retire-js"]="npm install -g retire 2>/dev/null || true"
    ["dependency-check"]="git clone https://github.com/jeremylong/DependencyCheck && cd DependencyCheck && ./gradlew build"
    ["mobsf"]="git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF && cd Mobile-Security-Framework-MobSF && pip3 install -r requirements.txt"
    ["jadx"]="curl -LO https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip && unzip -o jadx-*.zip"
    ["apktool"]="curl -LO https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool.jar && mv apktool.jar /usr/local/bin/"
    ["cloudmapper"]="git clone https://github.com/d душечка/CloudMapper && cd CloudMapper && pip3 install -r requirements.txt"
    ["scoutsuite"]="git clone https://github.com/nccgroup/ScoutSuite && cd ScoutSuite && pip3 install -r requirements.txt"
    ["prowler"]="git clone https://github.com/prowler-cloud/prowler && cd prowler && pip3 install -r requirements.txt"
    ["securitytrails"]="pip3 install securitytrails 2>/dev/null || true"
    ["misp"]="git clone https://github.com/MISP/MISP && cd MISP && ./INSTALL.sh"
    ["virustotal-cli"]="pip3 install vt-cli 2>/dev/null || true"
    ["duckduckgo"]="curl -s \"https://duckduckgo.com/\" | head -1 || true"
    ["bing"]="curl -s \"https://www.bing.com/\" | head -1 || true"
    ["yahoo"]="curl -s \"https://www.yahoo.com/\" | head -1 || true"
    ["baidu"]="curl -s \"https://www.baidu.com/\" | head -1 || true"
    ["yandex"]="curl -s \"https://yandex.com/\" | head -1 || true"
    ["google"]="curl -s \"https://www.google.com/\" | head -1 || true"
)

TOOL_CATEGORIES=(
    ["subfinder"]="subdomain"
    ["assetfinder"]="subdomain"
    ["sublist3r"]="subdomain"
    ["amass"]="subdomain"
    ["findomain"]="subdomain"
    ["crt.sh"]="subdomain"
    ["censys"]="subdomain"
    ["shodan"]="subdomain"
    ["virustotal"]="subdomain"
    ["chaos"]="subdomain"
    ["subzy"]="subdomain"
    ["sub404"]="subdomain"
    ["aquatone"]="web"
    ["gowitness"]="web"
    ["httpx"]="web"
    ["naabu"]="port"
    ["masscan"]="port"
    ["nmap"]="port"
    ["rustscan"]="port"
    ["dnx"]="subdomain"
    ["dnsx"]="subdomain"
    ["fierce"]="subdomain"
    ["dnsrecon"]="subdomain"
    ["dnschef"]="subdomain"
    ["nuclei"]="vuln"
    ["nuclei-templates"]="vuln"
    ["nvd"]="vuln"
    ["osv-scanner"]="vuln"
    ["trivy"]="vuln"
    ["semgrep"]="vuln"
    ["bandit"]="vuln"
    ["trufflehog"]="secret"
    ["gitleaks"]="secret"
    ["gitguardian"]="secret"
    ["secretlint"]="secret"
    ["dotenv-lister"]="secret"
    ["dcodein"]="web"
    ["waybackurls"]="web"
    ["gau"]="web"
    ["gauplus"]="web"
    ["hakrawler"]="web"
    ["gospider"]="web"
    ["photon"]="web"
    ["eyewitness"]="web"
    ["webscreenshot"]="web"
    ["cuttles"]="web"
    ["dirsearch"]="web"
    ["gobuster"]="web"
    ["ffuf"]="web"
    ["feroxbuster"]="web"
    ["dirb"]="web"
    ["wpscan"]="web"
    ["cmsmap"]="web"
    ["joomscan"]="web"
    ["droopescan"]="web"
    ["nikto"]="web"
    ["wapiti"]="web"
    ["skipfish"]="web"
    ["arachni"]="web"
    ["zap"]="web"
    ["burp-suite"]="web"
    ["whatweb"]="web"
    ["wafw00f"]="web"
    ["whatcms"]="web"
    ["builtwith"]="web"
    ["netcraft"]="osint"
    ["whois"]="osint"
    ["theharvester"]="osint"
    ["metasploit"]="exploit"
    ["maltego"]="osint"
    ["recon-ng"]="osint"
    ["spiderfoot"]="osint"
    ["sn1per"]="all"
    ["x1"]="subdomain"
    ["knockpy"]="subdomain"
    ["enumall"]="subdomain"
    ["altdns"]="subdomain"
    ["dnsgen"]="subdomain"
    ["gotator"]="subdomain"
    ["permute"]="subdomain"
    ["massdns"]="subdomain"
    ["dnsvalidator"]="subdomain"
    ["cloudflare"]="cloud"
    ["aws"]="cloud"
    ["azure"]="cloud"
    ["gcloud"]="cloud"
    ["github-subdomains"]="subdomain"
    ["github-endpoints"]="web"
    ["shodan-cli"]="subdomain"
    ["shodan-filter"]="subdomain"
    ["binaryedge"]="subdomain"
    ["securitytrails"]="subdomain"
    ["fullhunt"]="subdomain"
    ["leakix"]="leak"
    ["pixelhunter"]="leak"
    ["pwned"]="leak"
    ["breach-parse"]="leak"
    ["shh"]="leak"
    ["pastehunter"]="leak"
    ["dorks-hunter"]="osint"
    ["goohak"]="osint"
    ["google-dorks"]="osint"
    ["dorker"]="osint"
    ["dorkScanner"]="osint"
    ["searchsploit"]="exploit"
    ["cve-search"]="vuln"
    ["cvemap"]="vuln"
    ["cvebin"]="vuln"
    ["vulners"]="vuln"
    ["syft"]="vuln"
    ["grype"]="vuln"
    ["clair"]="vuln"
    ["zmap"]="port"
    ["autorecon"]="all"
    ["netcat"]="network"
    ["p0f"]="osint"
    ["xprobe2"]="osint"
    ["shodan-cli"]="subdomain"
    ["censys-cli"]="subdomain"
    ["dnstwist"]="subdomain"
    ["dnsenum"]="subdomain"
    ["dnsdumpster"]="osint"
    ["mxtoolbox"]="osint"
    ["domaintools"]="osint"
    ["passivetotal"]="osint"
    ["cuckoosandbox"]="malware"
    ["wireshark"]="network"
    ["tcpdump"]="network"
    ["zeek"]="network"
    ["snort"]="ids"
    ["suricata"]="ids"
    ["ntopng"]="network"
    ["arp-scan"]="network"
    ["enum4linux"]="windows"
    ["smbclient"]="windows"
    ["ldapsearch"]="directory"
    ["snmpwalk"]="network"
    ["rdpscan"]="windows"
    ["bluetoothctl"]="wireless"
    ["kismet"]="wireless"
    ["zoomeye"]="subdomain"
    ["emailrep"]="osint"
    ["urlcrazy"]="subdomain"
    ["selenium"]="web"
    ["puppeteer"]="web"
    ["unicornscan"]="port"
    ["certspotter"]="subdomain"
    ["pipl"]="osint"
    ["intelligencex"]="osint"
    ["phishtool"]="osint"
    ["mitmproxy"]="proxy"
    ["aircrack-ng"]="wireless"
    ["osint-framework"]="osint"
    ["hybrid-analysis"]="malware"
    ["abuseipdb"]="osint"
    ["safebrowsing"]="osint"
    ["twint"]="osint"
    ["exiftool"]="osint"
    ["foca"]="osint"
    ["retire-js"]="vuln"
    ["dependency-check"]="vuln"
    ["mobsf"]="mobile"
    ["jadx"]="mobile"
    ["apktool"]="mobile"
    ["cloudmapper"]="cloud"
    ["scoutsuite"]="cloud"
    ["prowler"]="cloud"
    ["securitytrails"]="subdomain"
    ["misp"]="threat-intel"
    ["virustotal-cli"]="threat-intel"
)

install_tool() {
    local tool=$1
    local cmd=${TOOLS[$tool]:-""}
    
    if [ -z "$cmd" ]; then
        warn "No install command for: $tool"
        return 1
    fi
    
    if command -v "$tool" &>/dev/null 2>&1; then
        success "$tool already installed"
        return 0
    fi
    
    info "Installing $tool..."
    if eval "$cmd" >/dev/null 2>&1; then
        success "Installed: $tool"
        return 0
    else
        error "Failed to install: $tool"
        return 1
    fi
}

install_all_tools() {
    local total=${#TOOLS[@]}
    local current=0
    local failed=0
    
    info "Installing $total tools..."
    
    for tool in "${!TOOLS[@]}"; do
        current=$((current + 1))
        printf "\rProgress: [%d/%d] %s" "$current" "$total" "$tool"
        
        if ! install_tool "$tool"; then
            failed=$((failed + 1))
        fi
    done
    echo ""
    
    if [ $failed -gt 0 ]; then
        warn "$failed tools failed to install"
    else
        success "All tools installed successfully"
    fi
}

check_dependencies() {
    local deps=("go" "git" "curl" "jq" "nmap" "masscan")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        info "Installing dependencies: ${missing[*]}"
        if command -v dnf &>/dev/null; then
            sudo dnf install -y "${missing[@]}" 2>/dev/null || true
        elif command -v apt-get &>/dev/null; then
            sudo apt-get install -y "${missing[@]}" 2>/dev/null || true
        fi
    fi
}

subdomain_scan() {
    local target=$1
    local output_dir=$2
    local results=()
    
    info "Running subdomain enumeration for: $target"
    
    if command -v subfinder &>/dev/null; then
        subfinder -d "$target" -silent -o "$output_dir/subs_subfinder.txt" 2>/dev/null &
        results+=("subfinder")
    fi
    
    if command -v assetfinder &>/dev/null; then
        assetfinder --subs-only "$target" > "$output_dir/subs_assetfinder.txt" 2>/dev/null &
        results+=("assetfinder")
    fi
    
    if command -v amass &>/dev/null; then
        amass enum -d "$target" -o "$output_dir/subs_amass.txt" 2>/dev/null &
        results+=("amass")
    fi
    
    if command -v findomain &>/dev/null; then
        findomain -t "$target" -o "$output_dir/subs_findomain.txt" 2>/dev/null &
        results+=("findomain")
    fi
    
    if command -v chaos &>/dev/null; then
        chaos -d "$target" -silent -o "$output_dir/subs_chaos.txt" 2>/dev/null &
        results+=("chaos")
    fi
    
    curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null > "$output_dir/subs_crtsh.txt" &
    results+=("crt.sh")
    
    wait
    
    cat "$output_dir"/subs_*.txt 2>/dev/null | sort -u > "$output_dir/all_subs.txt"
    local count=$(wc -l < "$output_dir/all_subs.txt" 2>/dev/null || echo 0)
    
    success "Found $count subdomains"
    echo "$count" > "$output_dir/subdomain_count.txt"
}

port_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running port scan for: $target"
    
    if command -v naabu &>/dev/null; then
        naabu -host "$target" -top-ports 100 -silent -o "$output_dir/ports_naabu.txt" 2>/dev/null &
    fi
    
    if command -v masscan &>/dev/null; then
        masscan "$target" -p1-1000 --rate=1000 -oG "$output_dir/ports_masscan.txt" 2>/dev/null &
    fi
    
    if command -v rustscan &>/dev/null; then
        rustscan -a "$target" --ulimit 5000 -oG "$output_dir/ports_rustscan.txt" 2>/dev/null &
    fi
    
    wait
    
    if command -v naabu &>/dev/null; then
        cat "$output_dir/ports_naabu.txt" 2>/dev/null
    fi
    
    local count=$(wc -l < "$output_dir"/ports_*.txt 2>/dev/null | tail -1 || echo 0)
    success "Port scan complete: $count ports found"
}

web_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running web analysis for: $target"
    
    if command -v httpx &>/dev/null; then
        cat "$output_dir/all_subs.txt" 2>/dev/null | httpx -silent -title -status-code -o "$output_dir/alive.txt" 2>/dev/null
    else
        cat "$output_dir/all_subs.txt" 2>/dev/null > "$output_dir/alive.txt"
    fi
    
    if command -v whatweb &>/dev/null; then
        cat "$output_dir/alive.txt" 2>/dev/null | whatweb --log-brief="$output_dir/tech.txt" 2>/dev/null &
    fi
    
    if command -v aquatone &>/dev/null; then
        cat "$output_dir/alive.txt" 2>/dev/null | aquatone -out "$output_dir/aquatone" 2>/dev/null &
    fi
    
    if command -v gowitness &>/dev/null; then
        gowitness file -f "$output_dir/alive.txt" -d "$output_dir/gowitness" 2>/dev/null &
    fi
    
    wait
    
    local alive_count=$(wc -l < "$output_dir/alive.txt" 2>/dev/null || echo 0)
    success "Web scan complete: $alive_count alive hosts"
}

vuln_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running vulnerability scan for: $target"
    
    if command -v nuclei &>/dev/null; then
        if [ -s "$output_dir/alive.txt" ]; then
            cat "$output_dir/alive.txt" | nuclei -silent -severity critical,high,medium -o "$output_dir/vulns.txt" 2>/dev/null
        fi
    fi
    
    if command -v subzy &>/dev/null; then
        subzy --targets "$output_dir/all_subs.txt" --output "$output_dir/subdomain_takeovers.txt" 2>/dev/null
    fi
    
    if command -v trufflehog &>/dev/null; then
        trufflehog filesystem "$output_dir" --output "$output_dir/secrets.txt" 2>/dev/null || true
    fi
    
    local vuln_count=$(wc -l < "$output_dir/vulns.txt" 2>/dev/null || echo 0)
    success "Vulnerability scan complete: $vuln_count issues found"
}

generate_report() {
    local target=$1
    local output_dir=$2
    
    local subs_count=$(cat "$output_dir/subdomain_count.txt" 2>/dev/null || echo 0)
    local alive_count=$(wc -l < "$output_dir/alive.txt" 2>/dev/null || echo 0)
    local vuln_count=$(wc -l < "$output_dir/vulns.txt" 2>/dev/null || echo 0)
    local port_count=$(wc -l < "$output_dir"/ports_*.txt 2>/dev/null | tail -1 || echo 0)
    
    cat > "$output_dir/report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Recon Report: $target</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0d0d0d; color: #00ff00; margin: 0; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a1a1a, #2a2a2a); padding: 30px; border-radius: 10px; margin-bottom: 20px; border: 1px solid #00ff00; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-box { background: #1a1a1a; border: 1px solid #00ff00; border-radius: 8px; padding: 20px; text-align: center; }
        .stat-box.critical { border-color: #ff0000; }
        .stat-box.high { border-color: #ff8800; }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        .finding { background: #1a1a1a; border-left: 3px solid #00ff00; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .finding.critical { border-left-color: #ff0000; }
        .finding.high { border-left-color: #ff8800; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #1a1a1a; color: #00ff00; }
        a { color: #00ff00; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Recon Report: $target</h1>
        <p>Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>Version: $VERSION</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div>Subdomains</div>
            <div class="stat-value">$subs_count</div>
        </div>
        <div class="stat-box">
            <div>Alive Hosts</div>
            <div class="stat-value">$alive_count</div>
        </div>
        <div class="stat-box critical">
            <div>Critical</div>
            <div class="stat-value">$(grep -c "critical" "$output_dir/vulns.txt" 2>/dev/null || echo 0)</div>
        </div>
        <div class="stat-box high">
            <div>High</div>
            <div class="stat-value">$(grep -c "high" "$output_dir/vulns.txt" 2>/dev/null || echo 0)</div>
        </div>
        <div class="stat-box">
            <div>Open Ports</div>
            <div class="stat-value">$port_count</div>
        </div>
    </div>
    
    <h2>📁 Output Files</h2>
    <table>
        <tr><th>File</th><th>Lines</th></tr>
        $(for f in "$output_dir"/*.txt; do [ -f "$f" ] && echo "<tr><td>$(basename "$f")</td><td>$(wc -l < "$f")</td></tr>"; done)
    </table>
</body>
</html>
EOF

    success "Report generated: $output_dir/report.html"
}

quick_scan() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         QUICK RECON SCAN                      ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Enter target domain: " TARGET
    
    if [ -z "$TARGET" ]; then
        error "Target cannot be empty"
        return 1
    fi
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$OUTPUT_DIR/quick_${timestamp}_${TARGET//[^a-zA-Z0-9]/_}"
    mkdir -p "$output_dir"
    
    subdomain_scan "$TARGET" "$output_dir"
    web_scan "$TARGET" "$output_dir"
    vuln_scan "$TARGET" "$output_dir"
    
    generate_report "$TARGET" "$output_dir"
    
    success "Scan complete! Results in: $output_dir"
}

full_scan() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         FULL RECON SCAN                       ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Enter target domain: " TARGET
    
    if [ -z "$TARGET" ]; then
        error "Target cannot be empty"
        return 1
    fi
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$OUTPUT_DIR/full_${timestamp}_${TARGET//[^a-zA-Z0-9]/_}"
    mkdir -p "$output_dir"
    
    subdomain_scan "$TARGET" "$output_dir"
    port_scan "$TARGET" "$output_dir"
    web_scan "$TARGET" "$output_dir"
    vuln_scan "$TARGET" "$output_dir"
    
    generate_report "$TARGET" "$output_dir"
    
    success "Scan complete! Results in: $output_dir"
}

single_tool() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         SINGLE TOOL EXECUTION                 ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "Available tools:"
    local index=1
    for tool in "${!TOOLS[@]}"; do
        printf "  %3d. %-20s [%s]\n" "$index" "$tool" "${TOOL_CATEGORIES[$tool]:-unknown}"
        index=$((index + 1))
    done
    
    echo ""
    read -p "Select tool number (or name): " selection
    
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        local tool_names=("${!TOOLS[@]}")
        selection=$((selection - 1))
        if [ $selection -ge 0 ] && [ $selection -lt ${#tool_names[@]} ]; then
            TOOL="${tool_names[$selection]}"
        else
            error "Invalid selection"
            return 1
        fi
    else
        TOOL="$selection"
    fi
    
    if [ -z "${TOOLS[$TOOL]:-}" ]; then
        error "Unknown tool: $TOOL"
        return 1
    fi
    
    read -p "Enter target (if applicable): " TARGET
    
    info "Running $TOOL..."
    
    if command -v "$TOOL" &>/dev/null 2>&1; then
        if [ -n "$TARGET" ]; then
            "$TOOL" "$TARGET" 2>&1 | head -100
        else
            "$TOOL" 2>&1 | head -100
        fi
    else
        install_tool "$TOOL"
        if command -v "$TOOL" &>/dev/null 2>&1; then
            if [ -n "$TARGET" ]; then
                "$TOOL" "$TARGET" 2>&1 | head -100
            else
                "$TOOL" 2>&1 | head -100
            fi
        else
            error "Tool not available: $TOOL"
        fi
    fi
}

list_tools() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         INSTALLED TOOLS                       ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    local installed=0
    local not_installed=0
    
    for tool in "${!TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null 2>&1; then
            echo -e "  ${GREEN}[✓]${NC} $tool"
            installed=$((installed + 1))
        else
            echo -e "  ${RED}[✗]${NC} $tool"
            not_installed=$((not_installed + 1))
        fi
    done
    
    echo ""
    echo "Installed: $installed | Not installed: $not_installed | Total: ${#TOOLS[@]}"
}

show_help() {
    echo -e "${MAGENTA}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         RECON TUI v$VERSION                   ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "OPTIONS:"
    echo "  1  Quick Scan    - Fast subdomain + web + vuln scan"
    echo "  2  Full Scan     - Complete reconnaissance"
    echo "  3  Single Tool   - Run any tool individually"
    echo "  4  Install Tools - Install/verify all tools"
    echo "  5  List Tools    - Show installed tools status"
    echo "  6  Config        - Edit configuration"
    echo "  7  Update        - Update all tools"
    echo "  H  Help          - Show this help"
    echo "  Q  Quit          - Exit"
    echo ""
    echo "EXAMPLES:"
    echo "  recon-tui        # Start interactive menu"
    echo "  recon-tui quick  # Quick scan"
    echo "  recon-tui full   # Full scan"
    echo ""
}

edit_config() {
    if command -v nano &>/dev/null; then
        nano "$CONFIG_FILE"
    elif command -v vim &>/dev/null; then
        vim "$CONFIG_FILE"
    elif command -v micro &>/dev/null; then
        micro "$CONFIG_FILE"
    else
        info "Config file: $CONFIG_FILE"
        cat "$CONFIG_FILE"
    fi
}

update_tools() {
    info "Updating all tools..."
    
    for tool in "${!TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null 2>&1; then
            case "$tool" in
                nuclei)
                    nuclei -update-templates 2>/dev/null || true
                    ;;
                subfinder|httpx|naabu|dnsx|chaos|cvemap)
                    go install -v github.com/projectdiscovery/${tool}/cmd/${tool}@latest 2>/dev/null || true
                    ;;
                *)
                    info "Skipping update for: $tool"
                    ;;
            esac
        fi
    done
    
    success "Update complete"
}

main_menu() {
    while true; do
        echo -e "${MAGENTA}"
        echo "╔═══════════════════════════════════════════════╗"
        echo "║         RECON TUI v$VERSION                   ║"
        echo "║         ${#TOOLS[@]} Tools Available                   ║"
        echo "╚═══════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        echo "  [1] Quick Scan"
        echo "  [2] Full Scan"
        echo "  [3] Single Tool"
        echo "  [4] Install Tools"
        echo "  [5] List Tools"
        echo "  [6] Config"
        echo "  [7] Update"
        echo "  [H] Help"
        echo "  [Q] Quit"
        echo ""
        read -p "Select option: " choice
        
        case "$choice" in
            1) quick_scan ;;
            2) full_scan ;;
            3) single_tool ;;
            4) install_all_tools ;;
            5) list_tools ;;
            6) edit_config ;;
            7) update_tools ;;
            H|h) show_help ;;
            Q|q) 
                echo "Goodbye!"
                exit 0
                ;;
            *)
                error "Invalid option"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..." dummy
        clear
    done
}

main() {
    load_config
    check_dependencies
    
    case "${1:-menu}" in
        quick)
            load_config
            quick_scan
            ;;
        full)
            load_config
            full_scan
            ;;
        install)
            install_all_tools
            ;;
        list)
            list_tools
            ;;
        config)
            edit_config
            ;;
        update)
            update_tools
            ;;
        help|--help|-h)
            show_help
            ;;
        menu|*)
            main_menu
            ;;
    esac
}

main "$@"
