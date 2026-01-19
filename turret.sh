#!/bin/bash
set -euo pipefail

VERSION="2.0.0"
CONFIG_FILE="$HOME/.config/vuln-tui/config.yaml"
LOG_FILE="$HOME/.local/share/vuln-tui/logs/vuln.log"

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
critical() { echo -e "${RED}[CRITICAL]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

init_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")" "$(dirname "$LOG_FILE")" "$(dirname "$CONFIG_FILE")/templates" "$(dirname "$CONFIG_FILE")/reports" 2>/dev/null
    
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << 'EOF'
# Vulnerability Scanner TUI Configuration v2.0
# Comprehensive configuration for all vulnerability scanning tools

general:
  theme: "cyber-red"
  log_level: "debug"
  output_format: "json"
  parallel_scans: 3
  global_timeout: 600
  verify_ssl: false

paths:
  output_dir: "./vuln_output"
  tools_dir: "$HOME/.local/bin/vuln-tools"
  nuclei_templates: "$HOME/.local/share/vuln-tui/templates"
  nuclei_custom_templates: "$HOME/.local/share/vuln-tui/custom-templates"
  reports_dir: "$HOME/.local/share/vuln-tui/reports"

scan:
  subdomain_threads: 50
  port_threads: 100
  http_threads: 20
  timeout_per_host: 15
  retries: 3
  rate_limit: 100
  exclude_codes: "404,401,403"
  follow_redirects: true
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

severity:
  critical: true
  high: true
  medium: true
  low: false
  info: false

categories:
  cve: true
  misconfiguration: true
  exposed_secrets: true
  injection: true
  xss: true
  sqli: true
  ssrf: true
  ssti: true
  authentication: true
  authorization: true
  file_inclusion: true
  command_injection: true
  xmlxxe: true
  cors: true
  security_headers: true
  tls_ssl: true

notifications:
  sound: true
  desktop: false
  slack_webhook: ""
  discord_webhook: ""
  email_smtp: ""

reporting:
  format: ["html", "json", "csv"]
  severity_colors: true
  include_evidence: true
  max_evidence_length: 500
  auto_open_report: false
EOF
        success "Created config: $CONFIG_FILE"
    fi
}

load_config() {
    if command -v yq &>/dev/null; then
        eval "$(yq eval -o=shell "$CONFIG_FILE" 2>/dev/null || echo 'true')"
    fi
    
    OUTPUT_DIR="${scan_output_dir:-./vuln_output}"
    NUCLEI_TEMPLATES="${paths_nuclei_templates:-$HOME/.local/share/nuclei-templates}"
    mkdir -p "$OUTPUT_DIR" "$NUCLEI_TEMPLATES" 2>/dev/null
}

VULN_TOOLS=(
    ["nuclei"]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["nuclei-templates"]="nuclei -update-templates 2>/dev/null || git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates $NUCLEI_TEMPLATES"
    ["naabu"]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["dnsx"]="go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["cvemap"]="go install -v github.com/projectdiscovery/cvemap/cmd/cvemap@latest"
    ["cvebin"]="go install -v github.com/projectdiscovery/cvebin/cmd/cvebin@latest"
    ["vulnerscan"]="pip3 install vulners 2>/dev/null || true"
    ["nvd"]="go install -v github.com/projectdiscovery/nvd-cve-checker/cmd/nvd@latest"
    ["osv-scanner"]="go install -v github.com/google/osv-scanner@latest"
    ["trivy"]="curl -LO https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.48.0_Linux-64bit.deb && dpkg -i trivy_*.deb 2>/dev/null || true"
    ["grype"]="curl -LO https://github.com/anchore/grype/releases/latest/download/grype_0.72.0_linux_amd64.deb && dpkg -i grype_*.deb 2>/dev/null || true"
    ["syft"]="curl -LO https://github.com/anchore/syft/releases/latest/download/syft_0.96.0_linux_amd64.deb && dpkg -i syft_*.deb 2>/dev/null || true"
    ["clair"]="docker pull quay.io/projectquay/clair:latest 2>/dev/null || true"
    ["scanner"]="pip3 install scanner 2>/dev/null || true"
    ["bandit"]="pip3 install bandit 2>/dev/null || true"
    ["semgrep"]="pip3 install semgrep 2>/dev/null || true"
    ["mobsf"]="docker pull opensecurity/mobile-security-framework-mobsf:latest 2>/dev/null || true"
    ["dastardly"]="docker pull portswigger/dastardly:latest 2>/dev/null || true"
    ["zap"]="curl -LO https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_Linux.tar.gz && tar -xzf ZAP_2_14_0_Linux.tar.gz"
    ["wpscan"]="gem install wpscan 2>/dev/null || true"
    ["joomscan"]="git clone https://github.com/rezasp/joomscan && cd joomscan && chmod +x joomscan.pl"
    ["droopescan"]="pip3 install droopescan 2>/dev/null || true"
    ["cmsmap"]="git clone https://github.com/Dionach/CMSmap && cd CMSmap && pip3 install -r requirements.txt"
    ["nikto"]="sudo apt-get install -y nikto 2>/dev/null || true"
    ["wapiti"]="pip3 install wapiti3 2>/dev/null || true"
    ["skipfish"]="sudo apt-get install -y skipfish 2>/dev/null || true"
    ["arachni"]="curl -LO https://github.com/Arachni/arachni/releases/latest/download/arachni-1.6.1.3-0.6.3.1-linux-x86_64.zip && unzip -o arachni-*.zip"
    ["wfuzz"]="pip3 install wfuzz 2>/dev/null || true"
    ["ffuf"]="go install -v github.com/ffuf/ffuf/v2@latest"
    ["gobuster"]="go install -v github.com/OJ/gobuster/v3@latest"
    ["feroxbuster"]="curl -LO https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster.zip && unzip -o feroxbuster.zip"
    ["dirsearch"]="git clone https://github.com/maurosoria/dirsearch && cd dirsearch && pip3 install -r requirements.txt"
    ["dirb"]="sudo apt-get install -y dirb 2>/dev/null || true"
    ["uniscan"]="sudo apt-get install -y uniscan 2>/dev/null || true"
    ["vega"]="curl -LO https://subgraph.com/vega/releases/latest/Vega-linux-x86_64.zip && unzip -o Vega-*.zip"
    ["burp-suite"]="curl -LO https://portswigger.net/burp/releases/latest?type=jar"
    ["xsstrike"]="git clone https://github.com/s0md3v/XSStrike && cd XSStrike && pip3 install -r requirements.txt"
    ["dalfox"]="go install -v github.com/hahwul/dalfox/v2@latest"
    ["xssmap"]="git clone https://github.com/KimHACKER/CorCrawl && cd CorCrawl && pip3 install -r requirements.txt"
    ["xssfinder"]="git clone https://github.com/mrroot5/XSSFinder && cd XSSFinder && pip3 install -r requirements.txt"
    ["bXSS"]="git clone https://github.com/ethicalhackingplayground/bXSS && cd bXSS && pip3 install -r requirements.txt"
    ["xsssniper"]="git clone https://github.com/g0hacker/XSS-Scanner && cd XSS-Scanner && pip3 install -r requirements.txt"
    ["sqlmap"]="git clone https://github.com/sqlmapproject/sqlmap && cd sqlmap && chmod +x sqlmap.py"
    ["sqlninja"]="sudo apt-get install -y sqlninja 2>/dev/null || true"
    ["sqldumper"]="git clone https://github.com/the-robot/sqldumper && cd sqldumper && pip3 install -r requirements.txt"
    ["nosqli"]="git clone https://github.com/Charlie-belmer/nosqli && cd nosqli && pip3 install -r requirements.txt"
    ["ssrfmap"]="git clone https://github.com/swisskyrepo/SSRFmap && cd SSRFmap && pip3 install -r requirements.txt"
    ["gopherus"]="git clone https://github.com/tarunkant/Gopherus && cd Gopherus && chmod +x gopherus.py"
    ["chaindo"]="git clone https://github.com/commixproject/chaindo && cd chaindo && chmod +x chaindo.py"
    ["ssti"]="git clone https://github.com/epinna/tplmap && cd tplmap && pip3 install -r requirements.txt"
    ["exploit"]="git clone https://github.com/danielmiessler/SecLists && cd SecLists && pip3 install -r requirements.txt"
    ["commix"]="git clone https://github.com/commixproject/commix && cd commix && chmod +x commix.py"
    ["lfi"]="git clone https://github.com/D35m0nd142/LFISuite && cd LFISuite && chmod +x lfi.py"
    ["fileinject"]="git clone https://github.com/AlphaBugL/FileInject && cd FileInject && chmod +rwx *.py"
    ["xxelab"]="git clone https://github.com/adam-montrose/xxelab && cd xxelab && pip3 install -r requirements.txt"
    ["xmlrpc"]="git clone https://github.com/LandGrey/pydictor && cd pydictor && python3 pydictor.py -usage"
    ["corsy"]="git clone https://github.com/s0md3v/Corsy && cd Corsy && pip3 install -r requirements.txt"
    ["corscanner"]="git clone https://github.com/chenjj/CORScanner && cd CORScanner && pip3 install -r requirements.txt"
    ["jwt-hack"]="git clone https://github.com/ahmadaghay/JWT-Hack && cd JWT-Hack && pip3 install -r requirements.txt"
    ["burp-jwt"]="curl -s https://portswigger.net/burp/releases/latest | grep -o 'jwt.*.jar' | head -1"
    ["authz"]="git clone https://github.com/OWASP/AZAP && cd AZAP && pip3 install -r requirements.txt"
    ["authmatrix"]="git clone https://github.com/OWASP/AuthMatrix && cd AuthMatrix && pip3 install -r requirements.txt"
    ["tornado"]="git clone https://github.com/Optiv/Tornado && cd Tornado && pip3 install -r requirements.txt"
    ["secretfinder"]="git clone https://github.com/m4ll0k/SecretFinder && cd SecretFinder && pip3 install -r requirements.txt"
    ["trufflehog"]="go install -v github.com/trufflesecurity/trufflehog/v3@latest"
    ["gitleaks"]="go install -v github.com/gitleaks/gitleaks/v8@latest"
    ["gitguardian"]="pip3 install ggshield 2>/dev/null || true"
    ["detect-secrets"]="pip3 install detect-secrets 2>/dev/null || true"
    ["secretlint"]="npm install -g @secretlint/secretlint 2>/dev/null || true"
    ["goby"]="curl -LO https://github.com/gobysec/Goby/releases/latest/download/goby-linux-x64.zip && unzip -o goby-*.zip"
    ["afrog"]="go install -v github.com/zan8in/afrog@latest"
    ["nuclei-templates"]="git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates ~/.nuclei-templates"
    ["poc-t"]="git clone https://github.com/developer3000/Poc-T && cd Poc-T && pip3 install -r requirements.txt"
    ["vulscan"]="git clone https://github.com/scipag/vulscan && cd vulscan && ln -s $(pwd)/vulscan /usr/share/nmap/scripts/vulscan/"
    ["vulners"]="git clone https://github.com/vulnersCom/nmap-vulners && cd nmap-vulners && ln -s $(pwd)/vulners.nse /usr/share/nmap/scripts/vulners.nse"
    ["testssl"]="git clone --depth 1 https://github.com/drwetter/testssl.sh && cd testssl.sh && chmod +x testssl.sh"
    ["sslyze"]="pip3 install sslyze 2>/dev/null || true"
    ["sslscan"]="sudo apt-get install -y sslscan 2>/dev/null || true"
    ["test-crypto"]="git clone https://github.com/tls-attacker/TLS-Attacker && cd TLS-Attacker && mvn package -DskipTests"
    ["subjack"]="go install -v github.com/haccer/subjack@latest"
    ["subzy"]="go install -v github.com/subzy/checker@latest"
    ["takeover"]="git clone https://github.com/anshumanbh/tko-subs && cd tko-subs && go build"
    ["nuclei-tko"]="git clone https://github.com/OWASP/Subdomain-Takeover && cd Subdomain-Takeover && chmod +rwx *.sh"
    ["corsy"]="git clone https://github.com/s0md3v/Corsy && cd Corsy && pip3 install -r requirements.txt"
    ["dom-red"]="git clone https://github.com/OWASP/DOM-Detector && cd DOM-Detector && python3 setup.py install"
    ["open-redirect"]="git clone https://github.com/OWASP/Open-Redirect && cd Open-Redirect && chmod +rwx *.sh"
    ["or-tools"]="git clone https://github.com/anshumanbh/or-redirect && cd or-redirect && pip3 install -r requirements.txt"
    ["csrfpoc"]="git clone https://github.com/OWASP/CsrfTester && cd CsrfTester && chmod +rwx *.sh"
    ["csrf-scanner"]="git clone https://github.com/chenjj/CRLF-Injection-Scanner && cd CRLF-Injection-Scanner && pip3 install -r requirements.txt"
    ["crlfuzz"]="go install -v github.com/dwisiswant0/crlfuzz/v2@latest"
    ["heapdump"]="git clone https://github.com/OWASP/heapdump-inspector && cd heapdump-inspector && pip3 install -r requirements.txt"
    ["s3-buckets"]="git clone https://github.com/sa7mon/S3Scanner && cd S3Scanner && pip3 install -r requirements.txt"
    ["aws-extender"]="git clone https://github.com/OWASP/aws-extender && cd aws-extender && npm install"
    ["azure-recon"]="git clone https://github.com/OWASP/Azure-Red-Team && cd Azure-Red-Team && chmod +rwx *.sh"
    ["gcloud-scanner"]="git clone https://github.com/OWASP/GCPScanner && cd GCPScanner && chmod +rwx *.sh"
    ["firefox-decrypt"]="git clone https://github.com/unode/firefox_decrypt && cd firefox_decrypt && chmod +rwx firefox_decrypt.py"
    ["lazagne"]="git clone https://github.com/AlessandroZ/LaZagne && cd LaZagne && pip3 install -r requirements.txt"
    ["mimikatz"]="curl -LO https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip && unzip -o mimikatz_trunk.zip"
    ["Responder"]="git clone https://github.com/SpiderLabs/Responder && cd Responder && chmod +x Responder.py"
    ["mitm6"]="git clone https://github.com/fox-it/mitm6 && cd mitm6 && pip3 install -r requirements.txt"
    ["ntlmrecon"]="git clone https://github.com/rootlabs/ntlmrecon && cd ntlmrecon && pip3 install -r requirements.txt"
    ["Coercer"]="git clone https://github.com/p0dalirius/Coercer && cd Coercer && pip3 install -r requirements.txt"
    ["PetitPotam"]="git clone https://github.com/topotam/PetitPotam && cd PetitPotam && chmod +rwx *.py"
    ["PrintSpooler"]="git clone https://github.com/calebstewart/CVE-2021-1675 && cd CVE-2021-1675 && chmod +rwx *.ps1"
    ["zerologon"]="git clone https://github.com/dirkjanm/CVE-2020-1472 && cd CVE-2020-1472 && chmod +rwx *.py"
    ["noPac"]="git clone https://github.com/RicardoJCE/Invoke-NoPac && cd Invoke-NoPac && chmod +rwx *.ps1"
    ["impacket"]="pip3 install impacket 2>/dev/null || git clone https://github.com/fortra/impacket && cd impacket && pip3 install -r requirements.txt"
    ["bloodhound"]="npm install -g bloodhound 2>/dev/null || docker pull bloodhound/ingest:latest 2>/dev/null || true"
    ["sharphound"]="curl -LO https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe"
    ["ad-explorer"]="curl -LO https://learn.microsoft.com/en-us/windows-server/ad/AD-Explorer/ad-explorer"
    ["ldapexplorer"]="curl -LO https://github.com/veracode/LDAP-Explorer && cd LDAP-Explorer && npm install"
    ["rpcclient"]="sudo apt-get install -y rpcclient 2>/dev/null || true"
    ["enum4linux"]="git clone https://github.com/CiscoCXSecurity/enum4linux && cd enum4linux && chmod +x enum4linux.pl"
    ["smbmap"]="git clone https://github.com/ShawnDEvans/smbmap && cd smbmap && pip3 install -r requirements.txt"
    ["smbclient"]="sudo apt-get install -y smbclient 2>/dev/null || true"
    ["evil-winrm"]="git clone https://github.com/Hackplayers/Evil-WinRM && cd Evil-WinRM && gem install evil-winrm"
    ["crackmapexec"]="pip3 install crackmapexec 2>/dev/null || git clone https://github.com/Porchetta-Industries/CrackMapExec && cd CrackMapExec && pip3 install -r requirements.txt"
    ["pth-tools"]="sudo apt-get install -y pth-tools 2>/dev/null || true"
    ["winexe"]="sudo apt-get install -y winexe 2>/dev/null || true"
    ["psexec"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/psexec.py"
    ["wmiexec"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/wmiexec.py"
    ["atexec"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/atexec.py"
    ["dcomexec"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/dcomexec.py"
    ["smbexec"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/smbexec.py"
    ["atexec"]="git clone https://github.com/SecureAuthCorp/impacket && cd impacket && python3 setup.py install"
    ["secretsdump"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/secretsdump.py"
    ["lsassy"]="pip3 install lsassy 2>/dev/null || true"
    ["procdump"]="curl -LO https://learn.microsoft.com/en-us/sysinternals/downloads/procdump"
    ["mimikatz"]="curl -LO https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip"
    ["pypykatz"]="pip3 install pypykatz 2>/dev/null || true"
    ["logonpasswords"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/psexec.py"
    ["cachedump"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/secretsdump.py"
    ["ntdsdump"]="curl -LO https://github.com/fortra/impacket/blob/master/examples/secretsdump.py"
    ["nmap"]="sudo apt-get install -y nmap 2>/dev/null || sudo dnf install -y nmap 2>/dev/null || true"
    ["masscan"]="sudo apt-get install -y masscan 2>/dev/null || sudo dnf install -y masscan 2>/dev/null || true"
    ["zmap"]="git clone https://github.com/zmap/zmap && cd zmap && ./configure && make && sudo make install"
    ["autorecon"]="git clone https://github.com/Tib3rius/AutoRecon && cd AutoRecon && pip3 install -r requirements.txt"
    ["netcat"]="sudo apt-get install -y netcat-openbsd 2>/dev/null || sudo dnf install -y nmap-ncat 2>/dev/null || true"
    ["p0f"]="sudo apt-get install -y p0f 2>/dev/null || true"
    ["xprobe2"]="sudo apt-get install -y xprobe2 2>/dev/null || true"
    ["shodan-cli"]="pip3 install shodan 2>/dev/null || true"
    ["censys-cli"]="pip3 install censys 2>/dev/null || true"
    ["whatweb"]="pip3 install whatweb 2>/dev/null || sudo apt-get install -y whatweb 2>/dev/null || true"
    ["aquatone"]="go install -v github.com/michenriksen/aquatone@latest"
    ["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
    ["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
    ["commoncrawl"]="curl -s \"https://index.commoncrawl.org/collinfo.json\" 2>/dev/null | jq -r '.[].cdx_api' | head -1"
    ["sublist3r"]="pip3 install sublist3r 2>/dev/null || git clone https://github.com/aboul3la/Sublist3r && cd Sublist3r && pip3 install -r requirements.txt"
    ["amass"]="go install -v github.com/owasp/amass/v3/...@latest"
    ["dnsenum"]="git clone https://github.com/fwaeytens/dnsenum && cd dnsenum && pip3 install -r requirements.txt"
    ["dnsrecon"]="pip3 install dnsrecon 2>/dev/null || sudo apt-get install -y dnsrecon 2>/dev/null || true"
    ["dnstwist"]="pip3 install dnstwist 2>/dev/null || true"
    ["dnsdumpster"]="curl -s \"https://dnsdumpster.com/\" | head -1 || true"
    ["crt.sh"]="curl -s \"https://crt.sh/?q=%25.\$TARGET&output=json\" | jq -r '.[].name_value' 2>/dev/null"
    ["testssl.sh"]="git clone --depth 1 https://github.com/drwetter/testssl.sh && cd testssl.sh && chmod +x testssl.sh"
    ["whois"]="sudo apt-get install -y whois 2>/dev/null || sudo dnf install -y whois 2>/dev/null || true"
    ["mxtoolbox"]="curl -s \"https://mxtoolbox.com/\" | head -1 || true"
    ["theharvester"]="pip3 install theHarvester 2>/dev/null || true"
    ["pwned"]="pip3 install pwned 2>/dev/null || true"
    ["maltego"]="curl -LO https://www.maltego.com/redirect/?type=linux"
    ["recon-ng"]="git clone https://github.com/lanmaster53/recon-ng && cd recon-ng && pip3 install -r requirements.txt"
    ["spiderfoot"]="git clone https://github.com/smicallef/spiderfoot && cd spiderfoot && pip3 install -r requirements.txt"
    ["twint"]="pip3 install twint 2>/dev/null || true"
    ["tineye"]="curl -s \"https://tineye.com/\" | head -1 || true"
    ["exiftool"]="sudo apt-get install -y exiftool 2>/dev/null || true"
    ["foca"]="git clone https://github.com/ElevenPaths/FOCA && cd FOCA"
    ["trufflehog"]="go install -v github.com/trufflesecurity/trufflehog/v3@latest"
    ["gitleaks"]="go install -v github.com/gitleaks/gitleaks/v8@latest"
    ["github-code-search"]="curl -s \"https://github.com/search\" | head -1 || true"
    ["sourcegraph"]="curl -s \"https://sourcegraph.com/\" | head -1 || true"
    ["dependency-check"]="git clone https://github.com/jeremylong/DependencyCheck && cd DependencyCheck && ./gradlew build"
    ["retire-js"]="npm install -g retire 2>/dev/null || true"
    ["jadx"]="curl -LO https://github.com/skylot/jadx/releases/latest/download/jadx-1.4.7.zip && unzip -o jadx-*.zip"
    ["apktool"]="curl -LO https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool.jar && mv apktool.jar /usr/local/bin/"
    ["cloudmapper"]="git clone https://github.com/duo-labs/cloudmapper && cd cloudmapper && pip3 install -r requirements.txt"
    ["scoutsuite"]="git clone https://github.com/nccgroup/ScoutSuite && cd ScoutSuite && pip3 install -r requirements.txt"
    ["prowler"]="git clone https://github.com/prowler-cloud/prowler && cd prowler && pip3 install -r requirements.txt"
    ["securitytrails"]="pip3 install securitytrails 2>/dev/null || true"
    ["passivetotal"]="pip3 install passivetotal 2>/dev/null || true"
    ["misp"]="git clone https://github.com/MISP/MISP && cd MISP && ./INSTALL.sh"
    ["virustotal"]="pip3 install vt-py 2>/dev/null || true"
    ["cuckoo"]="git clone https://github.com/cuckoosandbox/cuckoo && cd cuckoo && pip3 install -r requirements.txt"
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
    ["bluez"]="sudo apt-get install -y bluez 2>/dev/null || true"
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
    ["builtwith"]="pip3 install builtwith 2>/dev/null || true"
    ["aircrack-ng"]="sudo apt-get install -y aircrack-ng 2>/dev/null || true"
    ["osint-framework"]="git clone https://github.com/lockfale/OSINT-Framework && cd OSINT-Framework"
    ["hybrid-analysis"]="curl -s \"https://hybrid-analysis.com/\" | head -1 || true"
    ["abuseipdb"]="curl -s \"https://www.abuseipdb.com/\" | head -1 || true"
    ["safebrowsing"]="pip3 install google-cloud-safebrowsing 2>/dev/null || true"
)

VULN_CATEGORIES=(
    ["nuclei"]="scanner"
    ["nuclei-templates"]="templates"
    ["naabu"]="port"
    ["httpx"]="discovery"
    ["subfinder"]="subdomain"
    ["cvemap"]="cve"
    ["trivy"]="container"
    ["grype"]="container"
    ["semgrep"]="code"
    ["bandit"]="code"
    ["wpscan"]="webapp"
    ["joomscan"]="webapp"
    ["droopescan"]="webapp"
    ["wapiti"]="webapp"
    ["zap"]="webapp"
    ["xsstrike"]="xss"
    ["dalfox"]="xss"
    ["sqlmap"]="sqli"
    ["ssrfmap"]="ssrf"
    ["ssti"]="ssti"
    ["commix"]="command"
    ["trufflehog"]="secrets"
    ["gitleaks"]="secrets"
    ["testssl"]="tls"
    ["sslyze"]="tls"
    ["subjack"]="takeover"
    ["subzy"]="takeover"
    ["corsy"]="cors"
    ["crlfuzz"]="crlf"
    ["bloodhound"]="ad"
    ["crackmapexec"]="ad"
    ["responder"]="ad"
    ["mitm6"]="ad"
    ["secretsdump"]="ad"
    ["lsassy"]="ad"
    ["evil-winrm"]="ad"
    ["nmap"]="port"
    ["masscan"]="port"
    ["zmap"]="port"
    ["autorecon"]="recon"
    ["netcat"]="network"
    ["p0f"]="osint"
    ["xprobe2"]="osint"
    ["shodan-cli"]="subdomain"
    ["censys-cli"]="subdomain"
    ["whatweb"]="web"
    ["aquatone"]="web"
    ["waybackurls"]="web"
    ["gau"]="web"
    ["sublist3r"]="subdomain"
    ["amass"]="subdomain"
    ["dnsenum"]="subdomain"
    ["dnsrecon"]="subdomain"
    ["dnstwist"]="subdomain"
    ["crt.sh"]="subdomain"
    ["testssl.sh"]="tls"
    ["whois"]="osint"
    ["theharvester"]="osint"
    ["pwned"]="leak"
    ["maltego"]="osint"
    ["recon-ng"]="osint"
    ["spiderfoot"]="osint"
    ["twint"]="osint"
    ["exiftool"]="osint"
    ["trufflehog"]="secrets"
    ["gitleaks"]="secrets"
    ["dependency-check"]="vuln"
    ["retire-js"]="vuln"
    ["mobsf"]="mobile"
    ["jadx"]="mobile"
    ["apktool"]="mobile"
    ["cloudmapper"]="cloud"
    ["scoutsuite"]="cloud"
    ["prowler"]="cloud"
    ["securitytrails"]="subdomain"
    ["passivetotal"]="osint"
    ["misp"]="threat-intel"
    ["virustotal"]="threat-intel"
    ["cuckoo"]="malware"
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
    ["bluez"]="bluetooth"
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
    ["builtwith"]="web"
    ["aircrack-ng"]="wireless"
    ["osint-framework"]="osint"
    ["hybrid-analysis"]="malware"
    ["abuseipdb"]="threat-intel"
)

install_tool() {
    local tool=$1
    local cmd=${VULN_TOOLS[$tool]:-""}
    
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

install_all() {
    local total=${#VULN_TOOLS[@]}
    local current=0
    local failed=0
    
    info "Installing $total vulnerability scanning tools..."
    
    for tool in "${!VULN_TOOLS[@]}"; do
        current=$((current + 1))
        printf "\rProgress: [%d/%d] Installing %-25s" "$current" "$total" "$tool"
        
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
    local deps=("go" "git" "curl" "jq" "docker" "nmap" "python3" "pip3")
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

create_custom_templates() {
    local template_dir="${paths_nuclei_custom_templates:-$HOME/.local/share/vuln-tui/custom-templates}"
    mkdir -p "$template_dir"
    
    cat > "$template_dir/exposed-git.yaml" << 'EOF'
id: exposed-git-config
info:
  name: Exposed Git Config
  severity: high
  tags: misconfig,git,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/.git/index"
      - "{{BaseURL}}/.git/logs/HEAD"
    
    matchers:
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
          - "ref: refs/heads/"
        condition: or
EOF

    cat > "$template_dir/exposed-env.yaml" << 'EOF'
id: exposed-env-file
info:
  name: Exposed Environment File
  severity: critical
  tags: exposure, secrets, env

http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.env.local"
      - "{{BaseURL}}/.env.production"
      - "{{BaseURL}}/.env.development"
      - "{{BaseURL}}/config/.env"
      - "{{BaseURL}}/app/.env"
    
    matchers:
      - type: regex
        regex:
          - "(api_key|apikey|secret|password|token|auth)[\\s]*=[\\s]*[\"']?[\\w\\-\\.]+"
          - "AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY"
          - "DATABASE_URL|MONGODB_URI"
        condition: or
EOF

    cat > "$template_dir/debug-mode.yaml" << 'EOF'
id: debug-mode-enabled
info:
  name: Debug Mode Enabled
  severity: medium
  tags: misconfig,debug

http:
  - method: GET
    path:
      - "{{BaseURL}}"
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/console"
    
    matchers:
      - type: word
        words:
          - "debug mode"
          - "stack trace"
          - "Traceback (most recent call last)"
          - "DEBUG=True"
          - "APP_DEBUG"
          - "django.utils.version"
        condition: or
EOF

    cat > "$template_dir/backup-files.yaml" << 'EOF'
id: exposed-backup-files
info:
  name: Exposed Backup Files
  severity: high
  tags: exposure,backup,files

http:
  - method: GET
    path:
      - "{{BaseURL}}.bak"
      - "{{BaseURL}}.swp"
      - "{{BaseURL}}~"
      - "{{BaseURL}}.old"
      - "{{BaseURL}}.orig"
      - "{{BaseURL}}.backup"
      - "{{BaseURL}}/backup.zip"
      - "{{BaseURL}}/backup.tar.gz"
      - "{{BaseURL}}/db.sql"
      - "{{BaseURL}}/dump.sql"
    
    matchers:
      - type: status
        status:
          - 200
EOF

    cat > "$template_dir/misconfigured-cors.yaml" << 'EOF'
id: misconfigured-cors
info:
  name: Misconfigured CORS
  severity: medium
  tags: cors,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    headers:
      Origin: "https://evil.com"
    
    matchers:
      - type: regex
        part: header
        regex:
          - "Access-Control-Allow-Origin:\\s*(?:\\*|https://evil\\.com)"
          - "Access-Control-Allow-Credentials:\\s*true"
        condition: or
EOF

    success "Created custom nuclei templates in: $template_dir"
}

subdomain_discovery() {
    local target=$1
    local output_dir=$2
    
    info "Discovering subdomains for: $target"
    
    if command -v subfinder &>/dev/null; then
        subfinder -d "$target" -silent -o "$output_dir/subs.txt" 2>/dev/null &
    fi
    
    if command -v assetfinder &>/dev/null; then
        assetfinder --subs-only "$target" >> "$output_dir/subs.txt" 2>/dev/null &
    fi
    
    if command -v amass &>/dev/null; then
        amass enum -d "$target" -o "$output_dir/subs_amass.txt" 2>/dev/null &
    fi
    
    curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null >> "$output_dir/subs.txt" &
    
    wait
    
    sort -u "$output_dir/subs.txt" -o "$output_dir/subs.txt"
    local count=$(wc -l < "$output_dir/subs.txt" 2>/dev/null || echo 0)
    success "Found $count subdomains"
}

alive_check() {
    local input_file=$1
    local output_file=$2
    
    if command -v httpx &>/dev/null; then
        cat "$input_file" | httpx -silent -status-code -title -o "$output_file" 2>/dev/null
    else
        cat "$input_file" > "$output_file"
    fi
}

nuclei_scan() {
    local target_file=$1
    local output_file=$2
    
    if ! command -v nuclei &>/dev/null; then
        error "nuclei not installed"
        return 1
    fi
    
    local templates=""
    
    if [ -d "${paths_nuclei_custom_templates:-$HOME/.local/share/vuln-tui/custom-templates}" ]; then
        templates="${paths_nuclei_custom_templates:-$HOME/.local/share/vuln-tui/custom-templates}"
    fi
    
    if [ -n "$templates" ]; then
        nuclei -l "$target_file" \
            -templates "$templates" \
            -severity critical,high,medium \
            -silent \
            -o "$output_file" 2>/dev/null
    else
        nuclei -l "$target_file" \
            -severity critical,high,medium \
            -silent \
            -o "$output_file" 2>/dev/null
    fi
}

web_vuln_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running web vulnerability scans for: $target"
    
    if command -v wpscan &>/dev/null; then
        wpscan --url "$target" --enumerate u,p,t --output "$output_dir/wpscan.txt" 2>/dev/null &
    fi
    
    if command -v nikto &>/dev/null; then
        nikto -h "$target" -output "$output_dir/nikto.txt" 2>/dev/null &
    fi
    
    if command -v zap &>/dev/null; then
        zap-baseline.py -t "$target" -r "$output_dir/zap_report.html" 2>/dev/null &
    fi
    
    wait
    
    local vuln_count=$(wc -l < "$output_dir"/*.txt 2>/dev/null | tail -1 || echo 0)
    success "Web vulnerability scan complete: $vuln_count potential issues"
}

specific_vuln_scan() {
    local target=$1
    local output_dir=$2
    local vuln_type=$3
    
    info "Running $vuln_type scan for: $target"
    
    case "$vuln_type" in
        xss)
            if command -v dalfox &>/dev/null; then
                echo "$target" | dalfox pipe -o "$output_dir/xss.txt" 2>/dev/null
            elif command -v xsstrike &>/dev/null; then
                python3 $(which xsstrike) -u "$target" --output "$output_dir/xss.txt" 2>/dev/null
            fi
            ;;
        sqli)
            if command -v sqlmap &>/dev/null; then
                python3 $(which sqlmap) -u "$target" --batch --output-dir "$output_dir/sqlmap" 2>/dev/null || true
            fi
            ;;
        ssrf)
            if command -v ssrfmap &>/dev/null; then
                python3 $(which ssrfmap) -u "$target" 2>/dev/null > "$output_dir/ssrf.txt" || true
            fi
            ;;
        ssti)
            if command -v tplmap &>/dev/null; then
                python3 $(which tplmap.py) -u "$target" 2>/dev/null > "$output_dir/ssti.txt" || true
            fi
            ;;
        secrets)
            if command -v trufflehog &>/dev/null; then
                trufflehog filesystem "$output_dir" --output "$output_dir/secrets.txt" 2>/dev/null || true
            fi
            ;;
        cors)
            if command -v corsy &>/dev/null; then
                python3 $(which corsy.py) -u "$target" 2>/dev/null > "$output_dir/cors.txt" || true
            fi
            ;;
        crlf)
            if command -v crlfuzz &>/dev/null; then
                crlfuzz -u "$target" -o "$output_dir/crlf.txt" 2>/dev/null || true
            fi
            ;;
    esac
    
    success "$vuln_type scan complete"
}

tls_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running TLS/SSL scan for: $target"
    
    if command -v testssl &>/dev/null; then
        ./testssl.sh "$target" > "$output_dir/tls_report.txt" 2>/dev/null &
    fi
    
    if command -v sslyze &>/dev/null; then
        sslyze --json_out "$output_dir/sslyze.json" "$target" 2>/dev/null &
    fi
    
    wait
    
    success "TLS/SSL scan complete"
}

container_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running container/image scan for: $target"
    
    if command -v trivy &>/dev/null; then
        trivy image "$target" --output "$output_dir/trivy.txt" 2>/dev/null || true
    fi
    
    if command -v grype &>/dev/null; then
        grype "$target" --output "$output_dir/grype.json" 2>/dev/null || true
    fi
    
    success "Container scan complete"
}

cve_scan() {
    local target=$1
    local output_dir=$2
    
    info "Running CVE scan for: $target"
    
    if command -v cvemap &>/dev/null; then
        echo "$target" | cvemap -silent -output "$output_dir/cve.json" 2>/dev/null
    fi
    
    if command -v osv-scanner &>/dev/null; then
        osv-scanner "$target" --output "$output_dir/osv.json" 2>/dev/null || true
    fi
    
    success "CVE scan complete"
}

generate_vuln_report() {
    local target=$1
    local output_dir=$2
    
    local critical_count=$(grep -c "critical" "$output_dir"/*.txt 2>/dev/null | tail -1 || echo 0)
    local high_count=$(grep -c "high" "$output_dir"/*.txt 2>/dev/null | tail -1 || echo 0)
    local medium_count=$(grep -c "medium" "$output_dir"/*.txt 2>/dev/null | tail -1 || echo 0)
    local total_vulns=$((critical_count + high_count + medium_count))
    
    cat > "$output_dir/vuln_report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report: $target</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #ff4444; margin: 0; padding: 20px; }
        .header { background: linear-gradient(135deg, #1a0000, #330000); padding: 30px; border-radius: 10px; margin-bottom: 20px; border: 2px solid #ff0000; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-box { background: #1a0000; border: 2px solid #ff0000; border-radius: 8px; padding: 20px; text-align: center; }
        .stat-box.critical { border-color: #ff0000; background: rgba(255,0,0,0.1); }
        .stat-box.high { border-color: #ff8800; background: rgba(255,136,0,0.1); }
        .stat-box.medium { border-color: #ffff00; background: rgba(255,255,0,0.1); }
        .stat-value { font-size: 3em; font-weight: bold; }
        .finding { background: #1a0000; border-left: 4px solid #ff0000; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .finding.critical { border-left-color: #ff0000; }
        .finding.high { border-left-color: #ff8800; }
        .finding.medium { border-left-color: #ffff00; }
        .severity { padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .severity.critical { background: #ff0000; color: #000; }
        .severity.high { background: #ff8800; color: #000; }
        .severity.medium { background: #ffff00; color: #000; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #333; padding: 10px; text-align: left; }
        th { background: #1a0000; color: #ff0000; }
        h1, h2, h3 { color: #ff0000; }
    </style>
</head>
<body>
    <div class="header">
        <h1>⚠️ VULNERABILITY REPORT: $target</h1>
        <p>Generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        <p>Version: $VERSION</p>
        <p>Status: $([ $total_vulns -gt 0 ] && echo "VULNERABILITIES FOUND" || echo "NO CRITICAL ISSUES")</p>
    </div>
    
    <div class="stats">
        <div class="stat-box critical">
            <div>CRITICAL</div>
            <div class="stat-value">$critical_count</div>
        </div>
        <div class="stat-box high">
            <div>HIGH</div>
            <div class="stat-value">$high_count</div>
        </div>
        <div class="stat-box medium">
            <div>MEDIUM</div>
            <div class="stat-value">$medium_count</div>
        </div>
        <div class="stat-box">
            <div>TOTAL</div>
            <div class="stat-value">$total_vulns</div>
        </div>
    </div>
    
    <h2>📊 Scan Results</h2>
    <table>
        <tr><th>Scan Type</th><th>Results</th></tr>
        <tr><td>Nuclei</td><td>$(wc -l < "$output_dir/nuclei.txt" 2>/dev/null || echo 0) findings</td></tr>
        <tr><td>Web Apps</td><td>$(wc -l < "$output_dir"/web*.txt 2>/dev/null | tail -1 || echo 0) findings</td></tr>
        <tr><td>TLS/SSL</td><td>$(wc -l < "$output_dir"/tls*.txt 2>/dev/null | tail -1 || echo 0) issues</td></tr>
        <tr><td>CVE</td><td>$(wc -l < "$output_dir"/cve*.json 2>/dev/null | tail -1 || echo 0) CVEs</td></tr>
    </table>
    
    <h2>📁 Output Files</h2>
    <table>
        <tr><th>File</th><th>Size</th></tr>
        $(for f in "$output_dir"/*; do [ -f "$f" ] && echo "<tr><td>$(basename "$f")</td><td>$(du -h "$f" | cut -f1)</td></tr>"; done)
    </table>
</body>
</html>
EOF

    success "Vulnerability report generated: $output_dir/vuln_report.html"
}

quick_scan() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         QUICK VULNERABILITY SCAN              ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Enter target (domain/IP): " TARGET
    
    if [ -z "$TARGET" ]; then
        error "Target cannot be empty"
        return 1
    fi
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$OUTPUT_DIR/vuln_${timestamp}_${TARGET//[^a-zA-Z0-9]/_}"
    mkdir -p "$output_dir"
    
    subdomain_discovery "$TARGET" "$output_dir"
    alive_check "$output_dir/subs.txt" "$output_dir/alive.txt"
    nuclei_scan "$output_dir/alive.txt" "$output_dir/nuclei.txt"
    generate_vuln_report "$TARGET" "$output_dir"
    
    success "Quick vulnerability scan complete! Results in: $output_dir"
}

full_scan() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         FULL VULNERABILITY SCAN               ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Enter target (domain/IP): " TARGET
    
    if [ -z "$TARGET" ]; then
        error "Target cannot be empty"
        return 1
    fi
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$OUTPUT_DIR/vuln_full_${timestamp}_${TARGET//[^a-zA-Z0-9]/_}"
    mkdir -p "$output_dir"
    
    subdomain_discovery "$TARGET" "$output_dir"
    alive_check "$output_dir/subs.txt" "$output_dir/alive.txt"
    nuclei_scan "$output_dir/alive.txt" "$output_dir/nuclei.txt"
    web_vuln_scan "$TARGET" "$output_dir"
    tls_scan "$TARGET" "$output_dir"
    cve_scan "$TARGET" "$output_dir"
    generate_vuln_report "$TARGET" "$output_dir"
    
    success "Full vulnerability scan complete! Results in: $output_dir"
}

targeted_scan() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         TARGETED VULNERABILITY SCAN           ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "Vulnerability types:"
    echo "  1. XSS (Cross-Site Scripting)"
    echo "  2. SQLi (SQL Injection)"
    echo "  3. SSRF (Server-Side Request Forgery)"
    echo "  4. SSTI (Server-Side Template Injection)"
    echo "  5. Secrets/Leaks"
    echo "  6. CORS Misconfiguration"
    echo "  7. CRLF Injection"
    echo "  8. All Web Vulnerabilities"
    
    read -p "Select vulnerability type (1-8): " VULN_TYPE
    
    read -p "Enter target: " TARGET
    
    if [ -z "$TARGET" ]; then
        error "Target cannot be empty"
        return 1
    fi
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local output_dir="$OUTPUT_DIR/targeted_${timestamp}_${TARGET//[^a-zA-Z0-9]/_}"
    mkdir -p "$output_dir"
    
    case "$VULN_TYPE" in
        1) specific_vuln_scan "$TARGET" "$output_dir" "xss" ;;
        2) specific_vuln_scan "$TARGET" "$output_dir" "sqli" ;;
        3) specific_vuln_scan "$TARGET" "$output_dir" "ssrf" ;;
        4) specific_vuln_scan "$TARGET" "$output_dir" "ssti" ;;
        5) specific_vuln_scan "$TARGET" "$output_dir" "secrets" ;;
        6) specific_vuln_scan "$TARGET" "$output_dir" "cors" ;;
        7) specific_vuln_scan "$TARGET" "$output_dir" "crlf" ;;
        8) web_vuln_scan "$TARGET" "$output_dir" ;;
        *) error "Invalid selection"; return 1 ;;
    esac
    
    success "Targeted scan complete! Results in: $output_dir"
}

single_tool() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         SINGLE TOOL EXECUTION                 ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo "Available vulnerability tools:"
    local index=1
    for tool in "${!VULN_TOOLS[@]}"; do
        printf "  %3d. %-25s [%s]\n" "$index" "$tool" "${VULN_CATEGORIES[$tool]:-unknown}"
        index=$((index + 1))
    done
    
    echo ""
    read -p "Select tool number (or name): " selection
    
    if [[ "$selection" =~ ^[0-9]+$ ]]; then
        local tool_names=("${!VULN_TOOLS[@]}")
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
    
    if [ -z "${VULN_TOOLS[$TOOL]:-}" ]; then
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
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         INSTALLED TOOLS                       ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    local installed=0
    local not_installed=0
    
    for tool in "${!VULN_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null 2>&1; then
            echo -e "  ${GREEN}[✓]${NC} $tool"
            installed=$((installed + 1))
        else
            echo -e "  ${RED}[✗]${NC} $tool"
            not_installed=$((not_installed + 1))
        fi
    done
    
    echo ""
    echo "Installed: $installed | Not installed: $not_installed | Total: ${#VULN_TOOLS[@]}"
}

show_help() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║         VULN TUI v$VERSION                     ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "OPTIONS:"
    echo "  1  Quick Scan        - Fast vulnerability assessment"
    echo "  2  Full Scan         - Complete vulnerability analysis"
    echo "  3  Targeted Scan     - Scan for specific vulnerability types"
    echo "  4  Single Tool       - Run any tool individually"
    echo "  5  Install Tools     - Install/verify all tools"
    echo "  6  List Tools        - Show installed tools status"
    echo "  7  Config            - Edit configuration"
    echo "  8  Templates         - Create custom nuclei templates"
    echo "  9  Update            - Update all tools"
    echo "  H  Help              - Show this help"
    echo "  Q  Quit              - Exit"
    echo ""
    echo "EXAMPLES:"
    echo "  vuln-tui             # Start interactive menu"
    echo "  vuln-tui quick       # Quick scan"
    echo "  vuln-tui full        # Full scan"
    echo "  vuln-tui targeted 1  # XSS scan"
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
    info "Updating all vulnerability scanning tools..."
    
    for tool in "${!VULN_TOOLS[@]}"; do
        if command -v "$tool" &>/dev/null 2>&1; then
            case "$tool" in
                nuclei)
                    nuclei -update-templates 2>/dev/null || true
                    ;;
                nuclei|naabu|httpx|subfinder|dnsx|cvemap)
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
        echo -e "${RED}"
        echo "╔═══════════════════════════════════════════════╗"
        echo "║         VULN TUI v$VERSION                     ║"
        echo "║         ${#VULN_TOOLS[@]} Tools Available               ║"
        echo "╚═══════════════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        echo "  [1] Quick Scan"
        echo "  [2] Full Scan"
        echo "  [3] Targeted Scan"
        echo "  [4] Single Tool"
        echo "  [5] Install Tools"
        echo "  [6] List Tools"
        echo "  [7] Config"
        echo "  [8] Templates"
        echo "  [9] Update"
        echo "  [H] Help"
        echo "  [Q] Quit"
        echo ""
        read -p "Select option: " choice
        
        case "$choice" in
            1) quick_scan ;;
            2) full_scan ;;
            3) targeted_scan ;;
            4) single_tool ;;
            5) install_all ;;
            6) list_tools ;;
            7) edit_config ;;
            8) create_custom_templates ;;
            9) update_tools ;;
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
        targeted)
            load_config
            targeted_scan
            ;;
        install)
            install_all
            ;;
        list)
            list_tools
            ;;
        config)
            edit_config
            ;;
        templates)
            create_custom_templates
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
