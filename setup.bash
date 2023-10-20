#!/bin/bash
# Run the `setup.bash` file to install all required dependencies

echo "[*] Installing python3 dependencies!"
python -m pip install -r requirements.txt

echo "[*] Installing dalfox!"
go install github.com/hahwul/dalfox/v2@latest

echo "[*] Installing waybackurls!"
go install github.com/tomnomnom/waybackurls@latest

echo "[*] Installing amass!"
go install -v github.com/owasp-amass/amass/v3/...@master

echo "[*] Installing subfinder!"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[*] Installing httpx!"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[*] Installing nuclei!"
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo "[*] Installing gf!"
go install -v github.com/tomnomnom/gf@latest

echo "[*] Installing gf-Patterns!"
git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir .gf
mv Gf-Patterns/*.json .gf/
rm -r Gf-Patterns/

echo "[*] Installing dnsx!"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "[*] Installing eyewitness!"
apt install eyewitness

echo "[*] Installing prips!"
apt install prips

echo "[*] Installing waymore!"
git clone https://github.com/xnl-h4ck3r/waymore.git
python waymore/setup.py install
pip3 install -r waymore/requirements.txt

echo "[*] Installing retireJS!"
apt install nodejs
apt install npm
npm install -g retire

echo "[+] Completing the installation, thank you for being with us during this installation!"
apt -y autoremove
echo "[+++] Done!"
