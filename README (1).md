# 🔍 Sec Recon AI

An AI-powered reconnaissance tool for automated target enumeration and
analysis. Supports multiple scanning modes from passive intelligence
gathering to aggressive active scanning.

------------------------------------------------------------------------

## 🚀 Getting Started

Follow these steps to set up and run the project locally.

------------------------------------------------------------------------

## 📦 1. Clone the Repository

``` bash
git clone https://github.com/your-username/sec-recon-ai.git
cd sec-recon-ai
```

------------------------------------------------------------------------

## 🔐 2. Configure Environment Variables

``` bash
cp .env.example .env
```

Open the `.env` file and add your API keys:

``` env
SHODAN_API_KEY=your_shodan_api_key
GITHUB_TOKEN=your_github_token
```

------------------------------------------------------------------------

## 🐍 3. Set Up Virtual Environment (Recommended)

``` bash
python3 -m venv venv
source venv/bin/activate
```

> ⚠️ For Kali/Linux users using `zsh`, the above command works fine.

------------------------------------------------------------------------

## 📥 4. Install Python Dependencies

``` bash
pip install --upgrade pip
pip install -r requirements.txt
```

------------------------------------------------------------------------

## 🛠️ 5. Install External Tools

### 🐧 Debian / Kali / Ubuntu

``` bash
sudo apt update
sudo apt install -y nmap gobuster whatweb
```

### Install Sublist3r

``` bash
pip install sublist3r
```

### 🍎 macOS (Homebrew)

``` bash
brew install nmap gobuster whatweb
```

------------------------------------------------------------------------

## ▶️ 6. Run the Tool

### 🔹 Normal Mode

``` bash
python main.py -d example.com
```

### 🔹 Stealth Mode (Passive Recon Only)

``` bash
python main.py -d example.com --mode stealth
```

### 🔹 Aggressive Mode (Active Scanning + Save Output)

``` bash
python main.py -d example.com --mode aggressive --save
```

------------------------------------------------------------------------

## 📁 Output

-   Results can be saved in **JSON format** using the `--save` flag\
-   Useful for:
    -   Automation
    -   Reporting
    -   Further analysis

------------------------------------------------------------------------

## ⚠️ Notes

-   Ensure all external tools are installed and available in your system
    `$PATH`
-   Use **Python 3.11 or 3.12** for best compatibility
-   Some scans may require **root privileges**

------------------------------------------------------------------------

## 📌 Features

-   Subdomain Enumeration\
-   Port Scanning\
-   Technology Fingerprinting\
-   Directory Bruteforcing\
-   API Integrations (Shodan, GitHub)\
-   Multiple Scan Modes (Stealth / Normal / Aggressive)

------------------------------------------------------------------------

## 📜 License

MIT License

------------------------------------------------------------------------

## ⚡ Disclaimer

This tool is intended for **educational and ethical use only**.\
Use it only on systems you own or have permission to test.

------------------------------------------------------------------------

## ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub!
