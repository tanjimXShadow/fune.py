# Fune.py

## Description
`fune.py` is a Python-based tool for crawling websites, extracting links, detecting sensitive data patterns, and finding JavaScript endpoints.

## Features
- Asynchronous crawling of websites.
- Detects sensitive data like API keys, JWT tokens, and private keys using regex.
- Extracts JavaScript endpoints and query parameters.
- Supports deep scanning of URLs.

## Installation

##. Clone the repository:
   ```bash
   git clone https://github.com/Tanjimul1/fune.py.git
   cd fune.py

#Install dependencies:
1.  pip install -r requirements.txt  2. python3 fune.py

#Include all Python libraries your script depends on. Create a requirements.txt file with the following content:

✅ Prerequisites :

beautifulsoup4
requests
lxml
aiohttp
rich
colorama
termcolor

✅ Step by step with commands :
//Install python3-venv
sudo apt update
sudo apt install python3-venv -y

//Creat Virtual Environment:
cd /home/tanjimul/fune.py
python3 -m venv venv
source venv/bin/activate

//Download All Necessary Libraries : 
pip install beautifulsoup4 requests lxml aiohttp rich colorama termcolor

//Update :
pip freeze > requirements.txt

//Run Tool :
python3 fune.py


# Run the following command to generate it automatically if you already have these libraries installed:
pip freeze > requirements.txt
