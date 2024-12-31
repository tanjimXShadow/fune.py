import asyncio
import os
import re
from time import sleep
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import aiohttp
from rich.console import Console

# Console for rich output
console = Console()

# Headers for requests
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

# Define the REGEX_PATTERNS dictionary
REGEX_PATTERNS = {
    "API Key": r"(?:api[_\-]?key|access[_\-]?token)[\"']?[:=][\"']?([a-zA-Z0-9\-_]{32,})",
    "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Private Key": r"-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\+\/\n]+-----END PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}

# Animated Banner Function
def animated_banner():
    text = """
    ===========================================
    ███████╗██╗   ██╗██╗███╗   ██╗███████╗    
    ██╔════╝██║   ██║██║████╗  ██║██╔════╝    
    █████╗  ██║   ██║██║██╔██╗ ██║█████╗      
    ██╔══╝  ██║   ██║██║██║╚██╗██║██╔══╝      
    ██║     ╚██████╔╝██║██║ ╚████║███████╗    
    ╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝    
       Extended LinkFinder Framework [ Modern ]
    
       Author : Md. Tanjimul Islam Sifat
   ===========================================
    """
    for char in text:
        console.print(char, end='', style="bold green")
        sleep(0.01)
    console.print("\n")

# Asynchronous function to fetch a URL
async def fetch_url(session, url):
    try:
        async with session.get(url, headers=HEADERS, timeout=10) as response:
            if response.status == 200:
                return await response.text()
            else:
                console.print(f"[-] Failed to fetch {url} (Status: {response.status})", style="bold red")
                return None
    except Exception as e:
        console.print(f"[-] Error fetching {url}: {e}", style="bold red")
        return None

# Extract query parameters from URLs
def extract_query_parameters(urls):
    console.print("[+] Extracting query parameters...", style="bold yellow")
    parameters = {}
    for url in urls:
        parsed_url = urlparse(url)
        query = parse_qs(parsed_url.query)
        if query:
            parameters[url] = query
            console.print(f"    {url}:", style="bold blue")
            for param, value in query.items():
                console.print(f"        {param} = {value}", style="cyan")
    return parameters

# Extract sensitive data from a page's content
def extract_sensitive_data(content, url):
    findings = []
    for name, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings.append((name, matches))
            console.print(f"[!] Found {len(matches)} {name}(s) on {url}:", style="bold yellow")
            for match in matches:
                console.print(f"    {match}", style="bold cyan")
    return findings

# Parse JavaScript content to find endpoints using regex
def find_js_endpoints(js_content):
    console.print("[+] Finding JavaScript endpoints...", style="bold yellow")
    matches = re.finditer(r"""['"]((http|https):\/\/[^\s'"<>]+)['"]""", js_content, re.VERBOSE)
    return {m.group(1) for m in matches if m}

# Asynchronous function to extract links
async def extract_links(session, url):
    content = await fetch_url(session, url)
    if not content:
        return set(), None

    # Extract all links and scan for sensitive data
    soup = BeautifulSoup(content, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        full_url = urljoin(url, href)
        links.add(full_url)

    # Scan the page content for sensitive data
    extract_sensitive_data(content, url)
    return links, content

# Asynchronous function to scan for JavaScript endpoints
async def scan_js(session, urls):
    js_urls = [url for url in urls if url.endswith((".js", ".json", ".css", ".html"))]
    all_endpoints = set()

    for js_url in js_urls:
        console.print(f"[+] Fetching JS/JSON/CSS/HTML file: {js_url}", style="bold yellow")
        js_content = await fetch_url(session, js_url)
        if js_content:
            endpoints = find_js_endpoints(js_content)
            all_endpoints.update(endpoints)
            console.print(f"[+] Found {len(endpoints)} endpoints in {js_url}", style="bold green")
            for endpoint in endpoints:
                console.print(endpoint, style="cyan")

    return all_endpoints

# Deep scan: Crawl and extract all hidden parameters and endpoints
async def deep_scan(base_url, depth=2):
    console.print(f"[+] Starting deep scan for {base_url}...", style="bold yellow")
    async with aiohttp.ClientSession() as session:
        to_visit = {base_url}
        visited = set()
        all_links = set()

        for _ in range(depth):
            new_links = set()
            tasks = [extract_links(session, url) for url in to_visit if url not in visited]
            results = await asyncio.gather(*tasks)

            for links, content in results:
                if links:
                    new_links.update(links)
                    all_links.update(links)

            visited.update(to_visit)
            to_visit = new_links - visited

        # Extract query parameters
        extract_query_parameters(all_links)

        endpoints = await scan_js(session, all_links)
        return all_links, endpoints

# Main program loop
async def main():
    animated_banner()
    
    # Get the user input
    input_value = console.input("[yellow]Enter a website URL or file path (e.g., /home/kali/domain.txt): [/]")
    
    # If the input is a file path, read the domains from the file
    if os.path.isfile(input_value):
        with open(input_value, 'r') as file:
            urls = file.readlines()
        urls = [url.strip() for url in urls]  # Clean up any extra newlines/spaces
    else:
        # If it's a single URL, process it as such
        urls = [input_value.strip()]

    # Start the deep scan for each URL in the list
    for url in urls:
        console.print(f"[+] Scanning {url}...", style="bold green")
        all_links, endpoints = await deep_scan(url)
        
        # Output all found links and endpoints
        console.print("\n[+] Found links:", style="bold cyan")
        for link in all_links:
            console.print(link, style="blue")
        
        console.print("\n[+] Found JavaScript endpoints:", style="bold cyan")
        for endpoint in endpoints:
            console.print(endpoint, style="green")

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())

