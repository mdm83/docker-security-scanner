from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
import requests
import dns.resolver
import logging
import time
import urllib3
import ssl
import http.client
import nmap
import os
import re
from datetime import datetime
from typing import List, Optional

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='scanner.log'
)

# Ustawienie timeoutów
dns.resolver.timeout = 2
dns.resolver.lifetime = 2
REQUEST_TIMEOUT = 5

# Lista domen do podpowiadania
DOMAINS = ["apple.com", "github.com", "onet.pl", "google.com", "facebook.com", "scanme.nmap.org"]
COMPLETER = WordCompleter(DOMAINS, ignore_case=True)
SESSION = PromptSession("Podaj domenę (np. apple.com, 'quit' by zakończyć): ", completer=COMPLETER)

# Inicjalizacja Nmapa
NM = nmap.PortScanner()

def get_subdomains(domain: str, wordlist_path: Optional[str] = None) -> List[str]:
    """Pobiera subdomeny dla danej domeny za pomocą rekordów DNS i opcjonalnej wordlisty.

    Args:
        domain (str): Domena do analizy (np. 'example.com').
        wordlist_path (str, optional): Ścieżka do pliku z wordlistą subdomen.

    Returns:
        List[str]: Lista unikalnych subdomen.
    """
    subdomains = set()
    resolver = dns.resolver.Resolver()

    def resolve_records(record_type: str) -> List[str]:
        try:
            answers = resolver.resolve(domain, record_type)
            results = [answer.to_text().rstrip('.') for answer in answers]
            logging.info(f"Znaleziono {record_type} dla {domain}: {results}")
            return results
        except Exception as e:
            logging.warning(f"Zapytanie {record_type} dla {domain} nie powiodło się: {e}")
            return []

    start_time = time.time()
    logging.info(f"Rozpoczynanie skanowania subdomen dla {domain}")

    # NS
    ns_records = resolve_records('NS')
    for ns in ns_records:
        subdomains.add(ns)
        try:
            a_records = resolver.resolve(ns, 'A')
            ips = [a.to_text() for a in a_records]
            for ip in ips:
                try:
                    ptr_records = resolver.resolve_address(ip)
                    subs = [ptr.to_text().rstrip('.') for ptr in ptr_records]
                    subdomains.update(subs)
                except Exception as e:
                    logging.debug(f"Reverse DNS dla {ip} nie powiodło się: {e}")
        except Exception as e:
            logging.debug(f"Zapytanie A dla {ns} nie powiodło się: {e}")

    # MX
    mx_records = resolve_records('MX')
    for mx in mx_records:
        subdomain = mx.split()[-1].rstrip('.')
        subdomains.add(subdomain)

    # TXT
    txt_records = resolve_records('TXT')
    for txt in txt_records:
        if '.' in txt:
            potential_sub = txt.split('.')[0]
            if potential_sub and potential_sub != domain:
                subdomains.add(f"{potential_sub}.{domain}")

    # CNAME
    cname_records = resolve_records('CNAME')
    for cname in cname_records:
        if domain in cname:
            subdomains.add(cname)

    # SOA
    soa_records = resolve_records('SOA')
    for soa in soa_records:
        if '.' in soa:
            potential_sub = soa.split('.')[0]
            if potential_sub and potential_sub != domain:
                subdomains.add(f"{potential_sub}.{domain}")

    # Bruteforce z wordlistą
    if wordlist_path:
        try:
            with open(wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            logging.info(f"Bruteforce z wordlistą: {len(wordlist)} wpisów")
            for sub in wordlist:
                test_domain = f"{sub}.{domain}"
                try:
                    resolver.resolve(test_domain, 'A')
                    subdomains.add(test_domain)
                    logging.info(f"Znaleziono subdomenę: {test_domain}")
                except:
                    pass
        except Exception as e:
            logging.error(f"Błąd wordlisty {wordlist_path}: {e}")

    end_time = time.time()
    logging.info(f"Skanowanie subdomen zakończone w {end_time - start_time:.2f}s. Znaleziono {len(subdomains)} subdomen.")
    return sorted(list(re.sub(r'[^a-zA-Z0-9.-]', '', sub) for sub in subdomains))

def scan_domain(domain_part: str, report) -> None:
    """Skanuje domenę pod kątem nagłówków HTTP, portów, OS i wersji usług.

    Args:
        domain_part (str): Domena lub subdomena do analizy.
        report (file): Plik raportu Markdown.
    """
    domain_part = re.sub(r'[^a-zA-Z0-9.-]', '', domain_part)
    http_url = f"http://{domain_part}"
    https_url = f"https://{domain_part}"
    redirect_status = None

    # Sprawdzanie portu 443 i wybór protokołu
    response_url = https_url
    logging.info(f"Sprawdzanie portu 443 dla {domain_part}")
    try:
        NM.scan(domain_part, "443", arguments="-T4 --max-retries 1 --host-timeout 30s")
        port_443_state = "closed"
        for h in NM.all_hosts():
            if 'tcp' in NM[h] and 443 in NM[h]['tcp']:
                port_443_state = NM[h]['tcp'][443]['state']
        if port_443_state == "closed":
            response_url = http_url
            print(f"⚠️ Ostrzeżenie: Port 443 (HTTPS) jest zamknięty dla {domain_part} – użyto HTTP.")
    except nmap.nmap.PortScannerError as e:
        print(f"⚠️ Błąd Nmapa przy skanowaniu portu 443 dla {domain_part}: {e}")
        logging.error(f"Błąd Nmapa (port 443) dla {domain_part}: {e}")
        port_443_state = "unknown"

    # Sprawdzanie przekierowania HTTP
    try:
        http_response = requests.get(http_url, allow_redirects=False)
        redirect_status = http_response.status_code
        redirect_msg = f"HTTP Redirect: {redirect_status} - " + ("Przekierowanie jak z bajki!" if redirect_status in [301, 302] else "Brak przekierowania – słabo!")
    except requests.exceptions.RequestException:
        redirect_msg = "HTTP Redirect: BRAK - Nie działa HTTP albo coś się sypło!"

    # Skanowanie nagłówków HTTP
    try:
        start_time = time.time()
        response = requests.get(response_url)
        end_time = time.time()
        headers = response.headers

        print(f"\nSkanuję {domain_part.upper()} – trzymaj kciuki!")
        hsts = headers.get("Strict-Transport-Security")
        hsts_msg = "HSTS: " + (f"{hsts} - HTTPS na sterydach!" if hsts else "BRAK - 2025, a Ty bez HTTPS?!")
        print(hsts_msg)

        xcto = headers.get("X-Content-Type-Options")
        xcto_msg = "X-Content-Type-Options: " + (f"{xcto} - Nosniff jak pro!" if xcto == "nosniff" else "BRAK - MIME party dla hakerów!")
        print(xcto_msg)

        xfo = headers.get("X-Frame-Options")
        xfo_msg = "X-Frame-Options: " + (f"{xfo} - Clickjacking? Nie tu!" if xfo else "BRAK - Ramka czeka!")
        print(xfo_msg)

        csp = headers.get("Content-Security-Policy")
        csp_msg = "CSP: " + (f"{csp[:50]}... - Zasady jak w wojsku!" if csp else "BRAK - Skrypty szaleją!")
        print(csp_msg)

        status_msg = f"Status: {response.status_code} - " + ("Strona żyje!" if response.status_code == 200 else "Coś się sypnęło!")
        print(status_msg)
        print(redirect_msg)

        score = 0
        if hsts: score += 3
        if xcto == "nosniff": score += 2
        if xfo: score += 2
        if csp: score += 2
        if redirect_status in [301, 302]: score += 1
        if response.status_code == 200: score += 1

        tls_version = "Brak – port 443 zamknięty"
        tls_msg = "TLS: Brak – port 443 zamknięty"
        tls_score_msg = "TLSv1.3 brak – 0 punktów."
        cert_msg = "Certyfikat SSL: Brak – port 443 zamknięty"
        http_version = "Brak – port 443 zamknięty"
        http_version_msg = "HTTP Version: Brak – port 443 zamknięty"
        if port_443_state != "closed" and port_443_state != "unknown":
            try:
                http_pool = urllib3.HTTPSConnectionPool(domain_part, port=443)
                conn = http_pool._get_conn()
                conn.connect()
                tls_version = conn.sock.version()
                if tls_version == "TLSv1.3": score += 1
                tls_msg = f"TLS: {tls_version} - " + ("Bezpieczeństwo level mistrz!" if tls_version == "TLSv1.3" else "Stare jak świat – czas na update!")
                tls_score_msg = "TLSv1.3 dał +1 punkt!" if tls_version == "TLSv1.3" else "TLSv1.3 brak – 0 punktów."

                conn_http = http.client.HTTPSConnection(domain_part)
                conn_http.request("HEAD", "/")
                http_response = conn_http.getresponse()
                http_version = "HTTP/2" if http_response.version == 20 else "HTTP/1.1"
                http_version_msg = f"HTTP Version: {http_version} - " + ("Nowoczesne!" if http_version == "HTTP/2" else "Standardowo.")
                conn_http.close()

                cert = conn.sock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (expiry_date - datetime.now()).days
                cert_msg = f"Certyfikat SSL wygasa: {expiry_date.strftime('%Y-%m-%d')} - " + (f"Spoko, masz jeszcze {days_to_expiry} dni!" if days_to_expiry > 30 else "Uważaj, wygasa za mniej niż 30 dni!")
            except Exception as e:
                print(f"⚠️ Błąd analizy TLS dla {domain_part}: {e}")
                logging.error(f"Błąd TLS dla {domain_part}: {e}")

        score_msg = f"Score: {score}/12 - " + ("Kozak!" if score >= 10 else "Może być lepiej, ziom!")
        print(score_msg)
        print(tls_msg)
        print(tls_score_msg)
        print(http_version_msg)
        print(cert_msg)

        response_time = (end_time - start_time) * 1000
        response_time_msg = f"Czas odpowiedzi: {response_time:.2f} ms - " + ("Błyskawica!" if response_time < 100 else "Całkiem spoko!")
        print(response_time_msg)

        report.write(f"## {domain_part}\n")
        report.write(f"- {hsts_msg}\n")
        report.write(f"- {xcto_msg}\n")
        report.write(f"- {xfo_msg}\n")
        report.write(f"- {csp_msg}\n")
        report.write(f"- {status_msg}\n")
        report.write(f"- {redirect_msg}\n")
        report.write(f"- {score_msg}\n")
        report.write(f"- {tls_msg}\n")
        report.write(f"- {tls_score_msg}\n")
        report.write(f"- {http_version_msg}\n")
        report.write(f"- {response_time_msg}\n")
        report.write(f"- {cert_msg}\n\n")

    except requests.exceptions.RequestException as e:
        print(f"{domain_part} się sypnął – pewnie nie obsługuje HTTP/HTTPS!")
        logging.info(f"Brak odpowiedzi HTTP/HTTPS dla {domain_part}: {e}")

    # Skanowanie portów (22-443) z Nmapem
    logging.info(f"Rozpoczynanie skanowania portów dla {domain_part}")
    print(f"\nSkanowanie portów (22-443) dla {domain_part}:")
    try:
        NM.scan(domain_part, "22-443", arguments="-T4 --max-retries 1 --host-timeout 30s")
        if NM.all_hosts():
            for h in NM.all_hosts():
                print(f"\nHost: {h} jest aktywny")
                for proto in NM[h].all_protocols():
                    for port in NM[h][proto].keys():
                        state = NM[h][proto][port]['state']
                        service = NM[h][proto][port].get('name', 'nieznana')
                        print(f"Port {port}: {state} ({service})")
                        if port == 31337 and state == 'open':
                            print("⚠️ Ostrzeżenie: Port 31337 może wskazywać na backdoor (np. trojan Elite)!")
            report.write(f"### Porty dla {domain_part}\n")
            report.write(f"- {NM.csv()}\n\n")
        else:
            print("ℹ️ Brak aktywnych hostów lub portów w zakresie 22-443.")
            report.write(f"### Porty dla {domain_part}\n- Brak\n\n")
    except nmap.nmap.PortScannerError as e:
        print(f"⚠️ Błąd Nmapa przy skanowaniu portów dla {domain_part}: {e}")
        logging.error(f"Błąd Nmapa (porty) dla {domain_part}: {e}")

    # Wykrywanie OS – tylko z rootem
    logging.info(f"Rozpoczynanie wykrywania OS dla {domain_part}")
    print(f"\nWykrywanie systemu operacyjnego dla {domain_part}:")
    if os.geteuid() == 0:
        try:
            NM.scan(domain_part, arguments="-O -T4 --max-retries 1 --host-timeout 30s")
            if NM.all_hosts():
                for h in NM.all_hosts():
                    if 'osmatch' in NM[h]:
                        for os_match in NM[h]['osmatch']:
                            print(f"OS: {os_match['name']} (dokładność: {os_match['accuracy']}%)")
                            if 'macOS' in os_match['name']:
                                print("ℹ️ Info: To macOS – upewnij się, że system jest aktualny!")
                                if '12' in os_match['name']:
                                    print("⚠️ Ostrzeżenie: Nmap zgaduje macOS 12 (Monterey) – sprawdź aktualizacje!")
                        report.write(f"### OS dla {domain_part}\n")
                        report.write(f"- {os_match['name']} (dokładność: {os_match['accuracy']}%)\n\n")
                    else:
                        print("ℹ️ Info: Nie udało się wykryć OS – brak danych.")
                        report.write(f"### OS dla {domain_part}\n- Brak danych\n\n")
            else:
                print("ℹ️ Info: Brak aktywnych hostów dla OS detection.")
                report.write(f"### OS dla {domain_part}\n- Brak hostów\n\n")
        except nmap.nmap.PortScannerError as e:
            print(f"⚠️ Błąd Nmapa: {e}")
            logging.error(f"Błąd wykrywania OS dla {domain_part}: {e}")
    else:
        print("⚠️ Wykrywanie OS pominięte – uruchom z sudo, jeśli chcesz OS detection!")
        logging.warning(f"Wykrywanie OS pominięte dla {domain_part} – brak uprawnień root.")
        report.write(f"### OS dla {domain_part}\n- Pominięto (brak roota)\n\n")

    # Wersje usług
    logging.info(f"Rozpoczynanie skanowania wersji usług dla {domain_part}")
    print(f"\nWersje usług na portach 22 i 80 dla {domain_part}:")
    try:
        NM.scan(domain_part, "22,80", arguments="-sV -T4 --max-retries 1 --host-timeout 30s")
        if NM.all_hosts():
            for h in NM.all_hosts():
                for proto in NM[h].all_protocols():
                    for port in NM[h][proto].keys():
                        service = NM[h][proto][port].get('name', 'nieznana')
                        version = NM[h][proto][port].get('version', 'brak')
                        print(f"Port {port}: {service} (wersja: {version})")
                        if service == 'http' and 'Apache' in version and '2.4.7' in version:
                            print("⚠️ Ostrzeżenie: Apache 2.4.7 ma znane podatności (np. CVE-2014-0226)!")
                        if service == 'ssh' and 'OpenSSH' in version and '6.6.1' in version:
                            print("⚠️ Ostrzeżenie: OpenSSH 6.6.1 może mieć podatności – sprawdź aktualizacje!")
            report.write(f"### Wersje usług dla {domain_part}\n")
            report.write(f"- {NM.csv()}\n\n")
        else:
            print("ℹ️ Info: Brak aktywnych usług na portach 22 i 80.")
            report.write(f"### Wersje usług dla {domain_part}\n- Brak\n\n")
    except nmap.nmap.PortScannerError as e:
        print(f"⚠️ Błąd Nmapa przy wersjach usług dla {domain_part}: {e}")
        logging.error(f"Błąd Nmapa (wersje usług) dla {domain_part}: {e}")

print("Raport w report.md – jesteś mistrz!")

if __name__ == "__main__":
    with open("report.md", "a") as report:
        while True:
            domain = SESSION.prompt() or "apple.com"
            if domain.lower() == "quit":
                print("Koniec programu – idź na kawę!")
                break
            subdomains = get_subdomains(domain, "subdomains.txt")
            print(f"\nZnalezione subdomeny dla {domain.upper()}:")
            if subdomains:
                for sub in subdomains:
                    print(f"- {sub}")
            else:
                print("Brak subdomen – może słaba domena?")
            report.write(f"## Subdomeny dla {domain}\n")
            report.write("- " + "\n- ".join(subdomains) + "\n\n" if subdomains else "- Brak\n\n")

            domains_to_scan = [domain] + subdomains
            for domain_part in domains_to_scan:
                scan_domain(domain_part, report)