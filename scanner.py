from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
import requests
from datetime import datetime
import urllib3
import ssl
import time
import http.client

domains = ["apple.com", "github.com", "onet.pl", "google.com", "facebook.com"]
completer = WordCompleter(domains, ignore_case=True)
session = PromptSession("Podaj domenę (np. apple.com, 'quit' by zakończyć): ", completer=completer)

with open("report.md", "a") as report:
    report.write(f"# Skanowanie - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    while True:
        domain = session.prompt() or "apple.com"
        if domain.lower() == "quit":
            print("Koniec programu – idź na kawę!")
            break
        
        http_url = f"http://{domain}"
        https_url = f"https://{domain}"
        redirect_status = None
        try:
            http_response = requests.get(http_url, allow_redirects=False)
            redirect_status = http_response.status_code
            redirect_msg = f"HTTP Redirect: {redirect_status} - " + ("Przekierowanie jak z bajki!" if redirect_status in [301, 302] else "Brak przekierowania – słabo!")
        except requests.exceptions.RequestException:
            redirect_msg = "HTTP Redirect: BRAK - Nie działa HTTP albo coś się sypło!"

        try:
            start_time = time.time()
            response = requests.get(https_url)
            end_time = time.time()
            headers = response.headers

            print(f"\nSkanuję {domain.upper()} – trzymaj kciuki!")
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

            http_pool = urllib3.HTTPSConnectionPool(domain, port=443)
            conn = http_pool._get_conn()
            conn.connect()
            tls_version = conn.sock.version()
            if tls_version == "TLSv1.3": score += 1
            if response.status_code == 200: score += 1
            score_msg = f"Score: {score}/12 - " + ("Kozak!" if score >= 10 else "Może być lepiej, ziom!")
            print(score_msg)

            tls_msg = f"TLS: {tls_version} - " + ("Bezpieczeństwo level mistrz!" if tls_version == "TLSv1.3" else "Stare jak świat – czas na update!")
            print(tls_msg)
            tls_score_msg = "TLSv1.3 dał +1 punkt!" if tls_version == "TLSv1.3" else "TLSv1.3 brak – 0 punktów."
            print(tls_score_msg)

            # Poprawione wykrywanie wersji HTTP
            conn_http = http.client.HTTPSConnection(domain)
            conn_http.request("HEAD", "/")
            http_response = conn_http.getresponse()
            http_version = "HTTP/2" if http_response.version == 20 else "HTTP/1.1"
            http_version_msg = f"HTTP Version: {http_version} - " + ("Nowoczesne!" if http_version == "HTTP/2" else "Standardowo.")
            print(http_version_msg)
            conn_http.close()

            response_time = (end_time - start_time) * 1000
            response_time_msg = f"Czas odpowiedzi: {response_time:.2f} ms - " + ("Błyskawica!" if response_time < 100 else "Całkiem spoko!")
            print(response_time_msg)

            # Poprawione pobieranie certyfikatu SSL
            cert = conn.sock.getpeercert()
            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_to_expiry = (expiry_date - datetime.now()).days
            cert_msg = f"Certyfikat SSL wygasa: {expiry_date.strftime('%Y-%m-%d')} - " + (f"Spoko, masz jeszcze {days_to_expiry} dni!" if days_to_expiry > 30 else "Uważaj, wygasa za mniej niż 30 dni!")
            print(cert_msg)

            report.write(f"## {domain}\n")
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
            print(f"{domain} się sypnął – pewnie hakerzy już tam są!")
            report.write(f"## {domain}\n- Błąd: {e}\n\n")

print("Raport w report.md – jesteś mistrz!")