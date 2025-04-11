import docker
import logging
from datetime import datetime

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='docker_scan.log'
)

def scan_docker_images(report_file="docker_report.md"):
    """Skanuje lokalne obrazy Dockera i generuje raport bezpieczeństwa."""
    try:
        client = docker.from_env()
        images = client.images.list()
        
        if not images:
            print("Brak obrazów Dockera – pobierz coś, np. 'docker pull nginx'!")
            logging.warning("Brak obrazów do skanowania.")
            return
        
        # Otwieramy plik raportu
        with open(report_file, "w") as report:
            report.write(f"# Raport bezpieczeństwa Dockera - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            print(f"\nSkanowanie obrazów Dockera – trzymaj kciuki!")
            
            for img in images:
                tags = img.tags[0] if img.tags else "Brak tagu"
                created = datetime.fromisoformat(img.attrs['Created'].replace('Z', '+00:00')).replace(tzinfo=None)
                age_days = (datetime.now().replace(tzinfo=None) - created).days
                exposed_ports = img.attrs['Config'].get('ExposedPorts', {})
                # Poprawiamy wyświetlanie użytkownika
                user = img.attrs['Config'].get('User') or "root (domyślny)"
                user_warning = "⚠️ Root!" if "root" in user.lower() else "OK"
                
                # Wyświetlanie w terminalu
                print(f"\nObraz: {tags}")
                print(f"Wiek: {age_days} dni" + (" ⚠️ Stary (>90 dni)!" if age_days > 90 else ""))
                print(f"Otwarte porty: {list(exposed_ports.keys()) if exposed_ports else 'Brak'}")
                print(f"Użytkownik: {user} - {user_warning}")
                
                # Zapis do raportu
                report.write(f"## Obraz: {tags}\n")
                report.write(f"- Wiek: {age_days} dni" + (" ⚠️ Stary (>90 dni)!" if age_days > 90 else "") + "\n")
                report.write(f"- Otwarte porty: {list(exposed_ports.keys()) if exposed_ports else 'Brak'}\n")
                report.write(f"- Użytkownik: {user} - {user_warning}\n\n")
                logging.info(f"Przeskanowano: {tags}, wiek: {age_days}, porty: {exposed_ports}, user: {user}")
        
        print(f"\nRaport zapisany w {report_file} – jesteś kozak!")
    except Exception as e:
        print(f"⚠️ Błąd: {e}")
        logging.error(f"Błąd skanowania: {e}")

if __name__ == "__main__":
    scan_docker_images()