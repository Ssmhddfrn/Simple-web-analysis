import ssl
import socket
import sys
import requests

url = input("Taranması istenilen site girilir(The website to be scanned is entered(https:// ile): ")

headers_custom = {
    "User-Agent": "Mozilla/5.0(Windows NT 10.0; Win64; x64)"
}

try:
    response = requests.get(url, headers = headers_custom, timeout=10)
except requests.exceptions.RequestException as e:
    print("[-] Siteye baglanılamıyor:", e)
    sys.exit()

print("Status Code:" , response.status_code)

headers = response.headers

security_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

print("\n--- Security Header Check ---")

for header in security_headers:
    if header in headers:
        print(f"[+] {header} : Evet(yes)")
        
    else:
        print(f"[-] {header} : Hayır(no)")

print("\n--- Server Bilgisi(information) ---")
if "Server" in headers:
    print("[+] Server:", headers["Server"])
else:
    print("[-] Server bilgisi yok")

print("\n--- HTTPS Kontrol ---")
if url.startswith("https://"):
    print("[+] HTTPS kullanıyor(using)")
else:
    print("[-] HTTPS kullanmıyor(not using)")

print("\n--- Redirect Kontrol ---")
if response.history:
    print("[*] Redirect vaaar(found):")
    for r in response.history:
        print(" ->", r.status_code, r.url)
else:
    print("[+] Redirect yoook(not found)")

    print("\n--- SSL Certificate Bilgi(information) ---")

try:
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            print("[+] Certificate issued to:", cert.get("subject"))
            print("[+] Certificate issued by:", cert.get("issuer"))
            print("[+] Valid until:", cert.get("notAfter"))
except Exception as e:
    print("[-] SSL bilgisi alınamadı:", e)



    print("\n--- Open Port Scan (Top 10) ---")

common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443]

hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

for port in common_ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((hostname, port))
    
    if result == 0:
        print(f"[+] Port {port} açık(open)")
    else:
        print(f"[-] Port {port} kapalı(close)")
    
    s.close()

print("\n--- Admin / Login Path Check ---")

paths = [
    "/admin",
    "/login",
    "/panel",
    "/dashboard",
    "/wp-admin",
    "/admin/login",
    "/user/login"
]

base_url = url.rstrip("/")

for path in paths:
    full_url = base_url + path
    try:
        r = requests.get(full_url, headers=headers_custom, timeout=5)
        if r.status_code == 200:
            print(f"[+] Bulundu(found): {full_url}")
        elif r.status_code == 403:
            print(f"[!] Forbidden (var ama engellendi): {full_url}")
        else:
            print(f"[-] Bulunamadı(not found): {full_url}")
    except:
        print(f"[-] Error kontrolu: {full_url}")

        print("\n--- robots.txt Check ---")

robots_url = base_url + "/robots.txt"

try:
    r = requests.get(robots_url, headers=headers_custom, timeout=5)
    if r.status_code == 200:
        print("[+] robots.txt bulundu(found)")
        print(r.text[:500])  # ilk 500 karakter
    else:
        print("[-] robots.txt bulunamadı (not found)")
except:
    print("[-] robots.txt could not be checked")
