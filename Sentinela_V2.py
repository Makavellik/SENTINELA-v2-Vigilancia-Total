import os
import uuid
import psutil
import threading
import requests
from scapy.all import sniff, IP, TCP, UDP, Raw, IPv6, ICMP
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt
from rich.text import Text
from rich.panel import Panel
import subprocess
from rich import box
import random
from ipwhois import IPWhois
import re
import time
import random, uuid, time, socket, ssl, platform
import dns.resolver
import dns.reversename
import dns.exception
import uuid
import time
import ssl
import hashlib
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from curl_cffi import requests as curl_requests
import ipaddress

console = Console()

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

def mostrar_autor():
    console = Console()
    mensaje = Text()
    mensaje.append("✨ Proyecto creado por:\n", style="bold magenta")
    mensaje.append("👤 William Subname\n", style="bold cyan")
    mensaje.append("🛡️ Alias: ByMakaveli\n", style="bold yellow")
    mensaje.append("\n🚀 Con pasión y dedicación, para grandes aventuras.\n", style="italic green")
    mensaje.append("💻 ¡Gracias por usar este proyecto! 💙\n", style="bold blue")

    panel = Panel(mensaje, title="💡 Información del Autor", border_style="bright_magenta")
    console.print(panel)

# Para probar la función
if __name__ == "__main__":
    mostrar_autor()


# 💠 Estilo de encabezado futurista
def encabezado():
    console.print(Panel.fit(
        "[bold cyan]🧠 SENTINELA v2[/bold cyan] — [italic magenta]Módulo de Vigilancia Total[/italic magenta]\n\n"
        "[green]» Forjado por mentes que no duermen, [/green][yellow]que ven más allá del tiempo[/yellow]...\n"
        "[green]» Arquitectura viva, vigilancia sin tregua.[/green]",
        title="🚨 [bold magenta]Mente Imparable: Enlace Activo[/bold magenta]",
        subtitle="[bold white]Sintonizando el pulso del mañana...[/bold white]",
        border_style="bold bright_blue",
        box=box.HEAVY
    ))


# ⚡ ID único de sentinela
def generar_id_sentinela(prefijo: str = "SNT", incluir_timestamp: bool = False, longitud: int = 12) -> str:
    """
    Genera un ID único para la sesión Sentinela.
    
    Opcionalmente permite:
    - Prefijar el ID (por defecto: 'SNT')
    - Incluir timestamp (milisegundos)
    - Personalizar la longitud final del ID (mínimo 8)

    Args:
        prefijo (str): Texto al inicio del ID (máx 5 caracteres recomendados).
        incluir_timestamp (bool): Si se incluye un componente temporal único.
        longitud (int): Longitud total del ID sin contar el prefijo (mínimo 8).

    Returns:
        str: ID Sentinela único (Ej: 'SNT-A1B2C3D4E5F6' o 'SNT-20250612-B1C3F7...')
    """

    if longitud < 8:
        raise ValueError("La longitud mínima recomendada del ID es 8 caracteres.")

    # Base de entropía combinada (UUID + Random)
    raw_entropy = f"{uuid.uuid4().hex}{random.random()}{time.time_ns()}"
    hashed = hashlib.sha256(raw_entropy.encode()).hexdigest().upper()

    # Cortar con la longitud deseada
    id_core = hashed[:longitud]

    # Incluir timestamp si se desea
    if incluir_timestamp:
        timestamp = time.strftime("%Y%m%d")
        final_id = f"{prefijo}-{timestamp}-{id_core}"
    else:
        final_id = f"{prefijo}-{id_core}"

    return final_id

# 🌐 Sistema operativo
def plataforma_host(detallado: bool = False) -> str:
    """
    Detecta el sistema operativo principal del host.

    Args:
        detallado (bool): Si se desea incluir versión y arquitectura del sistema.

    Returns:
        str: Nombre del sistema operativo detectado, opcionalmente detallado.
    """
    try:
        sistema = platform.system().lower()
        nombre = "Desconocido"

        if "windows" in sistema:
            nombre = "Windows"
        elif "linux" in sistema:
            # Detectar si es Android
            if "ANDROID_ROOT" in os.environ:
                nombre = "Android"
            else:
                distro = platform.linux_distribution()[0] if hasattr(platform, 'linux_distribution') else platform.release()
                nombre = f"Linux ({distro})" if distro else "Linux"
        elif "darwin" in sistema:
            nombre = "macOS"
        elif "freebsd" in sistema:
            nombre = "FreeBSD"
        elif "openbsd" in sistema:
            nombre = "OpenBSD"
        elif "sunos" in sistema or "solaris" in sistema:
            nombre = "Solaris"
        else:
            nombre = sistema.capitalize()

        if detallado:
            version = platform.version()
            arquitectura = platform.machine()
            nombre += f" | v{version} | arch: {arquitectura}"

        return nombre

    except Exception as e:
        return f"Error detectando sistema: {e}"


# 🛡️ Anti-Virtualización Básica
def detectar_virtualizacion(detallado: bool = False) -> str | bool:
    """
    Detecta si el host está ejecutándose dentro de un entorno virtualizado.

    Analiza variables de entorno, BIOS/DMI, CPU flags, y rutas típicas
    para determinar si el sistema corre en una VM, contenedor o entorno cloud.

    Args:
        detallado (bool): Si se desea obtener el nombre del hipervisor (si aplica).

    Returns:
        bool | str: True/False si detallado es False. Si detallado=True, retorna
                    el nombre del hipervisor ("VMware", "KVM", "Docker", etc.)
                    o "Físico" si no se detecta virtualización.
    """
    posibles_indicios = []

    # 🔍 1. Variables de entorno
    palabras_clave_env = ["vmware", "virtualbox", "xen", "kvm", "hyperv", "qemu", "docker", "lxc"]
    for name, value in os.environ.items():
        if any(k in value.lower() for k in palabras_clave_env):
            posibles_indicios.append(value.lower())

    # 🔍 2. CPU Flags
    try:
        if platform.system().lower() == "linux":
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read().lower()
                if "hypervisor" in cpuinfo:
                    posibles_indicios.append("CPU flag: hypervisor")
    except Exception:
        pass

    # 🔍 3. Archivos típicos de contenedores
    contenedor_files = ["/.dockerenv", "/run/.containerenv"]
    for f in contenedor_files:
        if os.path.exists(f):
            posibles_indicios.append(f"Contenedor: {f}")

    # 🔍 4. DMI BIOS info
    try:
        if platform.system().lower() == "linux":
            output = subprocess.getoutput("dmidecode -s system-product-name 2>/dev/null").lower()
            if any(x in output for x in palabras_clave_env):
                posibles_indicios.append(f"DMI: {output.strip()}")
    except Exception:
        pass

    # 🔍 5. /sys/class/dmi/id para hipervisores (más fino)
    try:
        if platform.system().lower() == "linux":
            dmi_paths = [
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/product_name",
                "/sys/class/dmi/id/product_version"
            ]
            for path in dmi_paths:
                if os.path.exists(path):
                    with open(path) as f:
                        data = f.read().strip().lower()
                        if any(k in data for k in palabras_clave_env):
                            posibles_indicios.append(f"DMI match: {data}")
    except Exception:
        pass

    # ✅ Evaluación final
    if posibles_indicios:
        if detallado:
            return posibles_indicios[0]  # el primer indicio como nombre estimado del hipervisor
        return True
    else:
        return "Físico" if detallado else False


# 🔍 IPs Locales
def fingerprint_red(detallado: bool = False) -> dict:
    """
    Obtiene un fingerprint de las interfaces de red del sistema,
    incluyendo sus direcciones IP, estado y tipo.

    Args:
        detallado (bool): Si es True, incluye detalles extendidos.

    Returns:
        dict: Diccionario con la información de red por interfaz.
    """
    interfaces = psutil.net_if_addrs()
    estados = psutil.net_if_stats()
    resultado = {}

    for interfaz, direcciones in interfaces.items():
        info = {
            "IPv4": None,
            "IPv6": None,
            "MAC": None,
            "Estado": "desconocido",
            "Tipo": "desconocido"
        }

        for d in direcciones:
            if d.family == socket.AF_INET:
                info["IPv4"] = d.address
            elif d.family == socket.AF_INET6:
                info["IPv6"] = d.address
            elif d.family == psutil.AF_LINK:
                info["MAC"] = d.address

        # Estado y tipo de interfaz
        if interfaz in estados:
            stats = estados[interfaz]
            info["Estado"] = "activo" if stats.isup else "inactivo"

            if "lo" in interfaz or info["IPv4"] == "127.0.0.1":
                info["Tipo"] = "Loopback"
            elif "docker" in interfaz or "veth" in interfaz:
                info["Tipo"] = "Contenedor"
            elif "virbr" in interfaz or "vmnet" in interfaz:
                info["Tipo"] = "Virtual"
            elif "wlan" in interfaz or "wifi" in interfaz:
                info["Tipo"] = "Wi-Fi"
            elif "eth" in interfaz or "en" in interfaz:
                info["Tipo"] = "Ethernet"
            else:
                info["Tipo"] = "Otro"

        resultado[interfaz] = info if detallado else info["IPv4"]

    return resultado


# 🌐 Obtener IP pública
def obtener_ip_publica(timeout=5) -> dict:
    """
    Detecta y retorna información de red detallada:
    - IP pública desde múltiples fuentes
    - IPs locales (IPv4, IPv6)
    - Posible detección de NAT/VPN
    """
    info = {
        "IP Pública": "Desconocida",
        "Fuentes IP Pública": {},
        "IPs Privadas": [],
        "IPs IPv6": [],
        "Interfaces": {},
        "VPN/Proxy Sospecha": False
    }

    fuentes_publicas = {
        "ipify": "https://api.ipify.org",
        "ifconfig.me": "https://ifconfig.me/ip",
        "ipecho.net": "https://ipecho.net/plain",
        "ident.me": "https://ident.me",
        "myexternalip": "https://myexternalip.com/raw"
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Sentinela-NetScanner)"
    }

    # 🔍 Obtener IP pública de múltiples fuentes
    for nombre, url in fuentes_publicas.items():
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            ip = resp.text.strip()
            info["Fuentes IP Pública"][nombre] = ip
        except requests.RequestException:
            info["Fuentes IP Pública"][nombre] = "Error"

    # 📌 Consistencia entre fuentes
    ips_obtenidas = list(set(v for v in info["Fuentes IP Pública"].values() if v != "Error"))
    if ips_obtenidas:
        info["IP Pública"] = ips_obtenidas[0]
        if len(set(ips_obtenidas)) > 1:
            info["VPN/Proxy Sospecha"] = True  # Inconsistencia puede indicar proxy o VPN

    # 🧭 Recolectar IPs privadas (IPv4 + IPv6)
    interfaces = psutil.net_if_addrs()
    for interfaz, direcciones in interfaces.items():
        info["Interfaces"][interfaz] = []
        for d in direcciones:
            if d.family == socket.AF_INET:
                info["IPs Privadas"].append(d.address)
                info["Interfaces"][interfaz].append({"IPv4": d.address})
            elif d.family == socket.AF_INET6:
                ip6 = d.address.split('%')[0]
                if not ip6.startswith("fe80"):  # evitar link-local
                    info["IPs IPv6"].append(ip6)
                    info["Interfaces"][interfaz].append({"IPv6": ip6})

    return info


# 👁️ Captura de tráfico
def capturar_trafico(timeout=30):
    """
    Captura y analiza paquetes IP en tiempo real con nivel experto.
    Incluye: protocolo, tamaño, TTL, payload y detección de headers sensibles.
    """
    console.print("[bold cyan]🎧 Iniciando captura avanzada de tráfico...[/bold cyan]\n")
    stats = {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "http": 0,
        "https": 0,
        "dns": 0,
        "otros": 0
    }

    def procesar_paquete(pkt):
        timestamp = datetime.now().strftime("%H:%M:%S")
        protocolo = "DESCONOCIDO"

        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src = ip_layer.src
            dst = ip_layer.dst
            ttl = getattr(ip_layer, 'ttl', '?')
            length = len(pkt)

            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                protocolo = "TCP"
                stats["tcp"] += 1

                # Identificación de protocolos por puerto
                if dport == 80 or sport == 80:
                    tipo = "[red]HTTP[/red]"
                    stats["http"] += 1
                elif dport == 443 or sport == 443:
                    tipo = "[cyan]HTTPS[/cyan]"
                    stats["https"] += 1
                else:
                    tipo = "[green]TCP Genérico[/green]"
                    stats["otros"] += 1

            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                protocolo = "UDP"
                stats["udp"] += 1

                if dport == 53 or sport == 53:
                    tipo = "[magenta]DNS[/magenta]"
                    stats["dns"] += 1
                else:
                    tipo = "[green]UDP Genérico[/green]"
                    stats["otros"] += 1

            elif ICMP in pkt:
                sport = dport = "-"
                tipo = "[yellow]ICMP[/yellow]"
                protocolo = "ICMP"
                stats["icmp"] += 1

            else:
                sport = dport = "?"
                tipo = "[dim]Otro[/dim]"
                stats["otros"] += 1

            stats["total"] += 1

            # 🧾 Mostrar resumen del paquete
            console.print(
                f"{tipo} [bold]{timestamp}[/bold] [white]{src}:{sport}[/white] → [cyan]{dst}:{dport}[/cyan] "
                f"| Proto: {protocolo} | TTL: {ttl} | 📦 {length} bytes"
            )

            # 🔍 Inspección profunda (headers y payloads)
            if pkt.haslayer(Raw):
                raw_data = pkt[Raw].load
                texto = raw_data.decode(errors="ignore")

                # Extraer headers HTTP comunes
                if "User-Agent:" in texto:
                    ua = texto.split("User-Agent:")[1].split("\r\n")[0]
                    console.print(f"[blue]📱 User-Agent:[/blue] {ua}")
                if "Host:" in texto:
                    host = texto.split("Host:")[1].split("\r\n")[0]
                    console.print(f"[cyan]🌍 Host detectado:[/cyan] {host}")
                if "server_name" in texto:
                    try:
                        partes = texto.split("server_name")
                        sni = partes[1].split("\x00")[1]
                        console.print(f"[yellow]🔐 SNI detectado:[/yellow] {sni}")
                    except:
                        pass

    # 🧲 Inicia captura con filtro IP
    sniff(
        prn=procesar_paquete,
        store=0,
        filter="ip or ip6",
        timeout=timeout
    )

    # 📊 Estadísticas finales
    console.print("\n[bold green]✅ Captura finalizada[/bold green]")
    console.print("[bold cyan]📊 Estadísticas del tráfico:[/bold cyan]")
    for k, v in stats.items():
        console.print(f" - {k.upper()}: {v}")

# 📡 Mostrar información general
def mostrar_info(entorno):
    console.print("\n[bold bright_magenta]📊 ENTORNO DETECTADO:[/bold bright_magenta]")
    for clave, valor in entorno.items():
        console.print(f"[green]{clave}[/green]: [white]{valor}[/white]")

# 🚀 Ejecutar modo local
def modo_local():
    entorno = {
        "ID Sentinela": generar_id_sentinela(),
        "Sistema": plataforma_host(),
        "Virtualización": detectar_virtualizacion(),
        "IPs Locales": fingerprint_red(),
        "IP Pública": obtener_ip_publica()
    }
    mostrar_info(entorno)

    console.print("\n[bold cyan]🎧 Iniciando escucha pasiva...[/bold cyan]")
    hilo = threading.Thread(target=capturar_trafico)
    hilo.start()
    hilo.join()
    console.print("[bold green]✅ Captura finalizada.[/bold green]")

# 🌐 Escaneo remoto 

def resolucion_dns_inversa_evasiiva(ip_objetivo, verbose=True, modo='sigiloso', guardar_log=True):
    """
    Realiza una resolución DNS inversa y enriquecida sobre una IP objetivo.
    Incluye técnicas de evasión, análisis de ASN, verificación contra GeoIP,
    detección de tecnologías web y soporte para IPv6.
    """

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_entries = []

    # Validar dirección IP
    try:
        ip_obj = ipaddress.ip_address(ip_objetivo)
    except ValueError:
        console.print(f"[red]❌ Dirección IP inválida:[/red] {ip_objetivo}")
        return None

    dns_providers = [
        ("Google", "8.8.8.8"),
        ("Cloudflare", "1.1.1.1"),
        ("Quad9", "9.9.9.9"),
        ("OpenDNS", "208.67.222.222"),
        ("CleanBrowsing", "185.228.168.168"),
        ("ControlD", "76.76.2.0"),
        ("DNS.SB", "185.222.222.222"),
        ("AdGuard", "94.140.14.14"),
        ("Level3", "4.2.2.1")
    ]

    if modo == "agresivo":
        max_dns = len(dns_providers)
    else:
        max_dns = 3  # sigiloso

    bad_ptr_keywords = [
        "amazonaws", "cloudapp", "googleusercontent", "local", "lan",
        "home", "static", "unknown", "in-addr", "rev.op", "dsl", "cable",
        "broadband", "ipv6", "internal", "example", "test", "router"
    ]

    resultados_ptr = {}
    try:
        nombre_reverso = dns.reversename.from_address(ip_objetivo)
    except dns.exception.SyntaxError:
        console.print(f"[red]❌ Error al generar el nombre reverso para:[/red] {ip_objetivo}")
        return None

    for nombre, dns_ip in random.sample(dns_providers, max_dns):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_ip]
        resolver.timeout = 2.8
        resolver.lifetime = 4.0

        try:
            if verbose:
                console.print(f"[blue]📡 Consultando PTR en {nombre} ({dns_ip})...[/blue]")
            t_inicio = time.time()
            respuesta = resolver.resolve(nombre_reverso, "PTR")
            t_fin = time.time()
            duracion = round(t_fin - t_inicio, 2)

            for rdata in respuesta:
                ptr = str(rdata).strip().lower()

                if any(bad in ptr for bad in bad_ptr_keywords):
                    if verbose:
                        console.print(f"[yellow]⚠️ PTR genérico detectado en {nombre}, descartado:[/yellow] {ptr}")
                    log_entries.append(f"[{timestamp}] Genérico descartado: {ptr} @ {dns_ip}")
                    continue

                if ptr not in resultados_ptr:
                    resultados_ptr[ptr] = {
                        "fuente_dns": nombre,
                        "dns_ip": dns_ip,
                        "duracion": duracion
                    }

        except dns.resolver.NXDOMAIN:
            if verbose:
                console.print(f"[dim]⛔ NXDOMAIN desde {nombre} ({dns_ip})[/dim]")
            log_entries.append(f"[{timestamp}] NXDOMAIN en {nombre}")
        except dns.resolver.Timeout:
            if verbose:
                console.print(f"[red]⏱️ Timeout desde {nombre} ({dns_ip})[/red]")
            log_entries.append(f"[{timestamp}] Timeout en {nombre}")
        except dns.exception.DNSException as e:
            if verbose:
                console.print(f"[red]💥 Excepción DNS en {nombre} ({dns_ip}):[/red] {e}")
            log_entries.append(f"[{timestamp}] Excepción DNS: {e}")

    if not resultados_ptr:
        console.print(f"[red]❌ No se encontraron PTR válidos para[/red] {ip_objetivo}")
    else:
        console.print(f"[bold green]✅ PTRs válidos encontrados:[/bold green]")
        for ptr, meta in resultados_ptr.items():
            console.print(f"  ➜ [bold]{ptr}[/bold] [magenta](desde {meta['fuente_dns']} en {meta['duracion']}s)[/magenta]")
            log_entries.append(f"[{timestamp}] PTR válido: {ptr} desde {meta['fuente_dns']}")

    # ➕ Enriquecimiento con ASN/GeoIP
    try:
        whois = IPWhois(ip_objetivo)
        info = whois.lookup_rdap(depth=1)

        org = info.get("network", {}).get("name", "Desconocido")
        asn = info.get("asn", "N/A")
        asn_desc = info.get("asn_description", "N/A")
        country = info.get("asn_country_code", "??")

        console.print(f"\n🌍 [cyan]Información enriquecida:[/cyan]")
        console.print(f"    🌐 ASN: [bold]{asn}[/bold] → {asn_desc}")
        console.print(f"    🏢 Organización: [bold]{org}[/bold]")
        console.print(f"    📍 País: [bold]{country}[/bold]")

        log_entries.append(f"[{timestamp}] ASN {asn} - {asn_desc} - {country}")

    except Exception as e:
        console.print(f"[red]⚠️ Error al consultar ASN/GeoIP:[/red] {e}")
        log_entries.append(f"[{timestamp}] ERROR ASN: {e}")

    # 🔍 Detección de tecnologías web
    try:
        url = f"http://[{ip_objetivo}]/" if ip_obj.version == 6 else f"http://{ip_objetivo}/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        }
        response = curl_requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        server_header = response.headers.get("Server", "Desconocido")
        powered_by = response.headers.get("X-Powered-By", "Desconocido")
        content = response.text.lower()

        console.print(f"\n🧪 [cyan]Detección de tecnologías web:[/cyan]")
        console.print(f"    🖥️ Servidor: [bold]{server_header}[/bold]")
        console.print(f"    ⚙️ X-Powered-By: [bold]{powered_by}[/bold]")



        # Análisis básico de contenido
        techs = []
        if "wordpress" in content:
            techs.append("WordPress")
        if "drupal" in content:
            techs.append("Drupal")
        if "joomla" in content:
            techs.append("Joomla")
        if "shopify" in content:
            techs.append("Shopify")
        if "magento" in content:
            techs.append("Magento")
        if "django" in content:
            techs.append("Django")
        if "rails" in content or "ruby on rails" in content:
            techs.append("Ruby on Rails")
        if "laravel" in content:
            techs.append("Laravel")
        if "react" in content:
            techs.append("React")
        if "angular" in content:
            techs.append("Angular")
        if "vue" in content:
            techs.append("Vue.js")

        if techs:
            console.print(f"    🔍 Tecnologías detectadas: [bold]{', '.join(techs)}[/bold]")
            log_entries.append(f"[{timestamp}] Tecnologías detectadas: {', '.join(techs)}")
        else:
            console.print(f"    🔍 Tecnologías detectadas: [bold]No identificadas[/bold]")
            log_entries.append(f"[{timestamp}] Tecnologías detectadas: No identificadas")

    except Exception as e:
        console.print(f"[red]⚠️ Error al detectar tecnologías web:[/red] {e}")
        log_entries.append(f"[{timestamp}] ERROR detección tecnologías web: {e}")


    # 📝 Guardar log enriquecido
    if guardar_log:
        file_name = f"log_dns_inverso_{ip_objetivo.replace(':', '_').replace('.', '_')}_{timestamp}.log"
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("# Registro de resolución DNS inversa avanzada\n")
            f.write(f"# IP objetivo: {ip_objetivo} ({timestamp})\n\n")
            for entry in log_entries:
                f.write(entry + "\n")
        console.print(f"[cyan]📝 Log completo guardado en:[/cyan] {file_name}")

    return list(resultados_ptr.keys())[0] if resultados_ptr else None


#Calcular Hash
def calcular_ja3_hash():
    """
    Calcula un hash JA3 simulado a partir de una conexión SSL real.
    JA3: TLS fingerprint basado en versión, cifrados, extensiones y curvas.
    """
    try:
        host = 'www.google.com'
        port = 443
        ja3_fields = {
            'version': '',
            'ciphers': [],
            'extensions': [],
            'elliptic_curves': [],
            'ec_point_formats': []
        }

        # Preparar conexión SSL
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_ciphers('ALL')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Versión TLS
                version = ssock.version()
                ja3_fields['version'] = version

                # Ciphers disponibles (devueltas por el server)
                ciphers = ssock.shared_ciphers()
                if ciphers:
                    ja3_fields['ciphers'] = [cipher[0] for cipher in ciphers]

                # Algunas implementaciones JA3 reales analizan directamente bytes crudos
                # pero aquí simulamos lo más fielmente posible con lo disponible en alto nivel

                # Notas adicionales (simuladas)
                ja3_fields['extensions'] = ['server_name', 'status_request', 'supported_groups']
                ja3_fields['elliptic_curves'] = ['X25519', 'secp256r1']
                ja3_fields['ec_point_formats'] = ['uncompressed']

                # Generar string JA3 al estilo: version,ciphers,extensions,curves,ec_formats
                ja3_str = (
                    f"{ja3_fields['version']},"
                    f"{'-'.join(ja3_fields['ciphers'])},"
                    f"{'-'.join(ja3_fields['extensions'])},"
                    f"{'-'.join(ja3_fields['elliptic_curves'])},"
                    f"{'-'.join(ja3_fields['ec_point_formats'])}"
                )

                ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
                return ja3_hash

    except Exception as e:
        return f"unknown ({type(e).__name__})"



def generar_trafico(dominio, ip_objetivo, profundidad=2):
    console.print(f"[bold cyan]💥 Tráfico sigiloso hacia:[/bold cyan] {dominio} ({ip_objetivo})")

    score = 0
    log_data = []
    visitados = set()
    por_visitar = set([f"https://{dominio}/"])

    # Headers JS Fingerprinting simulados
    js_headers = {
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "viewport-width": str(random.choice([360, 720, 1080, 1920])),
        "device-memory": str(random.choice([2, 4, 8, 16])),
        "downlink": str(random.choice([5, 10, 15])),
        "dpr": str(random.choice([1.0, 2.0])),
        "rtt": str(random.choice([50, 100, 200])),
        "ect": random.choice(["3g", "4g", "5g"]),
    }

    # Fingerprints avanzados
    fingerprints = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "sec-ch-ua": '"Google Chrome";v="124", "Chromium";v="124", ";Not=A-Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        {
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
            "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", ";Not=A-Brand";v="99"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        },
        {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
        }
    ]

    def obtener_enlaces(html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        enlaces = set()
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href.startswith('/'):
                enlaces.add(urljoin(base_url, href))
            elif dominio in href:
                enlaces.add(href)
        return enlaces

    for nivel in range(profundidad):
        nuevos_por_visitar = set()
        for url in por_visitar:
            if url in visitados:
                continue
            visitados.add(url)

            headers = {
                "X-Request-ID": str(uuid.uuid4()),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": random.choice(["en-US,en;q=0.9", "es-ES,es;q=0.9"]),
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Pragma": "no-cache",
                "Referer": f"https://{dominio}/?ref={uuid.uuid4().hex[:8]}",
                "Origin": f"https://{dominio}",
                "X-Forwarded-For": ".".join(str(random.randint(1, 254)) for _ in range(4)),
                "Via": f"{random.randint(1,3)}.1 edge-cloudflare",
                "JA3-Fingerprint": calcular_ja3_hash(),
            }

            headers.update(random.choice(fingerprints))
            headers.update(js_headers)

            ptr_resultado = resolucion_dns_inversa_evasiiva(ip_objetivo)
            if ptr_resultado:
                log_data.append(f"PTR encontrado: {ptr_resultado}")
            else:
                log_data.append("PTR no encontrado o descartado")

            try:
                t1 = time.time()
                response = curl_requests.get(
                    url,
                    impersonate="chrome",
                    headers=headers,
                    timeout=random.uniform(10.0, 20.0),
                    verify=False,
                    allow_redirects=True
                )
                t2 = time.time()
                duracion = round(t2 - t1, 2)

                if response.status_code < 400:
                    console.print(f"[green]✅ Accedido:[/green] {url} [{response.status_code}] en {duracion}s")
                    log_data.append(f"OK: {url} | {response.status_code} | {duracion}s")
                    score += 2
                    nuevos_por_visitar.update(obtener_enlaces(response.text, url))
                else:
                    console.print(f"[yellow]⚠️ Código {response.status_code}[/yellow] en {url}")
                    log_data.append(f"FAIL: {url} | {response.status_code}")
            except Exception as e:
                console.print(f"[red]💥 Error:[/red] {url} → {e}")
                log_data.append(f"Exception: {url} → {e}")

            time.sleep(random.uniform(1.0, 3.0))  # Delay por URL

        por_visitar = nuevos_por_visitar

    # 🧾 Log Final
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_file = f"log_trafico_sigiloso_{dominio.replace('.', '_')}_{timestamp}.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(f"# Log sigiloso para {dominio} ({ip_objetivo})\n\n")
        for entry in log_data:
            f.write(f"{entry}\n")
        f.write(f"\n🎯 Score final: {score}\n")

    console.print(f"[cyan]📝 Log guardado en:[/cyan] {log_file}")
    console.print(f"[bold magenta]📊 Score de tráfico total:[/bold magenta] {score}")


def modo_dominio():
    dominio = Prompt.ask("[bold cyan]🌐 Ingrese dominio o IP para análisis real[/bold cyan]").strip()

    # Validación potente
    patron_valido = re.compile(
        r"^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})$"
    )
    if not dominio or not patron_valido.match(dominio):
        console.print("[red]❌ Entrada inválida. Ingrese un dominio o IP correcta.[/red]")
        return

    try:
        ip_objetivo = socket.gethostbyname(dominio)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"\n[bold green]🧠 Objetivo resuelto:[/bold green] {dominio} → [bold cyan]{ip_objetivo}[/bold cyan]")
        console.print(f"[bold magenta]⚙️ [{timestamp}] Iniciando escaneo híbrido con tráfico real...[/bold magenta]\n")

        # Estadísticas
        stats = {"total": 0, "http": 0, "https": 0, "dns": 0, "tls": 0, "otros": 0}

        def analizar_paquete(pkt):
            hora = datetime.now().strftime("%H:%M:%S")
            try:
                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    src, dst = ip_layer.src, ip_layer.dst
                    proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
                    sport = getattr(pkt, 'sport', "?")
                    dport = getattr(pkt, 'dport', "?")
                    length = len(pkt)
                    ttl = getattr(ip_layer, 'ttl', "?")
                    tipo = "[green]GENÉRICO[/green]"

                    # Clasificación por puertos
                    if TCP in pkt:
                        if sport == 443 or dport == 443:
                            tipo = "[cyan]HTTPS[/cyan]"
                            stats["https"] += 1
                        elif sport == 80 or dport == 80:
                            tipo = "[red]HTTP[/red]"
                            stats["http"] += 1
                        else:
                            stats["otros"] += 1
                    elif UDP in pkt and (sport == 53 or dport == 53):
                        tipo = "[magenta]DNS[/magenta]"
                        stats["dns"] += 1
                    else:
                        stats["otros"] += 1

                    stats["total"] += 1

                    console.print(
                        f"{tipo} [{hora}] {src}:{sport} → {dst}:{dport} | {proto} | TTL: {ttl} | {length} bytes"
                    )

                    # Deep inspection: Raw packet
                    if pkt.haslayer(Raw):
                        raw_data = pkt[Raw].load
                        texto = raw_data.decode(errors='ignore')

                        # Server Name Indication (SNI)
                        if b"server_name" in raw_data:
                            try:
                                partes = texto.split("server_name")
                                if len(partes) > 1:
                                    server_name = partes[1].split("\x00")[1]
                                    console.print(f"[yellow]🔍 SNI detectado:[/yellow] {server_name}")
                                    stats["tls"] += 1
                            except Exception:
                                pass

                        # User-Agent (HTTP headers)
                        if "User-Agent:" in texto:
                            try:
                                ua = texto.split("User-Agent:")[1].split("\r\n")[0]
                                console.print(f"[blue]📱 User-Agent:[/blue] {ua}")
                            except:
                                pass

                        # Host (HTTP)
                        if "Host:" in texto:
                            try:
                                host = texto.split("Host:")[1].split("\r\n")[0]
                                console.print(f"[cyan]🌍 Host detectado:[/cyan] {host}")
                            except:
                                pass

            except Exception as e:
                console.print(f"[red]⚠️ Error analizando paquete: {e}[/red]")

        # Generador de tráfico
        hilo_trafico = threading.Thread(target=generar_trafico, args=(dominio, ip_objetivo), daemon=True)
        hilo_trafico.start()

        # Captura activa de tráfico con filtros específicos
        sniff(
            filter=f"ip host {ip_objetivo} or udp port 53 or tcp port 80 or tcp port 443",
            prn=analizar_paquete,
            store=0,
            timeout=20
        )

        hilo_trafico.join()

        # Resumen
        console.print(f"\n[bold green]✅ [{datetime.now().strftime('%H:%M:%S')}] Captura completada[/bold green]\n")
        console.print(f"[bold cyan]📊 Estadísticas de tráfico:[/bold cyan]")
        console.print(f"- Total paquetes analizados: {stats['total']}")
        console.print(f"- HTTP: [red]{stats['http']}[/red] | HTTPS: [cyan]{stats['https']}[/cyan] | DNS: [magenta]{stats['dns']}[/magenta] | TLS: [yellow]{stats['tls']}[/yellow] | Otros: {stats['otros']}")

    except socket.gaierror:
        console.print(f"[red]❌ No se pudo resolver el dominio: {dominio}[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error crítico: {e}[/red]")


# 🔘 Menú interactivo
def iniciar_sentinela():
    # Encabezado visual
    encabezado()

    # Presentación visual del menú
    console.print(Panel.fit(
        Text.from_markup(
            "[bold bright_cyan]🛡️ MODO LOCAL[/bold bright_cyan]\n"
            "[dim]Escanea y analiza el entorno actual del sistema donde se ejecuta.[/dim]\n"
            "[green]✔️ Detecta IPs, virtualización, sistema operativo y más.[/green]"
        ),
        title="[1] Local",
        border_style="cyan",
        box=box.ROUNDED
    ))

    console.print(Panel.fit(
        Text.from_markup(
            "[bold bright_magenta]🌐 MODO DOMINIO[/bold bright_magenta]\n"
            "[dim]Realiza análisis remoto sobre un dominio/IP externo.[/dim]\n"
            "[green]✔️ Incluye tráfico real, fingerprinting, escaneo DNS, ASN y tecnologías web.[/green]"
        ),
        title="[2] Dominio",
        border_style="magenta",
        box=box.ROUNDED
    ))

    # Menú de selección interactiva
    opciones = {
        "1": "local",
        "2": "dominio",
        "local": "local",
        "dominio": "dominio"
    }

    while True:
        seleccion = Prompt.ask(
            "\n[bold bright_yellow]Selecciona el modo de operación[/bold bright_yellow] (1 = Local, 2 = Dominio)",
            choices=["1", "2", "local", "dominio"],
            default="1"
        ).lower()

        modo = opciones.get(seleccion)
        if modo == "local":
            console.print("\n[bold cyan]🔍 Ejecutando modo local...[/bold cyan]")
            modo_local()
            break
        elif modo == "dominio":
            console.print("\n[bold magenta]🌐 Ejecutando modo dominio...[/bold magenta]")
            modo_dominio()
            break
        else:
            console.print("[red]❌ Opción inválida, intenta de nuevo.[/red]")


# ▶️ Punto de inicio
if __name__ == "__main__":
    iniciar_sentinela()

