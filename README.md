# SENTINELA-v2-Vigilancia-Total
**Sentinela v2** es un sistema de análisis híbrido para la recopilación pasiva y activa de información sobre redes, dominios, IPs y tecnología web. Diseñado para investigadores de seguridad, analistas de inteligencia y entornos de vigilancia avanzada.

# 🧠🔍 SENTINELA v2 – Módulo de Vigilancia Total

> ⚡ Inteligencia activa. Vigilancia pasiva. Análisis preciso.  
> Diseñado por mentes que controlan el futuro.

![banner](https://img.shields.io/badge/status-Activo-brightgreen) ![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![License](https://img.shields.io/badge/license-MIT-purple)

---

## 🌐 ¿Qué es SENTINELA v2?

**SENTINELA v2** es una herramienta avanzada de **fingerprinting de red, escaneo híbrido de dominios/IPs y análisis de tráfico en tiempo real**. Combina técnicas de análisis pasivo y activo, enriquecimiento con ASN/GeoIP, evasión de PTRs genéricos, y detección heurística de tecnologías web.

🛠️ Diseñada para:

- 🔍 Analistas de ciberseguridad
- 🕵️ Pentesters
- 🧪 Investigadores OSINT
- 🧑‍💻 Curiosos tecnológicos

---

## 🧩 Funcionalidades Principales

| Módulo                     | Descripción                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| 🆔 **Generador de ID**     | Crea un identificador único de sesión para cada ejecución.                |
| 🧬 **Detección de SO**     | Identifica el sistema operativo del host actual.                          |
| 🛡️ **Anti-Virtualización**| Detecta entornos virtualizados (VMWare, VirtualBox, Hyper-V, etc).        |
| 🌐 **IP Pública / Local**  | Muestra IPs internas y resuelve tu IP externa real.                       |
| 📡 **Captura de tráfico** | Inspección pasiva en tiempo real: IP, puertos, protocolos, TTL, SNI, UA.  |
| 🧠 **Resolución DNS Inversa** | PTR enriquecido vía múltiples proveedores DNS.                           |
| 🌍 **GeoIP + ASN**        | Información de país, organización y ASN para cualquier IP.                |
| 🧪 **Tecnologías Web**     | Detecta tecnologías como WordPress, React, Laravel, Django, etc.          |
| 🧷 **JA3 Fingerprinting** | Simulación de huellas TLS (JA3 hash).                                     |
| 👻 **Tráfico Sigiloso**   | Generación de tráfico mimetizado con fingerprints reales.                |
| 📦 **Logs Detallados**    | Guarda logs de tráfico, PTRs, errores y resultados enriquecidos.          |

---

## 🚀 Instalación

### 1️⃣ Clona el repositorio

git clone [https://github.com/Makavellik/SENTINELA-v2-Vigilancia-Total

2️⃣ Instala las dependencias
pip install -r requirements.txt

🧪 Ejemplo de Ejecución
🔘 Modo Local:
📊 ENTORNO DETECTADO:
🆔 ID Sentinela: a1b2c3d4e5f6
🖥️ Sistema: Linux
🧿 Virtualización: No detectada
🌐 IP Pública: 88.123.45.67
🔌 IPs Locales: {'eth0': '192.168.1.100'}

🎧 Iniciando escucha pasiva...
192.168.1.100:443 → 172.217.3.110:443 via TCP
✅ Captura finalizada.

🌍 Modo Dominio:
🧠 Objetivo: example.com → 93.184.216.34

📡 PTRs válidos encontrados:
  ➜ server.edge.example.net (Cloudflare en 1.52s)

🌍 Información enriquecida:
🌐 ASN: 15169 → GOOGLE
🏢 Organización: Google LLC
📍 País: US

🧪 Tecnologías detectadas:
    🖥️ Servidor: nginx
    ⚙️ X-Powered-By: PHP/8.1.2
    🔍 Frameworks: WordPress, React

⚠️ Advertencias
Este script realiza capturas de red activas y puede generar tráfico visible. Úsalo únicamente en entornos controlados o con autorización explícita.

El módulo de detección de tecnologías es básico y se basa en patrones heurísticos, no detección exhaustiva.

🛡️ Seguridad & Ética
⚠️ Esta herramienta puede generar tráfico hacia servicios remotos. Úsala únicamente en:

🔐 Entornos controlados

🧪 Laboratorios de pruebas

📝 Con autorización explícita

No la utilices para fines maliciosos. El uso indebido es responsabilidad exclusiva del usuario.

📜 Licencia
MIT License © 2025
Desarrollado por mentes que no duermen.
Puedes usar, modificar y distribuir libremente bajo los términos de la licencia MIT.

