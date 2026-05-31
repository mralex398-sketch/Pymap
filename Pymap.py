#!/usr/bin/env python3

import argparse
import os
import random
import shutil
import socket
import ssl
import subprocess
import threading
from queue import Queue

COMMON_HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000}
COMMON_HTTPS_PORTS = {443, 8443, 9443}
SERVICE_PROBES = {
    21: b"\r\n",
    22: b"SSH-2.0-PythonScanner_1.0\r\n",
    25: b"EHLO scanner.example.com\r\n",
    80: b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    110: b"\r\n",
    143: b"\r\n",
    3306: b"\r\n",
}


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def detect_spoofing(host, timeout=1.0, probes=3):
    """Попытка обнаружить сетевые ловушки на случайных закрытых портах."""
    test_ports = random.sample(range(20000, 60000), probes)
    open_count = 0

    for port in test_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((host, port)) == 0:
                    open_count += 1
        except OSError:
            pass

    return open_count >= probes


def verify_service_on_socket(sock, port, timeout, target_host):
    """Проверяет реальность сервиса прямо внутри ЖИВОГО сокета (без повторного коннекта)."""
    probe = SERVICE_PROBES.get(port, b"\r\n")

    try:
        # Если это HTTPS — оборачиваем уже существующий сокет в TLS
        if port in COMMON_HTTPS_PORTS:
            context = ssl._create_unverified_context()
            with context.wrap_socket(sock, server_hostname=target_host) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
                )
                data = tls_sock.recv(128)
                return len(data) > 0

        # Для обычных портов отправляем сигнатуру-зонд
        if probe:
            sock.sendall(probe)
        try:
            data = sock.recv(128)
            return len(data) > 0
        except socket.timeout:
            # Веб-серверы могут промолчать на некорректный зонд, для них это норма
            return port in COMMON_HTTP_PORTS
    except Exception:
        return False


def scan_port(host, port, timeout=1.0, strict_mode=False, target_host=None):
    """Базовый TCP connect-скан с умным баннерграббингом."""
    target_host = target_host or host
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) != 0:
                return False

            if not strict_mode:
                return True

            # Передаем открытый сокет дальше для проверки баннера
            return verify_service_on_socket(sock, port, timeout, target_host)
    except OSError:
        return False


def run_nmap_scan(target, ports, timeout, threads):
    """Если nmap установлен, используем его для более надежного сканирования."""
    nmap_cmd = shutil.which("nmap")
    if not nmap_cmd:
        return None

    port_list = ",".join(str(p) for p in ports)
    cmd = [
        nmap_cmd,
        "-sT",
        "-Pn",
        "-p",
        port_list,
        "--host-timeout",
        f"{max(1, int(timeout * 2))}s",
        "--min-parallelism",
        str(max(1, min(threads, 100))),
        "--max-retries",
        "1",
        "-T3",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, timeout * len(ports) / 10),
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    if result.returncode != 0:
        return None

    open_ports = set()
    capture = False
    for line in result.stdout.splitlines():
        if line.startswith("PORT"):
            capture = True
            continue
        if not capture:
            continue
        if not line.strip():
            break
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "open":
            try:
                open_ports.add(int(parts[0].split("/")[0]))
            except ValueError:
                continue
    return open_ports


def run_scapy_syn_scan(address, ports, timeout, retries=1):
    """Пытаемся SYN-скан с помощью scapy, если он доступен."""
    try:
        from scapy.all import ICMP, IP, TCP, conf, send, sr1
    except ImportError:
        return None

    conf.verb = 0
    open_ports = set()

    for port in ports:
        for _ in range(retries):
            pkt = IP(dst=address) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout)
            if resp is None:
                continue
            if resp.haslayer(TCP):
                flags = resp.getlayer(TCP).flags
                if flags & 0x12:
                    rst = IP(dst=address) / TCP(dport=port, flags="R", seq=resp.ack)
                    send(rst, verbose=0)
                    open_ports.add(port)
                    break
                if flags & 0x14:
                    break
            if resp.haslayer(ICMP):
                icmp = resp.getlayer(ICMP)
                if int(icmp.type) == 3 and int(icmp.code) in {1, 2, 3, 9, 10, 13}:
                    break
    return open_ports


def scan_host(
    target, ports, threads, timeout, strict=False, mode="banner", retries=2
):
    address = resolve_target(target)
    if not address:
        print(f"[!] Не удалось разрешить {target}")
        return

    print(f"\n[+] Сканирование {target} ({address})")
    print(
        f"[*] Режим сканирования: {mode}, портов: {len(ports)}, потоков: {min(threads, len(ports))}, таймаут: {timeout}s"
    )

    if mode == "nmap":
        open_ports = run_nmap_scan(target, ports, timeout, threads)
        if open_ports is not None:
            print(
                "  Открытые порты:",
                (
                    ", ".join(str(p) for p in sorted(open_ports))
                    if open_ports
                    else "нет"
                ),
            )
            return
        print("[-] nmap не найден или завершился с ошибкой, пробуем встроенный режим")
    elif mode == "syn":
        open_ports = run_scapy_syn_scan(
            address, ports, timeout, retries=max(1, retries)
        )
        if open_ports is not None:
            print(
                "  Открытые порты (SYN scan):",
                (
                    ", ".join(str(p) for p in sorted(open_ports))
                    if open_ports
                    else "нет"
                ),
            )
            return
        print(
            "[-] scapy/SYN-скан недоступен или не удалось, пробуем встроенный режим"
        )

    spoofing_detected = detect_spoofing(address, timeout)
    if spoofing_detected:
        print(
            "⚠️  Обнаружен Port Spoofing/Tarpit: включен строгий режим баннерграббинга"
        )
        strict = True
    elif strict:
        print("[+] Принудительный строгий режим баннерграббинга включен")
    else:
        print("[+] Защитные ловушки не обнаружены. Обычное сканирование.")

    jobs = Queue()
    open_ports = set()
    lock = threading.Lock()

    def worker():
        while True:
            port = jobs.get()
            try:
                if port is None:
                    break
                for _ in range(retries):
                    # ИСПРАВЛЕНО: Передаем target_host для корректной валидации TLS SNI цен
                    if scan_port(
                        address,
                        port,
                        timeout,
                        strict_mode=strict,
                        target_host=target,
                    ):
                        with lock:
                            open_ports.add(port)
                        break
            finally:
                jobs.task_done()

    workers = []
    for _ in range(min(threads, len(ports))):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        workers.append(thread)

    for port in ports:
        jobs.put(port)

    jobs.join()
    for _ in workers:
        jobs.put(None)
    for thread in workers:
        thread.join()

    if open_ports:
        print(
            "  Реальные открытые порты:",
            ", ".join(str(p) for p in sorted(open_ports)),
        )
    else:
        print("  Реальных открытых портов не обнаружено")


def parse_ports(port_option):
    """ИСПРАВЛЕНО: Функция теперь полностью закрыта и возвращает результат."""
    ports = set()
    for part in port_option.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)


def load_targets(path):
    with open(path, encoding="utf-8") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def main():
    parser = argparse.ArgumentParser(description="Мини-сканер портов")
    parser.add_argument("-f", "--file", help="Файл со списком целей")
    parser.add_argument("-p", "--ports", default="1-1024", help="Порты")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Потоки")
    parser.add_argument("-T", "--timeout", type=float, default=1.0, help="Таймаут")
    parser.add_argument(
        "-m",
        "--mode",
        default="banner",
        choices=["banner", "nmap", "syn"],
        help="Режим",
    )
    parser.add_argument("targets", nargs="*", help="Цели")
    args = parser.parse_args()

    targets = args.targets
    if args.file:
        targets.extend(load_targets(args.file))

    if not targets:
        print("[!] Укажите цели.")
        return

    ports = parse_ports(args.ports)
    for target in targets:
        scan_host(target, ports, args.threads, args.timeout, mode=args.mode)


if __name__ == "__main__":
    main()


