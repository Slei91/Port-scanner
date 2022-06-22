import concurrent.futures
import socket
from itertools import product
import argparse
import re
import threading


class Scanner:
    """Сканер портов."""
    PORTS = [80, 443]

    def __init__(self, hosts, ports, software=False):
        """Инициализирует объект класса.

        :param hosts: Диапазон хостов. Принимает либо диапазон хостов вида 192.168.1.0/24 или 192.168.1.0
        :type hosts: str
        :param ports: Список портов
        :type ports: list
        :param software: Флаг определения ПО хоста
        :type software: bool
        """
        self.hosts = self._convert_range_to_hosts(hosts)
        self.ports = [int(port) for port in ports]
        self.software = software
        self.open_ports_list = []
        self.hosts_software = {}
        self.lock = threading.Lock()

    def run(self):
        """Запускает сканирование."""
        with concurrent.futures.ThreadPoolExecutor(100) as executor:
            for host, port in product(self.hosts, self.ports):
                executor.submit(self.scan_host, host, port)
        self.output()

    def scan_host(self, host, port):
        """Сканирует порт указанного хоста.

        :param host: Хост
        :type host: str
        :param port: Порт
        :type port: int
        :return: None
        """
        with socket.socket() as sock:
            try:
                sock.settimeout(1)
                sock.connect((host, port))
                self.open_ports_list.append(f'{host} {port} OPEN')
                if self.software:
                    self._define_software_for_ports_80_443(host, port, sock)
            except Exception:
                print(f'[+] Порт {host} {port} ЗАКРЫТ')

    def _define_software_for_ports_80_443(self, host, port, sock):
        """Определяет програмное обеспечение хоста.

        :param host: Хост
        :type host: str
        :param port: Порт
        :type port: int
        :param sock: Сокет
        :type sock: class 'socket.socket'
        :return: None
        """
        if port in self.PORTS:
            try:
                sock.send(b'Hello')
                data = sock.recv(1024)
                data = data.decode('utf-8')
                software = re.search(r'Server:(.+\w+)', data)[1].lstrip()
                with self.lock:
                    if host not in self.hosts_software:
                        self.hosts_software[host] = software
            except Exception:
                print(f'[+] не удалось определить ПО {host} {port}')

    def output(self):
        """Выводит в консоль в удобочитаемом виде.

        :return: None
        """
        print('===='*20)
        print('Открытые порты:')
        if self.open_ports_list:
            for item in self.open_ports_list:
                item = item.split()
                print(f'[+] Порт {item[0]}:{item[1]} ОТКРЫТ')
        else:
            print('[+] Нет открытых портов')
        print('===='*20)
        if self.hosts_software:
            print('Програмное обеспечение хостов:')
            for key, value in self.hosts_software.items():
                print(f'Хост {key}, програмное обеспечение {value}')
            print('====' * 20)
        else:
            print('[+] Не удалось определить ПО!')

    @staticmethod
    def _convert_range_to_hosts(host_arg):
        """Конвертирует аргумент хоста в список хостов.

        :param host_arg: Диапазон хостов. Принимает либо диапазон хостов вида 192.168.1.0/24 или 192.168.1.0
        :type host_arg: str
        :return: list
        """
        if '/' in host_arg:
            host_range = host_arg.split('.')[-1]
            host_range_list = host_range.split('/')
            first, last = int(host_range_list[0]), int(host_range_list[1])
            hosts_list = [f'{host_arg.replace(host_range, "")}{host}' for host in range(first, last + 1)]
            return hosts_list
        else:
            return [host_arg]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Сканер портов')
    parser.add_argument('hosts', help='Диапазон ip-адресов вида: 192.168.1.0/24')
    parser.add_argument('ports', help='Список портов', nargs='+')
    parser.add_argument(
        '-s',
        '--software',
        action='store_true',
        help='Флаг включения определения програмного обеспечения хоста по портам 80, 443')
    args = parser.parse_args()

    scanner = Scanner(args.hosts, args.ports, args.software)
    scanner.run()

# python3 ports_scanner.py -s 194.87.59.179 80 443 1 8080
