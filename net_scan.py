#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")# установка широковещатеьный мак-адрес
    arp_broadcast_request = broadcast/arp_request #объединяем первые два пакета в один
    # Ответы записываются в две переменные в виде списков. Нам нужна первая переменная - answ
    answ = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]   #ожидаем ответ в течение 1 секунды

    # Сам ответ тож состоит из списка (запрос, ответ). Поэтому мы пробегаем по answ, берем второй элемент(ответ)
    # и выводим из него ip и MAC
    clients_list = []
    for el in answ:
        client_dict = {"ip": el[1].psrc, "mac": el[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
