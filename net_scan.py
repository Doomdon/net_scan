#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")# установка широковещатеьный мак-адрес
    arp_broadcast_request = broadcast/arp_request #объединяем первые два пакета в один

    # Ответы записываются в две переменные в виде списков. Нам нужна первая переменная - answ
    answ = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]   #ожидаем ответ в течение 1 секунды

    # Сам ответ тож состоит из списка (запрос, ответ). Поэтому мы пробегаем по answ, берем второй элемент(ответ)
    # и выводим из него ip и MAC
    print("IP\t\t\tMAC Address")
    print("-----------------------------------------------")
    for el in answ:
        print(el[1].psrc + "\t\t" + el[1].hwsrc)    #ip и MAC
        print('-----------------------------------------------')


scan("ip")