# Pcap File Parser

Парсит и выводит информацию о UDP/IP пакетах из .pcap файла.

## Установка

Программе нужны [libpcap](http://www.tcpdump.org) и [PcapPlusPlus](https://github.com/seladb/PcapPlusPlus).

Перед сборкой, надо выставить переменные окружения PCAPP_INCLUDE - путь к инклудам PcapPlusPlus и PCAPP_LIB - путь к собранным библиотекам PcapPlusPlus (libPacket++, libPcap++, libCommon++).

## Использование

### Обязательные параметры:
Путь к PCAP-файлу
### Опциональные параметры:
Фильтр по IP-адресу назначения -a # / --address #

Фильтр по порту назначения -p # / --port #

### Примеры запуска приложения:

Напечатать все UDP-пакеты из файла
```
./print_pcap dump.pcap
```
Напечатать только UDP-пакеты, которые отравлены на адрес 192.168.1.22
```
./print_pcap -a 192.168.1.22 dump.pcap
```
Напечатать только UDP-пакеты, которые отравлены на адрес 192.168.1.22:9991
```
./print_pcap -a 192.168.1.22 -p 9991 dump.pcap
```

