# Краткий справочник CCNA

## Тема 1. Network Fundamentals (Основы сетей)

### Краткое описание технологий

Network Fundamentals охватывает базовые понятия компьютерных сетей, включая модели OSI и TCP/IP, типы сетей, топологии, Ethernet, IP-адресацию и базовые протоколы.

#### Основные концепции:
- **Модель OSI**: 7-уровневая модель (Physical, Data Link, Network, Transport, Session, Presentation, Application)
- **Модель TCP/IP**: 4-уровневая модель (Network Access, Internet, Transport, Application)
- **Типы сетей**: LAN, WAN, WLAN, MAN
- **Топологии**: Звезда, шина, кольцо, mesh
- **Ethernet**: Стандарт локальных сетей, кадры Ethernet
- **IP-адресация**: IPv4 и IPv6, классы адресов, подсети, CIDR

### Особенности использования

- **Модель OSI**: Используется для понимания взаимодействия уровней, но в практике чаще применяется TCP/IP
- **Ethernet**: Основной протокол для локальных сетей, поддерживает скорости от 10 Mbps до 100 Gbps
- **IP-адресация**: Необходима для уникальной идентификации устройств в сети
- **IPv6**: Решает проблему исчерпания IPv4-адресов, поддерживает автоконфигурацию

### Принципы работы

- **Модель OSI**: Каждый уровень выполняет специфические функции: Physical - передача битов, Data Link - кадры и MAC, Network - маршрутизация, Transport - сегментация, Session - управление сессиями, Presentation - кодирование, Application - интерфейс пользователя.
- **TCP/IP**: Network Access - физическая передача, Internet - IP-адресация, Transport - TCP/UDP, Application - сервисы.
- **Ethernet**: Использует CSMA/CD для доступа к среде, кадры содержат preamble, destination/source MAC, type, data, FCS.
- **IP**: IPv4 - 32-битные адреса, маски подсети; IPv6 - 128-битные, упрощенная заголовок.

### Методы использования

- **Диагностика сети**: Использовать ping для проверки связности, traceroute для пути.
- **Конфигурация устройств**: Настройка интерфейсов с IP-адресами, шлюзами.
- **Мониторинг**: Просмотр ARP-таблиц, маршрутов.
- **Переход на IPv6**: Двойной стек или туннелирование для совместимости.

### Примеры команд

#### Настройка интерфейса в Cisco IOS:
```
Router> enable
Router# configure terminal
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# ip address 192.168.1.1 255.255.255.0
Router(config-if)# no shutdown
Router(config-if)# exit
Router(config)# exit
Router# show ip interface brief
```

#### Проверка подключения:
```
Router# ping 192.168.1.2
```

#### Просмотр ARP-таблицы:
```
Router# show arp
```

#### Настройка IPv6:
```
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# ipv6 address 2001:db8::1/64
Router(config-if)# no shutdown
```

#### Проверка IPv6:
```
Router# show ipv6 interface brief
Router# ping ipv6 2001:db8::2
```

---

## Тема 2. Network Access (Доступ к сети)

### Краткое описание технологий

Network Access описывает технологии второго уровня модели OSI, включая VLAN, trunking, EtherChannel, протоколы Spanning Tree, беспроводные сети и физические подключения.

#### Основные концепции:
- **VLAN (Virtual Local Area Network)**: Логическое разделение сети на сегменты
- **Trunking**: Передача трафика нескольких VLAN по одному каналу (802.1Q)
- **EtherChannel**: Агрегация каналов для увеличения пропускной способности
- **STP (Spanning Tree Protocol)**: Предотвращение петель в сети
- **Беспроводные сети**: Wi-Fi стандарты (802.11), безопасность WPA3
- **Физические подключения**: Кабели Ethernet, коннекторы, скорости

### Особенности использования

- **VLAN**: Позволяет изолировать трафик, улучшает безопасность и управляемость
- **Trunking**: Необходим для связи между коммутаторами с VLAN
- **EtherChannel**: Увеличивает надежность и пропускную способность
- **STP**: Автоматически блокирует избыточные пути для предотвращения broadcast storm
- **Wi-Fi**: Поддерживает мобильность, требует защиты от несанкционированного доступа

### Принципы работы

- **VLAN**: Тегирование кадров 802.1Q добавляет VLAN ID; коммутаторы обрабатывают кадры только в своем VLAN.
- **Trunking**: Несет трафик нескольких VLAN по одному каналу; native VLAN без тега.
- **EtherChannel**: Группирует порты в логический канал; использует PAgP или LACP для согласования.
- **STP**: Выбирает root bridge, блокирует порты для предотвращения петель; BPDU для обмена информацией.
- **Wi-Fi**: Доступные точки (AP) транслируют SSID; клиенты ассоциируются и аутентифицируются.

### Методы использования

- **Создание VLAN**: Назначение портов, настройка trunk.
- **EtherChannel**: Настройка на обоих концах, проверка состояния.
- **STP**: Мониторинг root bridge, приоритизация.
- **Wi-Fi**: Настройка SSID, шифрования, каналов.
- **Диагностика**: Просмотр VLAN, trunk, port security.

### Примеры команд

#### Создание VLAN на Cisco Switch:
```
Switch> enable
Switch# configure terminal
Switch(config)# vlan 10
Switch(config-vlan)# name Sales
Switch(config-vlan)# exit
Switch(config)# vlan 20
Switch(config-vlan)# name Marketing
Switch(config-vlan)# exit
Switch# show vlan brief
```

#### Настройка интерфейса в VLAN:
```
Switch(config)# interface GigabitEthernet 0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 10
Switch(config-if)# exit
```

#### Настройка trunk порта:
```
Switch(config)# interface GigabitEthernet 0/24
Switch(config-if)# switchport mode trunk
Switch(config-if)# switchport trunk allowed vlan 10,20
Switch(config-if)# exit
Switch# show interfaces trunk
```

#### Настройка EtherChannel:
```
Switch(config)# interface range GigabitEthernet 0/1 - 2
Switch(config-if-range)# channel-group 1 mode active
Switch(config-if-range)# exit
Switch(config)# interface Port-channel 1
Switch(config-if)# switchport mode trunk
Switch# show etherchannel summary
```

#### Проверка STP:
```
Switch# show spanning-tree
```

#### Настройка беспроводной сети (на WLC или AP):
```
AP(config)# interface Dot11Radio 0
AP(config-if)# ssid MyWiFi
AP(config-if-ssid)# authentication open
AP(config-if-ssid)# wpa-psk ascii MyPassword
AP(config-if-ssid)# exit
AP(config-if)# exit
AP# show dot11 associations
```

---

## Тема 3. IP Connectivity (IP-связность)

### Краткое описание технологий

IP Connectivity охватывает технологии третьего уровня модели OSI, включая статическую и динамическую маршрутизацию, протоколы OSPF, EIGRP, BGP, а также основы маршрутизации IPv4 и IPv6.

#### Основные концепции:
- **Статическая маршрутизация**: Ручная настройка маршрутов
- **Динамическая маршрутизация**: Автоматическое обновление таблиц маршрутизации
- **OSPF (Open Shortest Path First)**: Link-state протокол для внутренней маршрутизации
- **EIGRP (Enhanced Interior Gateway Routing Protocol)**: Расширенный протокол Cisco
- **BGP (Border Gateway Protocol)**: Протокол внешней маршрутизации
- **Маршрутизация IPv6**: Поддержка IPv6-адресов и протоколов

### Особенности использования

- **Статическая маршрутизация**: Простая, но требует ручного обновления при изменении сети
- **OSPF**: Масштабируемый, использует cost для выбора пути, поддерживает areas
- **EIGRP**: Быстрая конвергенция, поддерживает различные метрики
- **BGP**: Используется для маршрутизации между автономными системами
- **IPv6**: Обязателен для современных сетей, поддерживает большие адресные пространства

### Принципы работы

- **Статическая маршрутизация**: Администратор вручную задает маршруты; маршрутизатор использует их без обновлений.
- **OSPF**: Link-state протокол; роутеры обмениваются LSA, строят базу данных; Dijkstra для кратчайшего пути.
- **EIGRP**: Distance-vector с enhancements; использует DUAL алгоритм для loop-free маршрутизации.
- **BGP**: Path-vector протокол; обменивается путями между AS; атрибуты для выбора лучшего пути.
- **IPv6 маршрутизация**: Поддерживает статические маршруты, OSPFv3, BGP4+.

### Методы использования

- **Настройка статических маршрутов**: Указание сети, маски, next-hop.
- **OSPF**: Определение областей, настройка интерфейсов, проверка соседей.
- **EIGRP**: Настройка автономной системы, сетей, метрик.
- **BGP**: Установка соседей, объявление сетей, фильтрация.
- **Мониторинг**: Просмотр таблиц маршрутизации, соседей, трафика.

### Примеры команд

#### Настройка статической маршрутизации:
```
Router> enable
Router# configure terminal
Router(config)# ip route 192.168.2.0 255.255.255.0 192.168.1.2
Router(config)# exit
Router# show ip route
```

#### Настройка OSPF для одной области:
```
Router(config)# router ospf 1
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
Router(config-router)# exit
Router# show ip ospf neighbor
Router# show ip route ospf
```

#### Настройка OSPF для нескольких областей:
```
Router(config)# router ospf 1
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
Router(config-router)# network 192.168.2.0 0.0.0.255 area 1
Router(config-router)# exit
Router# show ip ospf database
```

#### Настройка EIGRP:
```
Router(config)# router eigrp 100
Router(config-router)# network 192.168.1.0
Router(config-router)# network 192.168.2.0
Router(config-router)# exit
Router# show ip eigrp neighbors
Router# show ip route eigrp
```

#### Настройка BGP:
```
Router(config)# router bgp 65001
Router(config-router)# neighbor 10.1.1.2 remote-as 65002
Router(config-router)# network 192.168.1.0 mask 255.255.255.0
Router(config-router)# exit
Router# show ip bgp summary
Router# show ip bgp
```

#### Настройка маршрутизации IPv6:
```
Router(config)# ipv6 unicast-routing
Router(config)# ipv6 route ::/0 2001:db8::2
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# ipv6 address 2001:db8::1/64
Router(config-if)# ipv6 ospf 1 area 0
Router(config-if)# exit
Router(config)# ipv6 router ospf 1
Router(config-rtr)# exit
Router# show ipv6 route
```

---

## Тема 4. IP Services (IP-сервисы)

### Краткое описание технологий

IP Services описывает сетевые сервисы, необходимые для функционирования сети, включая DHCP, DNS, NAT, NTP, SNMP, QoS и другие.

#### Основные концепции:
- **DHCP (Dynamic Host Configuration Protocol)**: Автоматическое назначение IP-адресов
- **DNS (Domain Name System)**: Преобразование имен в IP-адреса
- **NAT (Network Address Translation)**: Трансляция адресов для выхода в Интернет
- **NTP (Network Time Protocol)**: Синхронизация времени
- **SNMP (Simple Network Management Protocol)**: Мониторинг и управление сетевыми устройствами
- **QoS (Quality of Service)**: Приоритизация трафика

### Особенности использования

- **DHCP**: Упрощает управление IP-адресами, поддерживает резервирование адресов
- **DNS**: Необходим для разрешения имен, поддерживает кеширование
- **NAT**: Позволяет использовать приватные адреса в публичных сетях
- **NTP**: Обеспечивает точное время для логов и синхронизации
- **SNMP**: Позволяет собирать статистику и управлять устройствами удаленно
- **QoS**: Критично для VoIP и видео, предотвращает задержки

### Принципы работы

- **DHCP**: Клиент запрашивает IP (DHCP Discover), сервер предлагает (Offer), клиент подтверждает (Request), сервер присваивает (ACK).
- **DNS**: Иерархическая система; recursive resolvers запрашивают authoritative servers; кеширование для ускорения.
- **NAT**: Переписывает IP в заголовках; inside local/global, outside local/global.
- **NTP**: Клиенты синхронизируют время с серверами; stratum уровни точности.
- **SNMP**: Агенты на устройствах отвечают на запросы менеджеров; MIB для данных.
- **QoS**: Классификация трафика, маркировка, queuing, policing.

### Методы использования

- **DHCP**: Настройка пула адресов, опций, резервирований.
- **DNS**: Настройка зон, записей A, CNAME, PTR.
- **NAT**: Определение inside/outside интерфейсов, ACL для трансляции.
- **NTP**: Синхронизация с надежными серверами, аутентификация.
- **SNMP**: Настройка community strings, traps.
- **QoS**: Создание классов, политик, применение к интерфейсам.

### Примеры команд

#### Настройка DHCP-сервера на Cisco Router:
```
Router> enable
Router# configure terminal
Router(config)# ip dhcp pool LAN
Router(dhcp-config)# network 192.168.1.0 255.255.255.0
Router(dhcp-config)# default-router 192.168.1.1
Router(dhcp-config)# dns-server 8.8.8.8
Router(dhcp-config)# exit
Router(config)# ip dhcp excluded-address 192.168.1.1 192.168.1.10
Router(config)# exit
Router# show ip dhcp binding
```

#### Настройка DNS-клиента:
```
Router(config)# ip domain-lookup
Router(config)# ip name-server 8.8.8.8
Router(config)# ip name-server 8.8.4.4
Router# ping google.com
```

#### Настройка NAT:
```
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# ip nat inside
Router(config-if)# exit
Router(config)# interface GigabitEthernet 0/1
Router(config-if)# ip nat outside
Router(config-if)# exit
Router(config)# ip nat inside source list 1 interface GigabitEthernet 0/1 overload
Router(config)# access-list 1 permit 192.168.1.0 0.0.0.255
Router# show ip nat translations
```

#### Настройка NTP:
```
Router(config)# ntp server 192.168.1.100
Router(config)# ntp authenticate
Router(config)# ntp authentication-key 1 md5 NTPkey123
Router(config)# ntp trusted-key 1
Router# show ntp status
Router# show ntp associations
```

#### Настройка SNMP:
```
Router(config)# snmp-server community public RO
Router(config)# snmp-server community private RW
Router(config)# snmp-server location "Main Office"
Router(config)# snmp-server contact "admin@company.com"
Router# show snmp
```

#### Настройка QoS (приоритизация VoIP):
```
Router(config)# class-map match-all VOIP
Router(config-cmap)# match protocol rtp audio
Router(config-cmap)# exit
Router(config)# policy-map QOS-POLICY
Router(config-pmap)# class VOIP
Router(config-pmap-c)# priority percent 30
Router(config-pmap-c)# exit
Router(config-pmap)# exit
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# service-policy output QOS-POLICY
Router# show policy-map interface GigabitEthernet 0/0
```

---

## Тема 5. Security Fundamentals (Основы безопасности)

### Краткое описание технологий

Security Fundamentals охватывает базовые принципы сетевой безопасности, включая ACL, аутентификацию, шифрование, защиту от угроз и мониторинг.

#### Основные концепции:
- **ACL (Access Control Lists)**: Списки контроля доступа для фильтрации трафика
- **Port Security**: Защита портов коммутаторов от несанкционированного доступа
- **SSH (Secure Shell)**: Безопасный удаленный доступ
- **VPN (Virtual Private Network)**: Защищенные соединения через публичные сети
- **Firewall**: Межсетевой экран для защиты от угроз
- **Основы криптографии**: Шифрование, хэширование, цифровые сертификаты

### Особенности использования

- **ACL**: Позволяет разрешать/запрещать трафик на основе IP, портов, протоколов
- **Port Security**: Ограничивает MAC-адреса на порту, предотвращает spoofing
- **SSH**: Заменяет Telnet, обеспечивает шифрование
- **VPN**: Обеспечивает конфиденциальность в публичных сетях
- **Firewall**: Фильтрует трафик по правилам, защищает от атак
- **Криптография**: Основана на алгоритмах AES, RSA для защиты данных

### Принципы работы

- **ACL**: Последовательная проверка правил; implicit deny в конце.
- **Port Security**: Учит MAC-адреса, блокирует при превышении лимита.
- **SSH**: Асимметричное шифрование для аутентификации, симметричное для данных.
- **VPN**: Туннелирование трафика; IPSec для шифрования и аутентификации.
- **Firewall**: Stateful inspection отслеживает соединения.
- **Криптография**: Симметричная (AES) для скорости, асимметричная (RSA) для ключей.

### Методы использования

- **ACL**: Создание списков, применение к интерфейсам.
- **Port Security**: Включение на access портах, sticky learning.
- **SSH**: Генерация ключей, настройка VTY.
- **VPN**: Настройка IPSec, GRE туннелей.
- **Firewall**: Zone-based или CBAC политики.
- **Криптография**: Выбор алгоритмов, управление ключами.

### Примеры команд

#### Настройка стандартного ACL:
```
Router> enable
Router# configure terminal
Router(config)# access-list 1 deny 192.168.2.0 0.0.0.255
Router(config)# access-list 1 permit any
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# ip access-group 1 out
Router(config-if)# exit
Router# show access-lists
```

#### Настройка расширенного ACL:
```
Router(config)# access-list 100 deny tcp 192.168.1.0 0.0.0.255 any eq 80
Router(config)# access-list 100 permit ip any any
Router(config)# interface GigabitEthernet 0/0
Router(config-if)# ip access-group 100 in
Router# show access-lists 100
```

#### Настройка Port Security:
```
Switch(config)# interface GigabitEthernet 0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 1
Switch(config-if)# switchport port-security violation restrict
Switch(config-if)# switchport port-security mac-address sticky
Switch# show port-security interface GigabitEthernet 0/1
```

#### Включение SSH:
```
Router(config)# hostname MyRouter
Router(config)# ip domain-name example.com
Router(config)# crypto key generate rsa modulus 2048
Router(config)# line vty 0 15
Router(config-line)# transport input ssh
Router(config-line)# login local
Router(config-line)# exit
Router(config)# username admin secret MyPassword
Router# show ssh
```

#### Настройка VPN (GRE + IPSec):
```
Router(config)# crypto isakmp policy 1
Router(config-isakmp)# encryption aes
Router(config-isakmp)# hash sha
Router(config-isakmp)# authentication pre-share
Router(config-isakmp)# group 2
Router(config-isakmp)# exit
Router(config)# crypto isakmp key MyKey address 10.1.1.2
Router(config)# crypto ipsec transform-set MYSET esp-aes esp-sha-hmac
Router(config)# crypto map MYMAP 1 ipsec-isakmp
Router(config-crypto-map)# set peer 10.1.1.2
Router(config-crypto-map)# set transform-set MYSET
Router(config-crypto-map)# match address 101
Router(config-crypto-map)# exit
Router(config)# access-list 101 permit gre host 192.168.1.1 host 192.168.2.1
Router(config)# interface Tunnel 0
Router(config-if)# ip address 10.0.0.1 255.255.255.0
Router(config-if)# tunnel source GigabitEthernet 0/0
Router(config-if)# tunnel destination 10.1.1.2
Router(config-if)# crypto map MYMAP
Router# show crypto ipsec sa
```

#### Настройка базового Firewall (Zone-Based):
```
Router(config)# class-map type inspect match-all HTTP
Router(config-cmap)# match protocol http
Router(config-cmap)# exit
Router(config)# policy-map type inspect ZBF-POLICY
Router(config-pmap)# class type inspect HTTP
Router(config-pmap-c)# inspect
Router(config-pmap-c)# exit
Router(config-pmap)# exit
Router(config)# zone security INSIDE
Router(config-sec-zone)# exit
Router(config)# zone security OUTSIDE
Router(config-sec-zone)# exit
Router(config)# zone-pair security IN-OUT source INSIDE destination OUTSIDE
Router(config-sec-zone-pair)# service-policy type inspect ZBF-POLICY
Router# show zone-pair security
```

---

## Тема 6. Automation and Programmability (Автоматизация и программируемость)

### Краткое описание технологий

Automation and Programmability описывает современные подходы к управлению сетями с использованием программного обеспечения, API, скриптов и инструментов автоматизации.

#### Основные концепции:
- **REST API**: Интерфейс для программного управления устройствами
- **NETCONF/YANG**: Стандарты для конфигурации и мониторинга
- **Ansible**: Инструмент для автоматизации задач
- **Python для сетей**: Скрипты на Python с библиотеками (Netmiko, NAPALM)
- **SDN (Software-Defined Networking)**: Разделение управления и данных
- **CI/CD для сетей**: Автоматизация развертывания и тестирования

### Особенности использования

- **REST API**: Позволяет интегрировать сеть с приложениями, использовать HTTP методы
- **NETCONF**: Обеспечивает транзакционную конфигурацию, модель данных YANG
- **Ansible**: Декларативный подход, playbooks для многократного использования
- **Python**: Гибкий язык для автоматизации, поддержка различных протоколов
- **SDN**: Централизованное управление, OpenFlow протокол
- **CI/CD**: Ускоряет развертывание, снижает ошибки

### Принципы работы

- **REST API**: Использует HTTP для CRUD операций; RESTCONF для сетевых устройств.
- **NETCONF**: RPC-based протокол; candidate/running datastores.
- **Ansible**: Push-модель; модули для задач, inventory для хостов.
- **Python**: Скрипты с библиотеками для подключения и конфигурации.
- **SDN**: Контроллер управляет потоком; OpenFlow для southbound.
- **CI/CD**: Автоматизация тестирования и развертывания через pipelines.

### Методы использования

- **REST API**: Отправка запросов GET/POST/PUT/DELETE.
- **NETCONF**: Подключение с YANG моделями.
- **Ansible**: Написание playbooks, запуск на inventory.
- **Python**: Импорт библиотек, написание скриптов.
- **SDN**: Настройка контроллера, интеграция с устройствами.
- **CI/CD**: Создание pipelines для сетевых изменений.

### Примеры команд

#### Использование REST API (пример с Postman или curl):
```
curl -X GET "https://router-ip/restconf/data/interfaces-state" \
     -H "Accept: application/yang-data+json" \
     -u "username:password"
```

#### Настройка NETCONF:
```
Router(config)# netconf-yang
Router(config)# netconf-yang feature candidate-datastore
Router# show netconf-yang datastores
```

#### Ansible playbook для настройки VLAN:
```yaml
---
- name: Configure VLAN on Cisco Switch
  hosts: switches
  tasks:
    - name: Create VLAN
      ios_vlan:
        vlan_id: 10
        name: Sales
        state: present
      register: vlan_output

    - name: Debug VLAN creation
      debug:
        var: vlan_output
```

#### Python скрипт для резервного копирования конфигурации:
```python
from netmiko import ConnectHandler

device = {
    'device_type': 'cisco_ios',
    'host': '192.168.1.1',
    'username': 'admin',
    'password': 'password',
}

net_connect = ConnectHandler(**device)
output = net_connect.send_command('show running-config')
print(output)
net_connect.disconnect()
```

#### Настройка SDN контроллера (OpenFlow на коммутаторе):
```
Switch(config)# openflow
Switch(config-openflow)# controller 1 192.168.1.100 port 6633
Switch(config-openflow)# exit
Switch# show openflow controllers
```

#### Использование NAPALM для проверки конфигурации:
```python
from napalm import get_network_driver

driver = get_network_driver('ios')
device = driver('192.168.1.1', 'admin', 'password')
device.open()

interfaces = device.get_interfaces()
print(interfaces)

device.close()
```

#### CI/CD pipeline (GitLab CI пример):
```yaml
stages:
  - test
  - deploy

test_config:
  stage: test
  script:
    - python -m pytest tests/

deploy_network:
  stage: deploy
  script:
    - ansible-playbook deploy.yml
  only:
    - main
```

#### Настройка RESTCONF на Cisco:
```
Router(config)# restconf
Router(config)# ip http secure-server
Router(config)# ip http authentication local
Router# show restconf
