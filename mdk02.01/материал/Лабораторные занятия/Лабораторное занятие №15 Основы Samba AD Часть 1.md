# Лабораторное занятие №15. Основы работы с Samba AD (Часть 1)

## Объем
2 часа

## Цель
Освоить установку и настройку Samba AD как контроллера домена, создание пользователей, групп и организационных подразделений, а также ввод клиентской машины в домен.

## Исходные данные
- **Сервер (srv)**: машина с установленной ОС ALT Linux, имя хоста `srv`
- **Клиент (cli)**: машина с установленной ОС ALT Linux, имя хоста `cli`
- **Домен**: `sa.test`
- **Пароль администратора домена**: `P@ssw0rd`

## Задание
1. Отключить службу BIND9 на сервере srv
2. Установить и настроить Samba AD на сервере srv
3. Создать домен sa.test
4. Создать пользователей и группы
5. Создать организационное подразделение (OU) и разместить в нем объекты
6. Ввести клиентскую машину cli в домен

---

## Ход работы

### Часть 1. Подготовка сервера и отключение BIND9

**На машине srv:**

1. Проверьте текущий статус службы BIND9:
```bash
systemctl status bind
```

2. Остановите службу BIND9:
```bash
systemctl stop bind
```

3. Отключите автозагрузку BIND9:
```bash
systemctl disable bind
```

4. Проверьте, что служба отключена:
```bash
systemctl is-enabled bind
# Должно вывести: disabled
```

5. Освободите 53 порт (если занят BIND):
```bash
# Проверьте, что порт 53 свободен
ss -tulpn | grep :53
```

---

### Часть 2. Установка и настройка Samba AD

**На машине srv:**

1. Обновите список пакетов:
```bash
apt-get update
```

2. Установите пакеты Samba AD:
```bash
apt-get install task-samba-dc
```

3. Остановите службы Samba (если запущены):
```bash
systemctl stop smb
systemctl stop nmb
systemctl stop winbind
```

4. Удалите существующие конфигурационные файлы (если есть):
```bash
rm -f /etc/samba/smb.conf
rm -rf /var/lib/samba
rm -rf /var/cache/samba
mkdir -p /var/lib/samba/sysvol
```

5. Выполните provision домена:
```bash
samba-tool domain provision 
```

При выполнении команды введите следующие параметры:
```
Realm: sa.test
Domain: SA
Server Role: dc
DNS backend: SAMBA_INTERNAL
DNS forwarder: 8.8.8.8
Administrator password: P@ssw0rd
Retype password: P@ssw0rd
```

6. Включите и запустите службу samba:
```bash
systemctl enable samba
systemctl start samba
# Перезагрузите машину srv для применения изменений
reboot
```

7. Проверьте статус службы:
```bash
systemctl status samba
```

8. Проверьте информацию о домене:
```bash
samba-tool domain info
```

Должно отобразиться:
```
Domain:               SA
NetBIOS Domain:       SA
DNS Domain:           sa.test
Domain SID:           S-1-5-21-...
```

---

### Часть 3. Создание пользователей и групп

**На машине srv:**

1. Создайте пользователей:
```bash
# Создаем пользователя Ivanov
samba-tool user create ivanov P@ssw0rd --given-name="Иван" --surname="Иванов"

# Создаем пользователя Petrov
samba-tool user create petrov P@ssw0rd --given-name="Петр" --surname="Петров"

# Создаем пользователя Sidorov
samba-tool user create sidorov P@ssw0rd --given-name="Сидор" --surname="Сидоров"
```

2. Проверьте созданных пользователей:
```bash
samba-tool user list
```

Должно отобразиться:
```
Administrator
ivanov
petrov
sidorov
```

3. Создайте группы:
```bash
# Создаем группу IT-Department
samba-tool group add "IT-Department"

# Создаем группу Sales
samba-tool group add "Sales"
```

4. Проверьте созданные группы:
```bash
samba-tool group list
```

5. Добавьте пользователей в группы:
```bash
# Добавляем ivanov и petrov в группу IT-Department
samba-tool group addmembers "IT-Department" ivanov,petrov

# Добавляем sidorov в группу Sales
samba-tool group addmembers "Sales" sidorov
```

6. Проверьте членство в группах:
```bash
# Проверка членов группы IT-Department
samba-tool group listmembers "IT-Department"

# Проверка членов группы Sales
samba-tool group listmembers "Sales"
```

---

### Часть 4. Создание организационного подразделения (OU)

**На машине srv:**

1. Создайте организационное подразделение "IT":
```bash
samba-tool ou add "OU=IT,DC=SA,DC=local"
```

2. Проверьте создание OU:
```bash
samba-tool ou list
```

Должно отобразиться:
```
OU=IT,DC=SA,DC=local
```

3. Переместите пользователей в OU "IT":
```bash
# Перемещаем пользователя ivanov
samba-tool user move ivanov "OU=IT,DC=SA,DC=local"

# Перемещаем пользователя petrov
samba-tool user move petrov "OU=IT,DC=SA,DC=local"
```

4. Переместите группу "IT-Department" в OU "IT":
```bash
samba-tool group move "IT-Department" "OU=IT,DC=SA,DC=local"
```

5. Проверьте структуру OU:
```bash
# Просмотр объектов в OU IT
ldapsearch -H ldap://localhost -D "Administrator@sa.test" -W -b "OU=IT,DC=SA,DC=local" "(objectClass=*)"
```

Введите пароль администратора: `P@ssw0rd`

---

### Часть 5. Ввод клиентской машины в домен

**На машине cli:**

1. Проверьте DNS для использования контроллера домена:
```bash
# Откройте файл конфигурации DNS
cat /etc/resolv.conf
```

Добавьте или измените строку:
```
nameserver <IP-адрес_сервера_srv>
search sa.test
```

2. Проверьте разрешение имени домена:
```bash
nslookup sa.test
```

Должно отобразиться имя сервера srv.

3. Установите необходимые пакеты:
```bash
apt-get install realmd
```

4. Проверьте доступность домена:
```bash
realm discover sa.test
```

5. Введите компьютер в домен:
```bash
realm join sa.test --user=Administrator
# Перезагрузите машину cli
reboot
```

Введите пароль администратора: `P@ssw0rd`

6. Проверьте информацию о домене:
```bash
realm list
```

7. Включите автоматическое создание домашних директорий:
```bash
authconfig --enablemkhomedir --update
```

8. Перезапустите службу SSSD:
```bash
systemctl restart sssd
systemctl enable sssd
```

9. Проверьте пользователей домена:
```bash
id administrator@sa.test
id ivanov@sa.test
```

10. Проверьте вход под доменным пользователем:
```bash
su - ivanov@sa.test
# Введите пароль: P@ssw0rd
```

---

### Часть 6. Проверка результатов

**На машине srv:**

1. Проверьте информацию о домене:
```bash
samba-tool domain info
```

2. Проверьте всех пользователей:
```bash
samba-tool user list
```

3. Проверьте все группы:
```bash
samba-tool group list
```

4. Проверьте структуру OU:
```bash
samba-tool ou list
```

5. Проверьте членство в группах:
```bash
samba-tool group listmembers "IT-Department"
samba-tool group listmembers "Sales"
```

**На машине cli:**

1. Проверьте подключение to домену:
```bash
realm list
```

2. Проверьте пользователей домена:
```bash
id administrator@sa.test
id ivanov@sa.test
id petrov@sa.test
```

3. Попробуйте войти под доменным пользователем:
```bash
ivanov
```

---

## Контрольные вопросы

1. Какую службу необходимо отключить перед установкой Samba AD и почему?
2. Какая команда используется for provision домена Samba AD?
3. Как создать нового пользователя в домене Samba?
4. Как добавить пользователя в группу?
5. Как создать организационное подразделение (OU)?
6. Как переместить пользователя в другое OU?
7. Какая утилита используется для ввода Linux-клиента в домен?
8. Как проверить, что компьютер успешно введен в домен?
9. Как проверить членство пользователя в группах?
10. Какие службы запускаются при установке Samba AD?

---

## Требования к отчету

Отчет должен содержать:
1. Скриншоты или вывод команд, подтверждающие выполнение каждого этапа
2. Ответы на контрольные вопросы
3. Выводы о проделанной работе

---

*Лабораторная работа рассчитана на 2 академических часа и представляет собой единую последовательность команд без индивидуальных заданий и вариантов.*