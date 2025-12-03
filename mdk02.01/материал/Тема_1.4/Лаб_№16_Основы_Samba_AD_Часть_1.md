# Лабораторное занятие №16. Основы работы с Samba AD (Часть 1)

## Объем
2 часа

## Цель
Освоить установку и настройку Samba AD как контроллера домена.

## Задания
- Установить пакеты Samba AD: `dnf install samba-dc`.
- Настроить realm: `samba-tool domain provision`.
- Запустить службы: `systemctl enable --now samba-ad-dc`.

## Результаты
- Проверить статус: `samba-tool domain info`.

---
*Материал разделен для соответствия 2ч на часть.*
