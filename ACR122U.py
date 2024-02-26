from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import NoCardException
from smartcard.System import readers
from sqlalchemy import create_engine, Table, Column, MetaData, String, DateTime,Integer,ForeignKey,Date
from sqlalchemy.sql import select,func
from sqlalchemy.exc import NoResultFound, IntegrityError
import ctypes
import threading
import time
'''
# Database connection details
DATABASE_SERVER = ''
DATABASE_NAME = ''
DATABASE_USER = ''
DATABASE_PASSWORD = ''
TABLE_NAME = 'AuthenticatedCards'
'''
# Новые подробности соединения с базой данных для доверенного подключения.
DATABASE_SERVER = ''
DATABASE_NAME = ''
# Доверенное подключение не использует имя пользователя и пароль.
DATABASE_USER = None
DATABASE_PASSWORD = None
TABLE_NAME = ''

r = readers()
print("Доступные считыватели:", r)

if r:
    reader = r[0]
    print("Используя:", reader)
    
    # Подключение к первому считывателю и попытка чтения карты
    connection = reader.createConnection()
    try:
        connection.connect()
        print("Карта подключена!")
    except Exception as e:
        print("Не удалось подключиться к карте:", e)
else:
    print("Нет доступных считывателей:")
# Подробности соединения с базой данных
DATABASE_URL = f'mssql+pyodbc://{DATABASE_SERVER}/{DATABASE_NAME}?trusted_connection=yes&driver=ODBC+Driver+17+for+SQL+Server'

# SQLAlchemy engine и метаданные
engine = create_engine(DATABASE_URL)
metadata = MetaData()
authenticated_cards_table = Table(
    'AuthenticatedCards',
    metadata,
    Column('CardUID', String(50), primary_key=True),
    Column('Block', String(50)),
    Column('KeyA', String(50)),  # This assumes the key is stored as a string
    Column('DateOfAuthentication', DateTime, server_default=func.now())
)
CardLink_table = Table('CardLink', metadata,
                       Column('CardUID', String(50), ForeignKey("AuthenticatedCards.CardUID"), primary_key=True),
                       Column('userid', Integer, ForeignKey("[User].userid"), primary_key=True)  # For SQL Server
                       # For other dialects, use ForeignKey('"User".userid')
                      )
User_table = Table('User', metadata,
                   Column('userid', Integer, primary_key=True),
                   Column('user_name', String(100)),
                   Column('date_of_birth', Date),
                   Column('phone_number', String(20))
                   )
# Create table if not exists
metadata.create_all(engine)



def authenticate_sector(connection, block_number, key_type):
    # Определение байта типа ключа
    key_type_byte = 0x60 if key_type == 'A' else 0x61
    # Создание команды APDU для аутентификации
    apdu = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_number, key_type_byte, 0x00]

    # Передача команды APDU считывателю и карте
    response, sw1, sw2 = connection.transmit(apdu)

    # Проверка слов состояния для определения успешности аутентификации
    if sw1 == 0x90 and sw2 == 0x00:
        print(f"Аутентификация успешна для блока {block_number:02X}h.")
        return True
    else:
        print(f"Аутентификация не удалась для блока {block_number:02X}h. SW1: {sw1:02X}, SW2: {sw2:02X}")
        return False
def load_key(connection, new_key_a):
    # Подготовка данных для записи в секторный трейлер
    data = new_key_a 
    
    # Создание команды APDU для записи в блок
    apdu = [0xFF, 0x82, 0x00, 0x00, 0x06] + list(data)
    
    # Передача команды APDU считывателю и карте
    response, sw1, sw2 = connection.transmit(apdu)
    
    # Проверка слов состояния для определения успешности записи
    if sw1 == 0x90 and sw2 == 0x00:
        print(f"Загрузка ключа успешна")
        return True
    else:
        print(f"Загрузка ключа не удалась")
        return False
def write_key(connection, block_number, new_key_a):
    data = new_key_a 
    
    # Создание команды APDU для записи в блок
    apdu = [0xFF, 0xD6, 0x00, block_number, 0x10] + list(data)
    
    # Передача команды APDU считывателю и карте
    response, sw1, sw2 = connection.transmit(apdu)
    
    # Проверка слов состояния для определения успешности записи
    if sw1 == 0x90 and sw2 == 0x00:
        print(f"Запись ключа успешна")
        return True
    else:
        print(f"Запись ключа не удалась")
        return False
def read_key(connection, block_number):
    # Создание команды APDU для чтения блока
    apdu = [0xFF, 0xB0, 0x00, block_number, 0x10]
    
    # Передача команды APDU считывателю и карте
    response, sw1, sw2 = connection.transmit(apdu)
    
    # Проверка слов состояния для определения успешности чтения
    if sw1 == 0x90 and sw2 == 0x00:
        hex_response = toHexString(response)
        print(f"Чтение успешно: {hex_response} в блоке {block_number}")
        return response  # Возвращение сырых байт ответа
    else:
        print(f"Чтение ключа не удалось")
        return False
    
def get_card_uid(connection):
    command = [0xFF, 0xCA, 0x00, 0x00, 0x00]  # Команда для получения UID карты
    data, sw1, sw2 = connection.transmit(command)
    if (sw1, sw2) == (0x90, 0x00):
        return toHexString(data)
    else:
        raise Exception("Не удалось получить UID карты")
    
def send_custom_apdu(connection, command):
    # Запрос пользователю на ввод команды APDU
    hex_apdu = command
    
    # Преобразование входной строки в список байтов
    apdu = bytes.fromhex(hex_apdu)
    
    # Передача пользовательской команды APDU на карту
    response, sw1, sw2 = connection.transmit(list(apdu))
    
    # Вывод ответа от карты
    print(f"Ответ: {response}, SW1: {sw1:02X}, SW2: {sw2:02X}")
    
def authenticate_and_log_card(reader, engine, authenticated_cards_table, block, key):
    connection = reader.createConnection()
    # Подключение к карте

    key_type = 'A'  # Предполагается аутентификация ключом A
    current_key = key
    block_number = block

    print("Ожидание карты...")

    # Ожидание присутствия карты
    card_present = False

    while not card_present:
        try:
            # Попытка подключения к карте
            connection.connect()
            card_present = True  # Карта присутствует, выход из цикла
        except Exception as e:
            # Если возникает ошибка, скорее всего карта отсутствует
            print("Карта не обнаружена. Пожалуйста, поднесите карту к считывателю.")
            time.sleep(1)  # Кратковременное ожидание перед следующей попыткой

    print("Карта обнаружена. Процедура аутентификации...")

    if load_key(connection, current_key):
        # Аутентификация сектора с использованием текущего ключа A
        if authenticate_sector(connection, block_number, key_type):
            uid = get_card_uid(connection)
            with engine.connect() as db_connection:
                print("UID карты получен:", uid)
                ins = authenticated_cards_table.insert().values(
                    CardUID=uid,
                    KeyA=' '.join(f"{b:02X}" for b in current_key),  # Преобразование ключа в строковый формат
                    Block=block_number,
                )
                try:
                    # Ваш код для вставки записи о карте
                    db_connection.execute(ins)
                    db_connection.commit()
                    print("Аутентифицированная карта добавлена в базу данных")
                except IntegrityError as e:
                    if 'Violation of PRIMARY KEY constraint' in str(e.orig):
                        print("Карта уже аутентифицирована")
        else:
            print("Карта не аутентифицирована")
    else:
        print("Аутентификация не удалась. Невозможно записать ключ A в трейлер сектора.")
 
def handle_card_authentication(reader, block_number, key, new_key_a):
    connection = reader.createConnection()
    print("Ожидание карты...")

    key_type = 'A'  # Предполагается аутентификация ключом A
    current_key = key
    block_number = 0x0B  # Блок для аутентификации

    # Ожидание присутствия карты
    card_present = False
    while not card_present:
        try:
            # Попытка подключения к карте
            connection.connect()
            card_present = True  # Карта присутствует, выход из цикла
            print("Карта обнаружена. Процесс записи...")

            if load_key(connection, current_key):
                # Аутентификация сектора с использованием текущего ключа A
                if authenticate_sector(connection, block_number, key_type):
                    new_key_a = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
                    # Запись нового ключа A в трейлер сектора
                    if write_key(connection, block_number, new_key_a):
                        print("Новый ключ A успешно записан.")
                        read_key(connection, block_number)
                    else:
                        print("Не удалось записать новый ключ A.")
                else:
                    print("Аутентификация не удалась. Невозможно записать ключ A в трейлер сектора.")
            else:
                print("Аутентификация не удалась. Невозможно загрузить ключ.")

        except Exception as e:
            # Если возникает ошибка, скорее всего карта отсутствует
            print("Карта не обнаружена. Пожалуйста, поднесите карту к считывателю.")
            time.sleep(1)  # Кратковременное ожидание перед следующей попыткой
            

def connect_and_send_apdu(reader):
    connection = reader.createConnection()
    try:
        connection.connect()
        print("Соединение с картой установлено. Теперь вы можете отправлять APDU команды. Для выхода напишите 'exit'.")
        
        while True:  # Начало бесконечного цикла
            command = input("Введите APDU команду или 'exit' для выхода: ").strip()
            if command.lower() == 'exit':
                print("Выход из режима ввода APDU команд.")
                break  # Выход из цикла, если пользователь ввёл 'exit'           
            try:              
                send_custom_apdu(connection, command)  # Команда передается в качестве аргумента               
            except Exception as e:
                print(f"Не удалось отправить APDU команду: {e}")
                
    except Exception as e:
        print(f"Не удалось установить соединение с картой: {e}")
    finally:
        connection.disconnect()
        print("Соединение с картой прервано.")
        
def associate_card_with_user(reader, engine, authenticated_cards_table, CardLink_table, block_number, current_key):
    connection = reader.createConnection()  

    print("Ожидание карты...")

    # Ожидание присутствия карты
    card_present = False
    while not card_present:
        try:
            # Попытка подключения к карте
            connection.connect()
            card_present = True  # Карта присутствует, выход из цикла
        except Exception as e:
            print("Карта не обнаружена. Пожалуйста, поднесите карту к считывателю.")
            time.sleep(1)  # Кратковременное ожидание перед следующей попыткой

    print("Карта обнаружена. Процесс аутентификации...")

    if load_key(connection, current_key):
        if authenticate_sector(connection, block_number, 'A'):
            uid = get_card_uid(connection)
            
            # Проверка наличия CardUID в таблице AuthenticatedCards
            with engine.connect() as db_connection:
                try:
                    # Подготовка оператора select для таблицы AuthenticatedCards
                    select_statement = select(authenticated_cards_table).where(authenticated_cards_table.c.CardUID == uid)
                    result = db_connection.execute(select_statement)
                    authenticated_card = result.fetchone()
                    
                    if authenticated_card is None:
                        print("CardUID отсутствует в таблице AuthenticatedCards.")
                        return  # Выход из функции, если карта не аутентифицирована

                    # Если карта аутентифицирована, запросить ID пользователя
                    user_id = input("Пожалуйста, введите ID пользователя для связи с этой картой: ")
                    
                    # Подготовка оператора insert для таблицы CardLink
                    ins = CardLink_table.insert().values(CardUID=uid, userid=user_id)
                    
                    # Вставка CardUID и userid в таблицу CardLink
                    db_connection.execute(ins)
                    db_connection.commit()
                    print("Связь CardUID и userid записана в базу данных")
                except IntegrityError as e:
                    db_connection.rollback()  # Откат транзакции при ошибке
                    if 'UNIQUE constraint failed' in str(e.orig):
                        print("Этот CardUID уже связан с userid.")
                    else:
                        print("Произошла ошибка при вставке в базу данных:", e.orig)
                except NoResultFound:
                    print("Запись в таблице AuthenticatedCards не найдена.")
        else:
            print("Аутентификация карты не удалась")
    else:
        print("Аутентификация не удалась. Невозможно записать ключ A в трейлер сектора.")

def get_user_data_by_card_uid(reader, engine, CardLink_table, User_table, current_key, block_number):
    connection = reader.createConnection()

    # Подключение к карте
    print("Ожидание карты...")

    # Ожидание наличия карты
    card_present = False
    while not card_present:
        try:
            # Попытка подключения к карте
            connection.connect()
            card_present = True  # Карта обнаружена, выход из цикла
        except Exception as e:
            # Если возникла ошибка, скорее всего, карта не присутствует
            print("Карта не обнаружена. Пожалуйста, поднесите карту к считывателю.")
            time.sleep(1)  # Кратковременное ожидание перед следующей попыткой

    print("Карта обнаружена. Продолжаем чтение UID...")

    if load_key(connection, current_key):
        # Аутентификация сектора с использованием текущего ключа A
        if authenticate_sector(connection, block_number, 'A'):           
            uid = get_card_uid(connection)  # Функция get_card_uid должна быть предоставлена
            if uid:
                with engine.connect() as db_connection:
                    try:
                        # Поиск user_id, связанного с CardUID в таблице CardLink
                        select_user_id = select(CardLink_table.c.userid).where(CardLink_table.c.CardUID == uid)
                        result = db_connection.execute(select_user_id)
                        user_id = result.scalar()

                        if user_id is not None:
                            # Получение данных пользователя из таблицы User, используя связанный user_id
                            select_user_data = select(User_table).where(User_table.c.userid == user_id)
                            user_data = db_connection.execute(select_user_data).one()
                            print("Данные пользователя получены:", user_data)
                            return user_data  # Возврат данных пользователя как результата
                        else:
                            print("Связь для данного CardUID не найдена.")
                    except NoResultFound:
                        print("Пользователь с связанным CardUID не найден.")
            else:
                print("Не удалось прочитать UID карты.")           
        else:
            print("Аутентификация карты не удалась")
    else:
        print("Аутентификация не удалась. Невозможно записать ключ A в трейлер сектора.")

# Основная программа с выбором задачи
def main_menu():
    while True:
        print("Пожалуйста, выберите опцию:")
        print("1. Аутентификация")
        print("2. Запись ключа")
        print("3. Отправка пользовательской команды APDU") # Добавлена новая опция
        print("4. Сопоставление карты с пользователем")
        print("5. Запрос пользователя, связанного с картой")
        print("6. Выход")
        choice = input("Введите ваш выбор: ")
        
        if choice == '1':
            current_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            block_number = 0x07   
            authenticate_and_log_card(reader, engine, authenticated_cards_table, block_number,current_key)
        elif choice == '2':
            new_key_a = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,0x07,0x80,0x69,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]                  
            current_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            block_number = 0x07           
            handle_card_authentication(reader,block_number,current_key,new_key_a)         
        elif choice == '3':
            connect_and_send_apdu(reader)
        elif choice == '4':
            current_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
            block_number = 0x0B   
            associate_card_with_user(reader, engine, authenticated_cards_table,CardLink_table, block_number, current_key)
        elif choice == '5':
            current_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]           
            block_number = 0x0B   
            get_user_data_by_card_uid(reader, engine, CardLink_table, User_table,current_key,block_number)
            break  # Exit the program
        elif choice == '6':
            print("Выход из программы.")
            break  # Exit the program
        else:
            print("Неверный выбор. Пожалуйста, введите корректную опцию.")

if __name__ == "__main__":
    main_menu()