# scanner.py
import os
import json
import tlsh
import logging

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_signatures(directory="threat_db"):
    """
    Загружает сигнатуры из JSON-файлов в указанной директории.

    Параметры:
        directory (str): Путь к директории с файлами сигнатур.

    Возвращает:
        dict: Словарь с TLSH хэшами в качестве ключей и описаниями угроз в качестве значений.
    """
    signatures = {}
    if not os.path.exists(directory):
        logging.error(f"Directory '{directory}' does not exist.")
        return signatures

    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            file_path = os.path.join(directory, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    tlsh_hash = data.get("tlsh")
                    description = data.get("name")
                    if tlsh_hash and description:
                        signatures[tlsh_hash.upper()] = description
                        logging.info(f"Loaded signature: {tlsh_hash} - {description}")
                    else:
                        logging.warning(f"Missing 'tlsh' or 'name' in {file_path}. Skipping.")
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON format in {file_path}. Skipping.")
            except Exception as e:
                logging.error(f"Error loading signature from {file_path}: {e}")
    return signatures


def get_file_tlsh(file_path):
    """
    Вычисляет TLSH хэш для указанного файла.

    Параметры:
        file_path (str): Путь к файлу для хэширования.

    Возвращает:
        str или None: TLSH хэш файла или None в случае ошибки.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            tlsh_hash = tlsh.hash(data)
            if tlsh.isValidTlsh(tlsh_hash):
                logging.info(f"Computed TLSH for {file_path}: {tlsh_hash}")
                return tlsh_hash
            else:
                logging.warning(f"Invalid TLSH hash computed for {file_path}.")
                return None
    except Exception as e:
        logging.error(f"Error reading {file_path}: {e}")
        return None


def heuristic_analysis(file_path):
    """
    Выполняет эвристический анализ файла на наличие подозрительных ключевых слов.

    Параметры:
        file_path (str): Путь к файлу для анализа.

    Возвращает:
        str или None: Описание подозрительного поведения или None, если ничего не обнаружено.
    """
    suspicious_keywords = ['eval', 'exec', 'shell', 'base64', 'import', 'marshal', 'pickle']
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            for keyword in suspicious_keywords:
                if keyword in content:
                    logging.info(f"Suspicious keyword '{keyword}' detected in {file_path}.")
                    return f"Suspicious keyword detected: {keyword}"
    except Exception as e:
        logging.error(f"Error during heuristic analysis of {file_path}: {e}")
    return None


def scan_directory(file_path, signatures):
    """
    Сканирует файл на наличие угроз, сравнивая его TLSH хэш с базой сигнатур и выполняя эвристический анализ.

    Параметры:
        file_path (str): Путь к файлу для сканирования.
        signatures (dict): Словарь с TLSH хэшами и описаниями угроз.

    Возвращает:
        list: Список найденных угроз в формате (file_path, description).
    """
    threats = []

    # Получаем TLSH хэш файла
    file_tlsh = get_file_tlsh(file_path)

    if file_tlsh:
        # Проверяем точное совпадение TLSH
        if file_tlsh in signatures:
            threats.append((file_path, signatures[file_tlsh]))
            logging.info(f"Threat found: {file_path} ({signatures[file_tlsh]})")
        else:
            # Выполняем эвристический анализ
            heuristic_result = heuristic_analysis(file_path)
            if heuristic_result:
                threats.append((file_path, heuristic_result))
                logging.info(f"Threat found via heuristic analysis: {file_path} ({heuristic_result})")

    return threats
