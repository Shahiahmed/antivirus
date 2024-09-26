import os
import hashlib
import csv

# Функция для вычисления MD5 хэша файла
def get_file_hash(file_path, hash_type="MD5"):
    if hash_type == "MD5":
        hasher = hashlib.md5()
    elif hash_type == "SHA-256":
        hasher = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash type")

    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hasher.update(byte_block)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None
    return hasher.hexdigest()

# Функция для загрузки сигнатур из файла
def load_signatures(file_path="signatures.csv"):
    signatures = {}
    try:
        with open(file_path, mode="r") as file:
            reader = csv.reader(file)
            next(reader)  # Пропустить заголовок
            for row in reader:
                signatures[row[0]] = row[1]  # MD5 хэш -> описание вируса
    except FileNotFoundError:
        print(f"Signature file {file_path} not found.")
    return signatures

# Функция для сканирования директории
# Функция для сканирования директории
def scan_directory(file_path, signatures, hash_type="MD5"):
    threats = []

    # Получаем хэш файла с выбранным алгоритмом
    file_hash = get_file_hash(file_path, hash_type)

    if file_hash in signatures:
        threats.append((file_path, signatures[file_hash]))  # Угроза найдена

    return threats



