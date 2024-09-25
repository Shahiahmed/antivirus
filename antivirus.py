import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import requests
import datetime

# Путь к файлу базы данных сигнатур
SIGNATURE_DB_FILE = 'signature_db.txt'


# Функция для загрузки сигнатур из файла
def load_signatures():
    signatures = []
    try:
        with open(SIGNATURE_DB_FILE, 'r') as f:
            for line in f:
                signatures.append(line.strip())
    except FileNotFoundError:
        print("Signature database not found.")
    return signatures


# Функция для сканирования файлов
def scan_file(filepath, signatures):
    with open(filepath, 'rb') as f:
        file_hash = hashlib.md5(f.read()).hexdigest()
        if file_hash in signatures:
            return True, file_hash
    return False, None


# Функция для обновления базы данных сигнатур
def update_signatures():
    try:
        response = requests.get('https://example.com/signatures.txt')  # URL для обновления
        with open(SIGNATURE_DB_FILE, 'w') as f:
            f.write(response.text)
        return True
    except Exception as e:
        print(f"Failed to update signatures: {e}")
        return False


# Функция для сканирования выбранного каталога
def scan_directory(directory, log_text):
    signatures = load_signatures()
    if not signatures:
        messagebox.showwarning("Warning", "Signature database is empty or not found.")
        return

    log_text.insert(tk.END, f"Scanning directory: {directory}\n")

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            infected, file_hash = scan_file(filepath, signatures)
            if infected:
                log_text.insert(tk.END, f"Infected file found: {filepath} (Hash: {file_hash})\n")

    log_text.insert(tk.END, "Scanning completed.\n")


# Функция для выбора каталога
def choose_directory(log_text):
    directory = filedialog.askdirectory()
    if directory:
        threading.Thread(target=scan_directory, args=(directory, log_text)).start()


# Функция для обновления сигнатур
def update_signature_database(log_text):
    if update_signatures():
        log_text.insert(tk.END, "Signature database updated successfully.\n")
    else:
        log_text.insert(tk.END, "Failed to update signature database.\n")


# Запись логов в файл
def write_log_to_file(log_content):
    with open(f'logs/log_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.txt', 'w') as f:
        f.write(log_content)


# Создание графического интерфейса
def create_gui():
    root = tk.Tk()
    root.title("Simple Antivirus")
    root.geometry("600x400")

    log_text = tk.Text(root, wrap=tk.WORD)
    log_text.pack(expand=True, fill=tk.BOTH)

    scan_button = tk.Button(root, text="Scan Directory", command=lambda: choose_directory(log_text))
    scan_button.pack(side=tk.LEFT, padx=5, pady=5)

    update_button = tk.Button(root, text="Update Signatures", command=lambda: update_signature_database(log_text))
    update_button.pack(side=tk.LEFT, padx=5, pady=5)

    save_log_button = tk.Button(root, text="Save Log", command=lambda: write_log_to_file(log_text.get("1.0", tk.END)))
    save_log_button.pack(side=tk.LEFT, padx=5, pady=5)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
