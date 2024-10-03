import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time
import os
import hashlib
from scanner import scan_directory
import requests  # Для обновления базы сигнатур
import logging

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Antivirus")
        self.root.geometry("600x500")

        # Создание папки logs, если она не существует
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Настройка логирования
        logging.basicConfig(filename='logs/antivirus.log', level=logging.INFO, format='%(asctime)s - %(message)s')

        # Загрузка базы сигнатур
        self.signatures = {}
        self.update_signatures()  # Проверить наличие обновлений при запуске

        # Тип хэширования
        self.hash_type = tk.StringVar(value="MD5")

        # Интерфейс
        self.setup_ui()

    def setup_ui(self):
        # Метки и кнопки интерфейса
        self.label = tk.Label(self.root, text="Choose a scan type:")
        self.label.pack(pady=10)

        # Радио-кнопки для выбора типа сканирования
        self.scan_type = tk.StringVar(value="Full")
        self.full_scan_radiobutton = tk.Radiobutton(self.root, text="Full Scan", variable=self.scan_type, value="Full")
        self.full_scan_radiobutton.pack(pady=5)

        self.custom_scan_radiobutton = tk.Radiobutton(self.root, text="Custom Scan", variable=self.scan_type, value="Custom")
        self.custom_scan_radiobutton.pack(pady=5)

        # Радио-кнопки для выбора типа хэширования
        self.md5_radiobutton = tk.Radiobutton(self.root, text="MD5", variable=self.hash_type, value="MD5")
        self.md5_radiobutton.pack(pady=5)

        self.sha256_radiobutton = tk.Radiobutton(self.root, text="SHA-256", variable=self.hash_type, value="SHA-256")
        self.sha256_radiobutton.pack(pady=5)

        # Кнопки для выбора директории
        self.scan_button = tk.Button(self.root, text="Select Directory", command=self.select_directory)
        self.scan_button.pack(pady=10)

        self.selected_dir_label = tk.Label(self.root, text="")
        self.selected_dir_label.pack(pady=10)

        # Кнопка для запуска сканирования
        self.start_scan_button = tk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.start_scan_button.pack(pady=10)

        # Прогресс-бар
        self.progress = ttk.Progressbar(self.root, orient="horizontal", mode="determinate")
        self.progress.pack(pady=10, fill=tk.X, padx=20)

        # Поле для вывода результатов
        self.result_text = tk.Text(self.root, height=10, width=70)
        self.result_text.pack(pady=10)

        # Статистика
        self.stats_label = tk.Label(self.root, text="Stats: Scanned Files: 0, Threats Found: 0, Time: 0s")
        self.stats_label.pack(pady=10)

        # Кнопка для генерации отчета
        self.report_button = tk.Button(self.root, text="Generate Report", command=self.generate_report)
        self.report_button.pack(pady=10)

    def select_directory(self):
        if self.scan_type.get() == "Custom":
            selected_dir = filedialog.askdirectory()
            if selected_dir:
                self.selected_dir_label.config(text=f"Selected: {selected_dir}")
                self.selected_dir = selected_dir
        else:
            self.selected_dir_label.config(text="Selected: Entire File System")
            self.selected_dir = "/"

    def start_scan(self):
        if hasattr(self, 'selected_dir'):
            self.result_text.delete(1.0, tk.END)  # Очистить текстовое поле
            self.result_text.insert(tk.END, f"Scanning: {self.selected_dir}\n")

            # Сброс статистики и прогресса
            self.progress['value'] = 0
            self.stats_label.config(text="Stats: Scanned Files: 0, Threats Found: 0, Time: 0s")

            start_time = time.time()

            all_files = self.get_all_files(self.selected_dir)
            total_files = len(all_files)
            scanned_files = 0
            threats_found = 0

            # Для отчёта
            self.scan_report = []  # Сохраняем результаты сканирования в этот список

            for file in all_files:
                self.progress['value'] = (scanned_files / total_files) * 100
                self.root.update_idletasks()

                threats = scan_directory(file, self.signatures, self.hash_type.get())  # Передаем выбранный тип хэша
                if threats:
                    for threat in threats:
                        self.result_text.insert(tk.END, f"Threat found: {threat[0]} ({threat[1]})\n")
                        threats_found += 1
                        logging.info(f"Threat found: {threat[0]} ({threat[1]})")
                        self.scan_report.append(f"Threat found: {threat[0]} ({threat[1]})")

                scanned_files += 1
                elapsed_time = time.time() - start_time
                self.stats_label.config(
                    text=f"Stats: Scanned Files: {scanned_files}, Threats Found: {threats_found}, Time: {elapsed_time:.2f}s")

            elapsed_time = time.time() - start_time
            self.result_text.insert(tk.END,
                                    f"Scan completed. Total scanned: {scanned_files}, Threats found: {threats_found}, Time: {elapsed_time:.2f}s\n")
            logging.info(
                f"Scan completed. Scanned: {scanned_files}, Threats: {threats_found}, Time: {elapsed_time:.2f}s")
            self.scan_report.append(
                f"Scan completed. Scanned: {scanned_files}, Threats: {threats_found}, Time: {elapsed_time:.2f}s")
        else:
            messagebox.showwarning("Warning", "Please select a directory first.")

    def get_all_files(self, directory):
        files = []
        for root, _, filenames in os.walk(directory):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files

    def generate_report(self):
        if not hasattr(self, 'scan_report') or len(self.scan_report) == 0:
            messagebox.showwarning("Warning", "No scan results to generate a report.")
            return

        # Сохраняем отчет в файл
        report_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if report_path:
            with open(report_path, 'w') as report_file:
                report_file.write("\n".join(self.scan_report))
            messagebox.showinfo("Report", f"Report saved to {report_path}")

    def update_signatures(self):
        try:
            # API URL для получения списка сигнатур
            response = requests.get('https://creativecode.kz/api/signatures')
            response.raise_for_status()  # Проверяем, что запрос успешен (статус 200)

            # Обновляем локальные сигнатуры
            self.signatures = {item['hash']: item['description'] for item in response.json()}

            # Логируем обновление
            logging.info("Signature database updated successfully.")
            messagebox.showinfo("Update", "Signature database updated successfully.")

            # Сохранение сигнатур в файл signatures.csv
            with open('signatures.csv', mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['hash', 'description'])  # Записываем заголовки
                for hash_val, description in self.signatures.items():
                    writer.writerow([hash_val, description])  # Записываем хэш и описание

            logging.info("Signatures saved to signatures.csv successfully.")

        except requests.exceptions.RequestException as e:
            # В случае ошибки HTTP-запроса
            logging.error(f"Failed to update signature database: {e}")
            messagebox.showerror("Update Error",
                                 "Failed to update signature database. Please check your internet connection.")

if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
