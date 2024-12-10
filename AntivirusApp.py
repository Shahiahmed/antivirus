import pika
import os
import tkinter as tk
from tkinter import filedialog


class AntivirusApp:
    def __init__(self, root, threat_db_path):
        self.root = root
        self.root.title("Antivirus")

        # Путь к базе данных угроз
        self.threat_db_path = threat_db_path

        # Настройка RabbitMQ
        self.queue_name = 'scan_queue'
        self.rabbitmq_host = 'localhost'
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(self.rabbitmq_host))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name)

        # Интерфейс
        self.scan_button = tk.Button(root, text="Сканировать папку", command=self.scan_folder)
        self.scan_button.pack(pady=20)

        self.result_label = tk.Label(root, text="Результаты сканирования будут здесь", width=50)
        self.result_label.pack(pady=20)

    def scan_folder(self):
        """Сканирует папку и отправляет файлы на проверку в очередь"""
        folder_path = filedialog.askdirectory()
        if not folder_path:
            return

        for foldername, subfolders, filenames in os.walk(folder_path):
            for filename in filenames:
                file_path = os.path.join(foldername, filename)
                # Отправляем файл на проверку в очередь RabbitMQ
                self.send_to_queue(file_path)

        self.result_label.config(text="Файлы отправлены на проверку.")

    def send_to_queue(self, file_path):
        """Отправка пути файла на проверку в очередь RabbitMQ"""
        self.channel.basic_publish(exchange='',
                                   routing_key=self.queue_name,
                                   body=file_path)
        print(f"Файл {file_path} отправлен на проверку.")

    def close(self):
        """Закрытие соединения с RabbitMQ"""
        self.connection.close()


# Запуск приложения
if __name__ == "__main__":
    threat_db_path = "./threat_db"  # Папка с базой данных угроз
    root = tk.Tk()
    app = AntivirusApp(root, threat_db_path)
    root.protocol("WM_DELETE_WINDOW", app.close)  # Закрытие соединения при закрытии окна
    root.mainloop()
