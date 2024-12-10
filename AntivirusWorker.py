import pika
import hashlib
import os


class AntivirusWorker:
    def __init__(self, threat_db_path, queue_name='scan_queue'):
        self.threat_db_path = threat_db_path
        self.hash_db = self.load_hash_db()

        # Настройка RabbitMQ
        self.queue_name = queue_name
        self.rabbitmq_host = 'localhost'
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(self.rabbitmq_host))
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name)

    def load_hash_db(self):
        """Загружаем хеши из базы данных"""
        hash_db = {'md5': set(), 'sha1': set(), 'sha256': set()}

        # Загружаем MD5 хеши
        md5_file = os.path.join(self.threat_db_path, 'full-hash-md5-aa')
        if os.path.exists(md5_file):
            with open(md5_file, 'r') as f:
                for line in f:
                    hash_db['md5'].add(line.strip())

        # Загружаем SHA-1 хеши
        sha1_file = os.path.join(self.threat_db_path, 'full-hash-sha1-aa')
        if os.path.exists(sha1_file):
            with open(sha1_file, 'r') as f:
                for line in f:
                    hash_db['sha1'].add(line.strip())

        # Загружаем SHA-256 хеши
        sha256_file = os.path.join(self.threat_db_path, 'full-hash-sha256-aa')
        if os.path.exists(sha256_file):
            with open(sha256_file, 'r') as f:
                for line in f:
                    hash_db['sha256'].add(line.strip())

        return hash_db

    def get_file_hashes(self, file_path):
        """Вычисляет хеши для файла (MD5, SHA-1, SHA-256)"""
        hashes = {'md5': None, 'sha1': None, 'sha256': None}

        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

                # Вычисляем MD5 хеш
                hashes['md5'] = hashlib.md5(file_data).hexdigest()

                # Вычисляем SHA-1 хеш
                hashes['sha1'] = hashlib.sha1(file_data).hexdigest()

                # Вычисляем SHA-256 хеш
                hashes['sha256'] = hashlib.sha256(file_data).hexdigest()

        except Exception as e:
            print(f"Ошибка при обработке файла {file_path}: {e}")

        return hashes

    def process_file(self, ch, method, properties, body):
        """Обрабатывает файл, полученный из очереди RabbitMQ"""
        file_path = body.decode('utf-8')
        print(f"Обработка файла: {file_path}")

        file_hashes = self.get_file_hashes(file_path)

        # Проверка хешей по всем типам (MD5, SHA1, SHA256)
        for hash_type, file_hash in file_hashes.items():
            if file_hash in self.hash_db[hash_type]:
                print(f"Файл {file_path} заражён!")
                return

        print(f"Файл {file_path} безопасен.")

    def start(self):
        """Запускает обработку сообщений из очереди RabbitMQ"""
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.process_file, auto_ack=True)
        print("Ожидание файлов на обработку...")
        self.channel.start_consuming()


# Запуск рабочего процесса
if __name__ == "__main__":
    threat_db_path = "./threat_db"  # Папка с базой данных угроз
    worker = AntivirusWorker(threat_db_path)
    worker.start()
