# producer.py
import pika
import json


def send_scan_task(file_path):
    """
    Отправляет задачу сканирования файла в очередь RabbitMQ.

    Параметры:
        file_path (str): Путь к файлу для сканирования.
    """
    try:
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()

        # Объявляем очередь
        channel.queue_declare(queue='scan_tasks', durable=True)

        # Создаем сообщение
        message = json.dumps({
            'file_path': file_path
            # 'hash_type': 'TLSH'  # Удалено, так как всегда используем TLSH
        })

        # Отправляем сообщение
        channel.basic_publish(
            exchange='',
            routing_key='scan_tasks',
            body=message,
            properties=pika.BasicProperties(
                delivery_mode=2,  # Сделать сообщение долговечным
            )
        )
        print(f" [x] Sent scan task for {file_path}")
    except Exception as e:
        print(f" [!] Failed to send scan task for {file_path}: {e}")
    finally:
        connection.close()
