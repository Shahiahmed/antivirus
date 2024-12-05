# consumer.py
import pika
import json
import os
from scanner import scan_directory, load_signatures
import logging

# Настройка логирования
logging.basicConfig(filename='logs/antivirus_worker.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Загрузка сигнатур
signatures = load_signatures('threat_db')
logging.info("Signature database loaded successfully.")

def callback(ch, method, properties, body):
    task = json.loads(body)
    file_path = task['file_path']
    logging.info(f"Starting scan for {file_path}")

    threats = scan_directory(file_path, signatures)
    if threats:
        for threat in threats:
            logging.info(f"Threat found: {threat[0]} ({threat[1]})")
            # Отправляем результат в очередь scan_results
            connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
            channel = connection.channel()
            channel.queue_declare(queue='scan_results', durable=True)
            result_message = json.dumps({
                'file_path': threat[0],
                'description': threat[1]
            })
            channel.basic_publish(
                exchange='',
                routing_key='scan_results',
                body=result_message,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Сделать сообщение долговечным
                )
            )
            connection.close()

    ch.basic_ack(delivery_tag=method.delivery_tag)

def start_consumer():
    connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
    channel = connection.channel()

    channel.queue_declare(queue='scan_tasks', durable=True)
    channel.basic_qos(prefetch_count=1)
    channel.basic_consume(queue='scan_tasks', on_message_callback=callback)

    logging.info(' [*] Waiting for scan tasks. To exit press CTRL+C')
    channel.start_consuming()

if __name__ == '__main__':
    start_consumer()
