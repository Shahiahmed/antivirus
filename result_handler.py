# result_handler.py
import pika
import json
import threading
import tkinter as tk
from tkinter import scrolledtext
import logging

class ResultHandler:
    def __init__(self, text_widget, stats_label):
        self.text_widget = text_widget
        self.stats_label = stats_label
        self.scanned_files = 0
        self.threats_found = 0
        self.start_time = time.time()
        self.lock = threading.Lock()

    def callback(self, ch, method, properties, body):
        result = json.loads(body)
        file_path = result['file_path']
        description = result['description']

        with self.lock:
            self.threats_found += 1
            elapsed_time = time.time() - self.start_time

            # Обновляем GUI (нужно использовать метод после событийного цикла)
            self.text_widget.after(0, self.text_widget.insert, tk.END, f"Threat found: {file_path} ({description})\n")
            self.text_widget.after(0, self.text_widget.see, tk.END)
            self.text_widget.after(0, self.stats_label.config, {
                'text': f"Stats: Scanned Files: {self.scanned_files}, Threats Found: {self.threats_found}, Time: {elapsed_time:.2f}s"
            })

        ch.basic_ack(delivery_tag=method.delivery_tag)

    def start_consuming(self):
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        channel = connection.channel()

        channel.queue_declare(queue='scan_results', durable=True)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='scan_results', on_message_callback=self.callback)

        logging.info(' [*] Waiting for scan results. To exit press CTRL+C')
        channel.start_consuming()

    def increment_scanned_files(self):
        with self.lock:
            self.scanned_files += 1
            elapsed_time = time.time() - self.start_time
            self.stats_label.config(
                text=f"Stats: Scanned Files: {self.scanned_files}, Threats Found: {self.threats_found}, Time: {elapsed_time:.2f}s")

def run_result_handler(result_handler):
    result_handler.start_consuming()
