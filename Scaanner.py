import os
import time
import requests
import hashlib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

API_KEY = '9b0420a6d701b2c5d987a2117c3041527466ef0396a2b3517a3440ee6c04916a'

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return None
        elif event.event_type == 'created':
            file_path = event.src_path
            print(f'New file added: {file_path}')
            is_malware = check_virustotal(file_path)
            if is_malware:
                print(f'{file_path} is malware!')
            else:
                print(f'{file_path} is clean!')

def check_virustotal(file_path):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    file_hash = hashlib.sha256(file_content).hexdigest()

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': file_hash}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if json_response['response_code'] == 1:
            positives = json_response['positives']
            total = json_response['total']
            if positives > 0:
                return True
    return False

def monitor_folder(folder):
    event_handler = NewFileHandler()
    observer = Observer()
    observer.schedule(event_handler, folder, recursive=False)
    observer.start()
    print(f'Monitoring folder {folder} for new file additions...')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Example usage
folder = '.' # current folder
monitor_folder(folder)