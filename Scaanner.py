import ctypes
import os
import time
import requests
import hashlib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pefile
import sys
import pydbg


#API KEY VIRUSTOTAL
API_KEY = '9b0420a6d701b2c5d987a2117c3041527466ef0396a2b3517a3440ee6c04916a'
# Define the known malicious APIs
MALICIOUS_APIS = ['CreateProcess', 'WriteMemory', 'VirtualAlloc']

# Define the severity levels for different types of malware
SEVERITY_LEVELS = {
    0: 'Not Malware',
    1: 'Low Severity Malware',
    2: 'Medium Severity Malware',
    3: 'High Severity Malware'
}

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return None
        elif event.event_type == 'created':
            file_path = event.src_path
            print(f'New file added: {file_path}')
            is_malware, severity = check_virustotal(file_path)
            if is_malware:
                print(f'{file_path} is malware with severity {severity}! via virustotal')
            else:
                print(f'{file_path} is clean! via virustotal')

            static_malware = static_malware_check(file_path)
            if static_malware:
                print(f'{file_path} is a malware! via static analysis')
            else:
                print(f'{file_path} is clean! via static analysis')
            dynamic_malware = dynamic_malware_check(file_path)
            print(f'{file_path} checked it is {dynamic_malware}! via dynamic analysis')

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
                severity = get_severity(json_response)
                return True, severity
    return False, None

def get_severity(json_response):
    engines = json_response['scans']
    detections = [engine for engine in engines if engines[engine]['detected']]
    num_detections = len(detections)
    if num_detections == 0:
        return 'Unknown'
    elif num_detections < 3:
        return 'Low'
    elif num_detections < 10:
        return 'Medium'
    else:
        return 'High'
    
def static_malware_check(file_path):
    # Load the PE file
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        # The file is not a valid PE file
        return False

    # Check if the file is marked as a DLL or an EXE
    if (pe.FILE_HEADER.Characteristics & pefile.IMAGE_FILE_DLL) or \
       (pe.FILE_HEADER.Characteristics & pefile.IMAGE_FILE_EXECUTABLE_IMAGE):
        # Check if the file has a debug directory
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            return True
        # Check if the file imports any suspicious APIs
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if 'kernel32.dll' in entry.dll.lower():
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.lower()
                        if 'createprocess' in api_name or \
                           'writememory' in api_name or \
                           'virtualalloc' in api_name:
                            return True
        # Check if the file contains suspicious resources
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name:
                if 'string' in resource_type.name.lower():
                    return True
            for resource in resource_type.directory.entries:
                if resource.name:
                    if 'config' in resource.name.lower() or \
                       'setup' in resource.name.lower() or \
                       'install' in resource.name.lower():
                        return True
    return False

# Define a function to monitor API calls during execution
def check_api_calls(dbg, args):
    # Get the API name from the stack
    api_name = args[0]
    # Check if the API is known to be malicious
    if api_name in MALICIOUS_APIS:
        # If the API is malicious, increase the severity level
        global severity_level
        severity_level += 1

# Define the main function to perform dynamic analysis
def dynamic_malware_check(file_path):
    # Load the PE file
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        # The file is not a valid PE file
        return SEVERITY_LEVELS[0]

    # Check if the file is marked as a DLL or an EXE
    if (pe.FILE_HEADER.Characteristics & pefile.IMAGE_FILE_DLL) or \
       (pe.FILE_HEADER.Characteristics & pefile.IMAGE_FILE_EXECUTABLE_IMAGE):
        # Initialize the severity level to 0
        global severity_level
        severity_level = 0

        # Create a Pydbg instance and attach it to the process
        dbg = pydbg.pydbg()
        pid = dbg.load(file_path)
        dbg.attach(pid)

        # Set a breakpoint on all API calls
        for func in pydbg.defines.ALL_APIS:
            dbg.func_resolve(func)
            dbg.set_callback(pydbg.defines.WINFUNCTYPE(None, pydbg.pydbg, ctypes.c_void_p))(check_api_calls)

        # Run the process and monitor its behavior
        dbg.run()

        # Detach the debugger and kill the process
        dbg.detach()
        os.kill(pid, 0)

        # Return the severity level based on the behavior observed during execution
        return SEVERITY_LEVELS[severity_level]
    else:
        # If the file is not marked as a DLL or an EXE, it is not malware
        return SEVERITY_LEVELS[0]
    

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
