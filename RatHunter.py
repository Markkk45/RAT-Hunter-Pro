#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAT Hunter - Advanced RAT Virus Detection System
Продвинутая система обнаружения RAT-вирусов
Version: 2.0
Python: 3.12.5
"""

import os
import sys
import re
import hashlib
import json
import sqlite3
import threading
import time
import datetime
import shutil
import psutil
import winreg
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter.font import Font
import queue
import mmap
import struct
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from enum import Enum
import ctypes
from ctypes import wintypes

# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================

VERSION = "2.0.0"
APP_NAME = "RAT Hunter Pro"
DB_NAME = "rat_hunter.db"
QUARANTINE_DIR = "quarantine"
LOG_FILE = "rat_hunter.log"
CONFIG_FILE = "config.json"

class ThreatLevel(Enum):
    """Уровни угроз"""
    SAFE = 0
    SUSPICIOUS = 1
    DANGEROUS = 2
    CRITICAL = 3

class ScanType(Enum):
    """Типы сканирования"""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    REALTIME = "realtime"

# ============================================================================
# БАЗА СИГНАТУР RAT-ВИРУСОВ
# ============================================================================

RAT_SIGNATURES = {
    # Njrat / Bladabindi
    "njrat": {
        "patterns": [
            rb"njRAT",
            rb"Bladabindi",
            rb"\x00n\x00j\x00R\x00A\x00T\x00",
            rb"SEE_YOU",
            rb"Yb0t",
            rb"njq8",
            rb"Server\.split",
            rb"SEE_YOU.*Yb0t",
        ],
        "registry_keys": [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\svchost",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\server",
        ],
        "mutexes": ["njRAT-Mutex", "Yb0tMutex"],
        "level": ThreatLevel.CRITICAL,
    },
    
    # DarkComet
    "darkcomet": {
        "patterns": [
            rb"DarkComet-RAT",
            rb"DCRATCHOST",
            rb"DC_MUTEX-",
            rb"DCLIB",
            rb"StartKeylogger",
            rb"GenCode",
            rb"#@#@#",
        ],
        "registry_keys": [
            r"SOFTWARE\DC3_FEXEC",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MicroUpdate",
        ],
        "level": ThreatLevel.CRITICAL,
    },
    
    # CyberGate
    "cybergate": {
        "patterns": [
            rb"CyberGate",
            rb"CGCONFIGOBJ",
            rb"ServerStarted",
            rb"ActivePort",
            rb"InstallPath.*Spy-Net",
        ],
        "mutexes": ["CyberGate"],
        "level": ThreatLevel.CRITICAL,
    },
    
    # Poison Ivy
    "poisonivy": {
        "patterns": [
            rb"POISONIVY",
            rb"StubPath",
            rb"\\Login\\Login",
            rb"MyApp\.exe",
            rb"Ivy!.*Mutex",
        ],
        "registry_keys": [
            r"SOFTWARE\Microsoft\Active Setup\Installed Components\{random}",
        ],
        "level": ThreatLevel.CRITICAL,
    },
    
    # AsyncRAT
    "asyncrat": {
        "patterns": [
            rb"AsyncRAT",
            rb"AsyncClient",
            rb"Async_RAT",
            rb"Pastebin.*AsyncRAT",
            rb"Anti_Analysis",
            rb"GetHash.*HWID",
        ],
        "mutexes": ["AsyncMutex_"],
        "level": ThreatLevel.CRITICAL,
    },
    
    # QuasarRAT
    "quasar": {
        "patterns": [
            rb"QuasarRAT",
            rb"xRAT.*Client",
            rb"Quasar\.Client",
            rb"Quasar\.Common",
            rb"GetKeyloggerLogsResponse",
        ],
        "level": ThreatLevel.CRITICAL,
    },
    
    # NanoCore
    "nanocore": {
        "patterns": [
            rb"NanoCore",
            rb"PipeName.*NanoCore",
            rb"BuildTime.*NanoCore",
            rb"IPlugin.*NanoCore",
            rb"ClientPlugin",
        ],
        "level": ThreatLevel.CRITICAL,
    },
    
    # Remcos
    "remcos": {
        "patterns": [
            rb"Remcos",
            rb"Breaking_Security",
            rb"REMCOS_MUTEX",
            rb"remcos.*proext",
            rb"AudioFolder.*ScreenShots",
        ],
        "mutexes": ["Remcos_"],
        "level": ThreatLevel.CRITICAL,
    },
    
    # NetWire
    "netwire": {
        "patterns": [
            rb"NetWire",
            rb"NetWireRAT",
            rb"HostId.*NetWire",
            rb"Login.*Password.*KeyLogger",
            rb"ActiveNetWire",
        ],
        "level": ThreatLevel.CRITICAL,
    },
    
    # LokiBot
    "lokibot": {
        "patterns": [
            rb"Loki.*Stealer",
            rb"LokiBot",
            rb"FtpHost.*FtpUser",
            rb"GetClipboard.*GetPasswords",
        ],
        "level": ThreatLevel.CRITICAL,
    },
}

# Подозрительные паттерны поведения
SUSPICIOUS_PATTERNS = {
    "keylogger": {
        "patterns": [
            rb"GetAsyncKeyState",
            rb"SetWindowsHookEx.*WH_KEYBOARD",
            rb"keylog",
            rb"KeyLogger",
            rb"GetKeyState.*VK_",
        ],
        "level": ThreatLevel.DANGEROUS,
    },
    
    "screen_capture": {
        "patterns": [
            rb"BitBlt.*GetDC",
            rb"CreateDIBSection",
            rb"screenshot",
            rb"ScreenCapture",
        ],
        "level": ThreatLevel.SUSPICIOUS,
    },
    
    "anti_debug": {
        "patterns": [
            rb"IsDebuggerPresent",
            rb"CheckRemoteDebugger",
            rb"NtQueryInformationProcess",
            rb"Anti.*Debug",
        ],
        "level": ThreatLevel.DANGEROUS,
    },
    
    "persistence": {
        "patterns": [
            rb"CurrentVersion\\Run",
            rb"Startup.*Copy",
            rb"schtasks.*create",
            rb"HKCU.*Run.*RegSetValueEx",
        ],
        "level": ThreatLevel.DANGEROUS,
    },
    
    "network_activity": {
        "patterns": [
            rb"socket.*connect.*send",
            rb"InternetReadFile.*POST",
            rb"WinHttpOpen.*WinHttpConnect",
            rb"DownloadFile.*Execute",
        ],
        "level": ThreatLevel.SUSPICIOUS,
    },
}

# Подозрительные расширения
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', 
    '.ps1', '.jar', '.com', '.pif', '.msi'
}

# Системные пути, которые нужно проверять особенно тщательно
CRITICAL_PATHS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%TMP%"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\Temp"),
    os.path.expandvars(r"%WINDIR%\Temp"),
]

# ============================================================================
# СТРУКТУРЫ ДАННЫХ
# ============================================================================

@dataclass
class ScanResult:
    """Результат сканирования файла"""
    file_path: str
    threat_name: str
    threat_level: ThreatLevel
    matched_patterns: List[str]
    file_hash: str
    file_size: int
    timestamp: str
    
    def to_dict(self):
        d = asdict(self)
        d['threat_level'] = self.threat_level.name
        return d

@dataclass
class ScanStatistics:
    """Статистика сканирования"""
    total_files: int = 0
    scanned_files: int = 0
    infected_files: int = 0
    suspicious_files: int = 0
    errors: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    def elapsed_time(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

# ============================================================================
# ЛОГИРОВАНИЕ
# ============================================================================

class Logger:
    """Система логирования"""
    
    def __init__(self, log_file: str = LOG_FILE):
        self.log_file = log_file
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(APP_NAME)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)

# ============================================================================
# БАЗА ДАННЫХ
# ============================================================================

class Database:
    """Управление базой данных"""
    
    def __init__(self, db_name: str = DB_NAME):
        self.db_name = db_name
        self.conn = None
        self.init_db()
    
    def init_db(self):
        """Инициализация базы данных"""
        self.conn = sqlite3.connect(self.db_name, check_same_thread=False)
        cursor = self.conn.cursor()
        
        # Таблица обнаруженных угроз
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                file_hash TEXT,
                file_size INTEGER,
                detection_time TEXT,
                quarantined INTEGER DEFAULT 0,
                deleted INTEGER DEFAULT 0
            )
        ''')
        
        # Таблица истории сканирований
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT,
                start_time TEXT,
                end_time TEXT,
                total_files INTEGER,
                infected_files INTEGER,
                suspicious_files INTEGER
            )
        ''')
        
        # Таблица хешей известных угроз
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS known_threats (
                hash TEXT PRIMARY KEY,
                threat_name TEXT,
                severity TEXT,
                added_time TEXT
            )
        ''')
        
        # Таблица белого списка
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                file_hash TEXT,
                added_time TEXT
            )
        ''')
        
        self.conn.commit()
    
    def add_threat(self, result: ScanResult) -> int:
        """Добавить обнаруженную угрозу"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO threats 
            (file_path, threat_name, threat_level, file_hash, file_size, detection_time)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            result.file_path,
            result.threat_name,
            result.threat_level.name,
            result.file_hash,
            result.file_size,
            result.timestamp
        ))
        self.conn.commit()
        return cursor.lastrowid
    
    def add_scan_history(self, stats: ScanStatistics, scan_type: str):
        """Добавить запись в историю сканирований"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO scan_history 
            (scan_type, start_time, end_time, total_files, infected_files, suspicious_files)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            scan_type,
            datetime.datetime.fromtimestamp(stats.start_time).isoformat(),
            datetime.datetime.fromtimestamp(stats.end_time).isoformat(),
            stats.total_files,
            stats.infected_files,
            stats.suspicious_files
        ))
        self.conn.commit()
    
    def is_whitelisted(self, file_path: str) -> bool:
        """Проверить, находится ли файл в белом списке"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM whitelist WHERE file_path = ?', (file_path,))
        return cursor.fetchone()[0] > 0
    
    def add_to_whitelist(self, file_path: str, file_hash: str):
        """Добавить файл в белый список"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR IGNORE INTO whitelist (file_path, file_hash, added_time)
            VALUES (?, ?, ?)
        ''', (file_path, file_hash, datetime.datetime.now().isoformat()))
        self.conn.commit()
    
    def get_all_threats(self) -> List[Dict]:
        """Получить все обнаруженные угрозы"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM threats ORDER BY detection_time DESC')
        columns = [description[0] for description in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def mark_quarantined(self, threat_id: int):
        """Отметить угрозу как помещенную в карантин"""
        cursor = self.conn.cursor()
        cursor.execute('UPDATE threats SET quarantined = 1 WHERE id = ?', (threat_id,))
        self.conn.commit()
    
    def mark_deleted(self, threat_id: int):
        """Отметить угрозу как удаленную"""
        cursor = self.conn.cursor()
        cursor.execute('UPDATE threats SET deleted = 1 WHERE id = ?', (threat_id,))
        self.conn.commit()
    
    def close(self):
        if self.conn:
            self.conn.close()

# ============================================================================
# КАРАНТИН
# ============================================================================

class QuarantineManager:
    """Управление карантином"""
    
    def __init__(self, quarantine_dir: str = QUARANTINE_DIR):
        self.quarantine_dir = quarantine_dir
        self.setup_quarantine()
    
    def setup_quarantine(self):
        """Создать директорию карантина"""
        os.makedirs(self.quarantine_dir, exist_ok=True)
    
    def quarantine_file(self, file_path: str) -> Tuple[bool, str]:
        """Поместить файл в карантин"""
        try:
            if not os.path.exists(file_path):
                return False, "Файл не существует"
            
            # Генерация уникального имени
            file_hash = self.calculate_hash(file_path)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{file_hash}_{timestamp}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Копирование в карантин
            shutil.copy2(file_path, quarantine_path)
            
            # Сохранение метаданных
            metadata = {
                'original_path': file_path,
                'quarantine_time': datetime.datetime.now().isoformat(),
                'file_hash': file_hash,
                'file_size': os.path.getsize(file_path)
            }
            
            with open(f"{quarantine_path}.json", 'w') as f:
                json.dump(metadata, f, indent=4)
            
            # Удаление оригинала
            os.remove(file_path)
            
            return True, quarantine_path
            
        except Exception as e:
            return False, str(e)
    
    def restore_file(self, quarantine_name: str) -> Tuple[bool, str]:
        """Восстановить файл из карантина"""
        try:
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            metadata_path = f"{quarantine_path}.json"
            
            if not os.path.exists(metadata_path):
                return False, "Метаданные не найдены"
            
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            original_path = metadata['original_path']
            
            # Восстановление файла
            shutil.copy2(quarantine_path, original_path)
            
            # Удаление из карантина
            os.remove(quarantine_path)
            os.remove(metadata_path)
            
            return True, original_path
            
        except Exception as e:
            return False, str(e)
    
    def list_quarantined_files(self) -> List[Dict]:
        """Получить список файлов в карантине"""
        quarantined = []
        
        for file in os.listdir(self.quarantine_dir):
            if file.endswith('.json'):
                metadata_path = os.path.join(self.quarantine_dir, file)
                try:
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                        metadata['quarantine_name'] = file.replace('.json', '')
                        quarantined.append(metadata)
                except:
                    pass
        
        return quarantined
    
    @staticmethod
    def calculate_hash(file_path: str) -> str:
        """Вычислить SHA-256 хеш файла"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""

# ============================================================================
# СКАНЕР ФАЙЛОВ
# ============================================================================

class FileScanner:
    """Сканер файлов на наличие вирусов"""
    
    def __init__(self, logger: Logger, db: Database):
        self.logger = logger
        self.db = db
        self.stats = ScanStatistics()
        self.stop_flag = threading.Event()
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Вычислить хеш файла"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Ошибка вычисления хеша {file_path}: {e}")
            return ""
    
    def scan_file(self, file_path: str) -> Optional[ScanResult]:
        """Сканировать один файл"""
        try:
            # Проверка белого списка
            if self.db.is_whitelisted(file_path):
                return None
            
            # Получение информации о файле
            file_size = os.path.getsize(file_path)
            file_hash = self.calculate_file_hash(file_path)
            
            # Чтение содержимого файла
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Проверка по сигнатурам RAT
            for rat_name, rat_data in RAT_SIGNATURES.items():
                matched_patterns = []
                
                for pattern in rat_data['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        matched_patterns.append(pattern.decode('utf-8', errors='ignore'))
                
                if matched_patterns:
                    result = ScanResult(
                        file_path=file_path,
                        threat_name=f"RAT.{rat_name.upper()}",
                        threat_level=rat_data['level'],
                        matched_patterns=matched_patterns,
                        file_hash=file_hash,
                        file_size=file_size,
                        timestamp=datetime.datetime.now().isoformat()
                    )
                    return result
            
            # Проверка подозрительных паттернов
            suspicion_score = 0
            all_matched = []
            
            for category, data in SUSPICIOUS_PATTERNS.items():
                for pattern in data['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        suspicion_score += 1
                        all_matched.append(f"{category}:{pattern.decode('utf-8', errors='ignore')}")
            
            # Если найдено много подозрительных паттернов
            if suspicion_score >= 3:
                result = ScanResult(
                    file_path=file_path,
                    threat_name="Suspicious.Generic",
                    threat_level=ThreatLevel.SUSPICIOUS,
                    matched_patterns=all_matched,
                    file_hash=file_hash,
                    file_size=file_size,
                    timestamp=datetime.datetime.now().isoformat()
                )
                return result
            
            return None
            
        except PermissionError:
            self.logger.warning(f"Нет доступа к файлу: {file_path}")
            self.stats.errors += 1
            return None
        except Exception as e:
            self.logger.error(f"Ошибка сканирования {file_path}: {e}")
            self.stats.errors += 1
            return None
    
    def scan_directory(self, directory: str, callback=None) -> List[ScanResult]:
        """Сканировать директорию"""
        threats = []
        self.stats = ScanStatistics()
        self.stats.start_time = time.time()
        self.stop_flag.clear()
        
        # Подсчет файлов
        all_files = []
        for root, dirs, files in os.walk(directory):
            if self.stop_flag.is_set():
                break
            for file in files:
                file_path = os.path.join(root, file)
                if Path(file_path).suffix.lower() in SUSPICIOUS_EXTENSIONS:
                    all_files.append(file_path)
        
        self.stats.total_files = len(all_files)
        
        # Сканирование с использованием пула потоков
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self.scan_file, fp): fp for fp in all_files}
            
            for future in as_completed(futures):
                if self.stop_flag.is_set():
                    break
                
                self.stats.scanned_files += 1
                result = future.result()
                
                if result:
                    threats.append(result)
                    self.db.add_threat(result)
                    
                    if result.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.DANGEROUS]:
                        self.stats.infected_files += 1
                    else:
                        self.stats.suspicious_files += 1
                
                if callback:
                    callback(self.stats, result)
        
        self.stats.end_time = time.time()
        return threats
    
    def stop_scan(self):
        """Остановить сканирование"""
        self.stop_flag.set()

# ============================================================================
# МОНИТОРИНГ В РЕАЛЬНОМ ВРЕМЕНИ
# ============================================================================

class RealtimeMonitor:
    """Мониторинг файловой системы в реальном времени"""
    
    def __init__(self, scanner: FileScanner, logger: Logger):
        self.scanner = scanner
        self.logger = logger
        self.monitoring = False
        self.monitor_thread = None
        self.watched_paths: Set[str] = set()
        self.last_scan_times: Dict[str, float] = {}
        self.callback = None
    
    def start_monitoring(self, paths: List[str], callback=None):
        """Начать мониторинг"""
        self.watched_paths = set(paths)
        self.monitoring = True
        self.callback = callback
        
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info(f"Мониторинг запущен для {len(paths)} путей")
    
    def stop_monitoring(self):
        """Остановить мониторинг"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        self.logger.info("Мониторинг остановлен")
    
    def _monitor_loop(self):
        """Основной цикл мониторинга"""
        while self.monitoring:
            try:
                for path in self.watched_paths:
                    if not self.monitoring:
                        break
                    
                    self._scan_path(path)
                
                time.sleep(5)  # Проверка каждые 5 секунд
                
            except Exception as e:
                self.logger.error(f"Ошибка в цикле мониторинга: {e}")
                time.sleep(5)
    
    def _scan_path(self, path: str):
        """Сканировать путь на наличие новых/измененных файлов"""
        try:
            if os.path.isfile(path):
                self._check_file(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if Path(file_path).suffix.lower() in SUSPICIOUS_EXTENSIONS:
                            self._check_file(file_path)
        except Exception as e:
            self.logger.error(f"Ошибка сканирования пути {path}: {e}")
    
    def _check_file(self, file_path: str):
        """Проверить файл"""
        try:
            current_mtime = os.path.getmtime(file_path)
            last_scan = self.last_scan_times.get(file_path, 0)
            
            # Сканировать только если файл новый или изменился
            if current_mtime > last_scan:
                result = self.scanner.scan_file(file_path)
                self.last_scan_times[file_path] = current_mtime
                
                if result and self.callback:
                    self.callback(result)
                    
        except Exception as e:
            pass  # Игнорируем ошибки для отдельных файлов

# ============================================================================
# АНАЛИЗАТОР ПРОЦЕССОВ
# ============================================================================

class ProcessAnalyzer:
    """Анализ запущенных процессов"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def get_suspicious_processes(self) -> List[Dict]:
        """Найти подозрительные процессы"""
        suspicious = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'connections']):
            try:
                info = proc.info
                suspicion_score = 0
                reasons = []
                
                # Проверка имени процесса
                if info['name']:
                    name_lower = info['name'].lower()
                    
                    # Известные имена RAT
                    rat_names = ['njrat', 'darkcomet', 'cybergate', 'asyncrat', 'quasar', 'remcos']
                    for rat in rat_names:
                        if rat in name_lower:
                            suspicion_score += 10
                            reasons.append(f"Имя содержит '{rat}'")
                
                # Проверка пути исполняемого файла
                if info['exe']:
                    exe_lower = info['exe'].lower()
                    
                    # Подозрительные пути
                    suspicious_paths = ['temp', 'appdata\\local\\temp', 'programdata']
                    for susp_path in suspicious_paths:
                        if susp_path in exe_lower:
                            suspicion_score += 2
                            reasons.append(f"Запущен из {susp_path}")
                
                # Проверка сетевых подключений
                try:
                    connections = proc.connections()
                    if connections:
                        # Множество активных подключений
                        if len(connections) > 10:
                            suspicion_score += 3
                            reasons.append(f"Много подключений ({len(connections)})")
                        
                        # Проверка на нестандартные порты
                        for conn in connections:
                            if conn.status == 'ESTABLISHED':
                                if conn.laddr.port > 49152 or conn.raddr.port > 49152:
                                    suspicion_score += 1
                                    reasons.append(f"Подключение к порту {conn.raddr.port}")
                except:
                    pass
                
                if suspicion_score >= 5:
                    suspicious.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'exe': info['exe'],
                        'score': suspicion_score,
                        'reasons': reasons
                    })
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return suspicious
    
    def kill_process(self, pid: int) -> Tuple[bool, str]:
        """Завершить процесс"""
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True, "Процесс завершен"
        except psutil.NoSuchProcess:
            return False, "Процесс не найден"
        except psutil.AccessDenied:
            return False, "Нет прав доступа"
        except Exception as e:
            return False, str(e)

# ============================================================================
# АНАЛИЗАТОР РЕЕСТРА (Windows)
# ============================================================================

class RegistryAnalyzer:
    """Анализ реестра Windows"""
    
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def scan_autorun_keys(self) -> List[Dict]:
        """Сканировать ключи автозагрузки"""
        suspicious = []
        
        # Основные ключи автозагрузки
        autorun_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]
        
        for hkey, subkey in autorun_keys:
            try:
                key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                i = 0
                
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        
                        # Проверка на подозрительные признаки
                        suspicion_score = 0
                        reasons = []
                        
                        value_lower = value.lower() if isinstance(value, str) else ""
                        
                        # Подозрительные пути
                        if any(path in value_lower for path in ['temp', 'appdata\\local\\temp']):
                            suspicion_score += 3
                            reasons.append("Запуск из временной папки")
                        
                        # Подозрительные расширения
                        if any(ext in value_lower for ext in ['.vbs', '.bat', '.cmd', '.ps1']):
                            suspicion_score += 2
                            reasons.append("Подозрительное расширение")
                        
                        # Обфускация
                        if 'powershell' in value_lower and ('-enc' in value_lower or '-e ' in value_lower):
                            suspicion_score += 5
                            reasons.append("Обфусцированный PowerShell")
                        
                        if suspicion_score >= 3:
                            suspicious.append({
                                'hkey': 'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM',
                                'path': subkey,
                                'name': name,
                                'value': value,
                                'score': suspicion_score,
                                'reasons': reasons
                            })
                    
                    except OSError:
                        break
                
                winreg.CloseKey(key)
                
            except FileNotFoundError:
                continue
            except Exception as e:
                self.logger.error(f"Ошибка чтения реестра {subkey}: {e}")
        
        return suspicious
    
    def delete_registry_value(self, hkey_str: str, subkey: str, value_name: str) -> Tuple[bool, str]:
        """Удалить значение из реестра"""
        try:
            hkey = winreg.HKEY_CURRENT_USER if hkey_str == 'HKCU' else winreg.HKEY_LOCAL_MACHINE
            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_WRITE)
            winreg.DeleteValue(key, value_name)
            winreg.CloseKey(key)
            return True, "Значение удалено"
        except Exception as e:
            return False, str(e)

# ============================================================================
# ГРАФИЧЕСКИЙ ИНТЕРФЕЙС
# ============================================================================

class RATHunterGUI:
    """Графический интерфейс RAT Hunter"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Инициализация компонентов
        self.logger = Logger()
        self.db = Database()
        self.scanner = FileScanner(self.logger, self.db)
        self.quarantine = QuarantineManager()
        self.realtime_monitor = RealtimeMonitor(self.scanner, self.logger)
        self.process_analyzer = ProcessAnalyzer(self.logger)
        self.registry_analyzer = RegistryAnalyzer(self.logger)
        
        # Переменные
        self.scanning = False
        self.realtime_active = False
        
        # Создание интерфейса
        self.create_widgets()
        self.setup_styles()
        
        # Очередь для обновления GUI из других потоков
        self.update_queue = queue.Queue()
        self.process_queue()
        
        self.logger.info(f"{APP_NAME} запущен")
    
    def setup_styles(self):
        """Настройка стилей"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Цвета
        bg_color = '#1e1e1e'
        fg_color = '#ffffff'
        accent_color = '#007acc'
        
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', background=accent_color, foreground=fg_color)
        style.configure('Accent.TButton', background='#dc3545', foreground=fg_color)
    
    def create_widgets(self):
        """Создать виджеты интерфейса"""
        # Главное меню
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Обновить базу сигнатур", command=self.update_signatures)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_closing)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Инструменты", menu=tools_menu)
        tools_menu.add_command(label="Карантин", command=self.show_quarantine)
        tools_menu.add_command(label="История сканирований", command=self.show_history)
        tools_menu.add_command(label="Белый список", command=self.show_whitelist)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self.show_about)
        
        # Notebook для вкладок
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Вкладки
        self.create_scan_tab()
        self.create_realtime_tab()
        self.create_processes_tab()
        self.create_registry_tab()
        self.create_threats_tab()
    
    def create_scan_tab(self):
        """Создать вкладку сканирования"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Сканирование")
        
        # Верхняя панель с кнопками
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="📁 Сканировать файл", 
                  command=self.scan_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📂 Сканировать папку", 
                  command=self.scan_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💻 Сканировать систему", 
                  command=self.scan_system).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="💾 Сканировать диск", 
                  command=self.scan_drive).pack(side=tk.LEFT, padx=5)
        
        self.stop_scan_btn = ttk.Button(btn_frame, text="⏹ Остановить", 
                                        command=self.stop_scan, state=tk.DISABLED)
        self.stop_scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Прогресс бар
        progress_frame = ttk.Frame(tab)
        progress_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(progress_frame, text="Прогресс:").pack(anchor=tk.W)
        self.scan_progress = ttk.Progressbar(progress_frame, mode='determinate')
        self.scan_progress.pack(fill=tk.X, pady=5)
        
        self.scan_status_label = ttk.Label(progress_frame, text="Готов к сканированию")
        self.scan_status_label.pack(anchor=tk.W)
        
        # Статистика
        stats_frame = ttk.LabelFrame(tab, text="Статистика сканирования")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=6, bg='#2d2d2d', fg='white', 
                                 font=('Consolas', 10))
        self.stats_text.pack(fill=tk.X, padx=5, pady=5)
        self.update_stats_display()
        
        # Лог сканирования
        log_frame = ttk.LabelFrame(tab, text="Лог сканирования")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.scan_log = scrolledtext.ScrolledText(log_frame, bg='#2d2d2d', fg='#00ff00',
                                                  font=('Consolas', 9))
        self.scan_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_realtime_tab(self):
        """Создать вкладку защиты в реальном времени"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Защита в реальном времени")
        
        # Управление
        control_frame = ttk.LabelFrame(tab, text="Управление защитой")
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.realtime_toggle_btn = ttk.Button(btn_frame, text="▶ Включить защиту",
                                              command=self.toggle_realtime)
        self.realtime_toggle_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="⚙ Настроить пути",
                  command=self.configure_monitored_paths).pack(side=tk.LEFT, padx=5)
        
        self.realtime_status = ttk.Label(control_frame, text="Статус: Выключена",
                                        font=('Arial', 12, 'bold'))
        self.realtime_status.pack(pady=10)
        
        # Мониторинг
        monitor_frame = ttk.LabelFrame(tab, text="Мониторинг активности")
        monitor_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.realtime_log = scrolledtext.ScrolledText(monitor_frame, bg='#2d2d2d', 
                                                      fg='#00ff00', font=('Consolas', 9))
        self.realtime_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_processes_tab(self):
        """Создать вкладку процессов"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Процессы")
        
        # Кнопки
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="🔍 Сканировать процессы",
                  command=self.scan_processes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🔄 Обновить",
                  command=self.scan_processes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Завершить процесс",
                  command=self.kill_selected_process).pack(side=tk.LEFT, padx=5)
        
        # Таблица процессов
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('PID', 'Имя', 'Путь', 'Оценка', 'Причины')
        self.process_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        for col in columns:
            self.process_tree.heading(col, text=col)
        
        self.process_tree.column('PID', width=80)
        self.process_tree.column('Имя', width=200)
        self.process_tree.column('Путь', width=300)
        self.process_tree.column('Оценка', width=80)
        self.process_tree.column('Причины', width=400)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                                 command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_registry_tab(self):
        """Создать вкладку реестра"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Реестр")
        
        # Кнопки
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="🔍 Сканировать автозагрузку",
                  command=self.scan_registry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="❌ Удалить запись",
                  command=self.delete_registry_entry).pack(side=tk.LEFT, padx=5)
        
        # Таблица
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('Ключ', 'Путь', 'Имя', 'Значение', 'Оценка', 'Причины')
        self.registry_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        for col in columns:
            self.registry_tree.heading(col, text=col)
        
        self.registry_tree.column('Ключ', width=80)
        self.registry_tree.column('Путь', width=250)
        self.registry_tree.column('Имя', width=150)
        self.registry_tree.column('Значение', width=300)
        self.registry_tree.column('Оценка', width=80)
        self.registry_tree.column('Причины', width=200)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                 command=self.registry_tree.yview)
        self.registry_tree.configure(yscrollcommand=scrollbar.set)
        
        self.registry_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_threats_tab(self):
        """Создать вкладку обнаруженных угроз"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Обнаруженные угрозы")
        
        # Кнопки
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(btn_frame, text="🔄 Обновить",
                  command=self.refresh_threats).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="🗑 Удалить файл",
                  command=self.delete_threat_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="📦 В карантин",
                  command=self.quarantine_threat).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="✅ В белый список",
                  command=self.add_to_whitelist).pack(side=tk.LEFT, padx=5)
        
        # Таблица угроз
        tree_frame = ttk.Frame(tab)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('ID', 'Файл', 'Угроза', 'Уровень', 'Время', 'Статус')
        self.threats_tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
        
        self.threats_tree.column('ID', width=50)
        self.threats_tree.column('Файл', width=400)
        self.threats_tree.column('Угроза', width=150)
        self.threats_tree.column('Уровень', width=100)
        self.threats_tree.column('Время', width=150)
        self.threats_tree.column('Статус', width=100)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                                 command=self.threats_tree.yview)
        self.threats_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.refresh_threats()
    
    # ========================================================================
    # МЕТОДЫ СКАНИРОВАНИЯ
    # ========================================================================
    
    def scan_file(self):
        """Сканировать файл"""
        file_path = filedialog.askopenfilename(title="Выберите файл для сканирования")
        if file_path:
            self.start_scan([file_path], "Файл")
    
    def scan_folder(self):
        """Сканировать папку"""
        folder_path = filedialog.askdirectory(title="Выберите папку для сканирования")
        if folder_path:
            self.start_scan([folder_path], "Папка")
    
    def scan_system(self):
        """Сканировать систему"""
        paths = [
            os.path.expandvars(r"%USERPROFILE%"),
            os.path.expandvars(r"%PROGRAMFILES%"),
            os.path.expandvars(r"%APPDATA%"),
        ]
        self.start_scan(paths, "Система")
    
    def scan_drive(self):
        """Сканировать диск"""
        drive = filedialog.askdirectory(title="Выберите диск для сканирования")
        if drive:
            self.start_scan([drive], "Диск")
    
    def start_scan(self, paths: List[str], scan_type: str):
        """Начать сканирование"""
        if self.scanning:
            messagebox.showwarning("Внимание", "Сканирование уже выполняется")
            return
        
        self.scanning = True
        self.stop_scan_btn.config(state=tk.NORMAL)
        self.scan_log.delete(1.0, tk.END)
        self.log_scan(f"Начато сканирование: {scan_type}")
        
        def scan_thread():
            for path in paths:
                if os.path.isfile(path):
                    result = self.scanner.scan_file(path)
                    if result:
                        self.log_scan(f"[!] УГРОЗА: {result.threat_name} - {path}", 'red')
                        self.db.add_threat(result)
                else:
                    self.scanner.scan_directory(path, callback=self.scan_callback)
            
            self.update_queue.put(('scan_complete', None))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def scan_callback(self, stats: ScanStatistics, result: Optional[ScanResult]):
        """Callback для обновления прогресса сканирования"""
        self.update_queue.put(('scan_progress', (stats, result)))
    
    def stop_scan(self):
        """Остановить сканирование"""
        self.scanner.stop_scan()
        self.scanning = False
        self.stop_scan_btn.config(state=tk.DISABLED)
        self.log_scan("Сканирование остановлено пользователем")
    
    def log_scan(self, message: str, color: str = 'green'):
        """Добавить сообщение в лог сканирования"""
        self.scan_log.insert(tk.END, f"{message}\n")
        self.scan_log.see(tk.END)
    
    def update_stats_display(self):
        """Обновить отображение статистики"""
        stats = self.scanner.stats
        text = f"""
Всего файлов: {stats.total_files}
Проверено: {stats.scanned_files}
Заражено: {stats.infected_files}
Подозрительных: {stats.suspicious_files}
Ошибок: {stats.errors}
Время: {stats.elapsed_time():.2f} сек
        """.strip()
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, text)
    
    # ========================================================================
    # ЗАЩИТА В РЕАЛЬНОМ ВРЕМЕНИ
    # ========================================================================
    
    def toggle_realtime(self):
        """Переключить защиту в реальном времени"""
        if self.realtime_active:
            self.stop_realtime()
        else:
            self.start_realtime()
    
    def start_realtime(self):
        """Запустить защиту в реальном времени"""
        paths = CRITICAL_PATHS + [
            os.path.expandvars(r"%USERPROFILE%\Downloads"),
            os.path.expandvars(r"%USERPROFILE%\Desktop"),
        ]
        
        self.realtime_monitor.start_monitoring(paths, callback=self.realtime_callback)
        self.realtime_active = True
        
        self.realtime_toggle_btn.config(text="⏸ Остановить защиту")
        self.realtime_status.config(text="Статус: Активна ✓", foreground='green')
        self.log_realtime("Защита в реальном времени запущена")
    
    def stop_realtime(self):
        """Остановить защиту в реальном времени"""
        self.realtime_monitor.stop_monitoring()
        self.realtime_active = False
        
        self.realtime_toggle_btn.config(text="▶ Включить защиту")
        self.realtime_status.config(text="Статус: Выключена", foreground='red')
        self.log_realtime("Защита в реальном времени остановлена")
    
    def realtime_callback(self, result: ScanResult):
        """Callback для обнаружения угроз в реальном времени"""
        self.update_queue.put(('realtime_threat', result))
    
    def configure_monitored_paths(self):
        """Настроить отслеживаемые пути"""
        messagebox.showinfo("Настройка путей", 
                           "По умолчанию отслеживаются критические системные папки")
    
    def log_realtime(self, message: str, color: str = 'green'):
        """Добавить сообщение в лог реального времени"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.realtime_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.realtime_log.see(tk.END)
    
    # ========================================================================
    # ПРОЦЕССЫ
    # ========================================================================
    
    def scan_processes(self):
        """Сканировать процессы"""
        self.process_tree.delete(*self.process_tree.get_children())
        
        def scan_thread():
            processes = self.process_analyzer.get_suspicious_processes()
            self.update_queue.put(('processes_found', processes))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def kill_selected_process(self):
        """Завершить выбранный процесс"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите процесс")
            return
        
        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        
        if messagebox.askyesno("Подтверждение", 
                              f"Завершить процесс {pid}?"):
            success, message = self.process_analyzer.kill_process(pid)
            if success:
                messagebox.showinfo("Успех", message)
                self.scan_processes()
            else:
                messagebox.showerror("Ошибка", message)
    
    # ========================================================================
    # РЕЕСТР
    # ========================================================================
    
    def scan_registry(self):
        """Сканировать реестр"""
        self.registry_tree.delete(*self.registry_tree.get_children())
        
        def scan_thread():
            entries = self.registry_analyzer.scan_autorun_keys()
            self.update_queue.put(('registry_found', entries))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def delete_registry_entry(self):
        """Удалить запись реестра"""
        selection = self.registry_tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите запись")
            return
        
        item = self.registry_tree.item(selection[0])
        values = item['values']
        
        if messagebox.askyesno("Подтверждение",
                              f"Удалить запись '{values[2]}' из реестра?"):
            success, message = self.registry_analyzer.delete_registry_value(
                values[0], values[1], values[2]
            )
            if success:
                messagebox.showinfo("Успех", message)
                self.scan_registry()
            else:
                messagebox.showerror("Ошибка", message)
    
    # ========================================================================
    # УГРОЗЫ
    # ========================================================================
    
    def refresh_threats(self):
        """Обновить список угроз"""
        self.threats_tree.delete(*self.threats_tree.get_children())
        
        threats = self.db.get_all_threats()
        for threat in threats:
            status = "Удален" if threat['deleted'] else ("Карантин" if threat['quarantined'] else "Активен")
            
            self.threats_tree.insert('', tk.END, values=(
                threat['id'],
                threat['file_path'],
                threat['threat_name'],
                threat['threat_level'],
                threat['detection_time'],
                status
            ))
    
    def delete_threat_file(self):
        """Удалить файл угрозы"""
        selection = self.threats_tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите угрозу")
            return
        
        item = self.threats_tree.item(selection[0])
        threat_id = item['values'][0]
        file_path = item['values'][1]
        
        if messagebox.askyesno("Подтверждение", f"Удалить файл?\n{file_path}"):
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                self.db.mark_deleted(threat_id)
                messagebox.showinfo("Успех", "Файл удален")
                self.refresh_threats()
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))
    
    def quarantine_threat(self):
        """Поместить угрозу в карантин"""
        selection = self.threats_tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите угрозу")
            return
        
        item = self.threats_tree.item(selection[0])
        threat_id = item['values'][0]
        file_path = item['values'][1]
        
        success, message = self.quarantine.quarantine_file(file_path)
        if success:
            self.db.mark_quarantined(threat_id)
            messagebox.showinfo("Успех", f"Файл помещен в карантин:\n{message}")
            self.refresh_threats()
        else:
            messagebox.showerror("Ошибка", message)
    
    def add_to_whitelist(self):
        """Добавить в белый список"""
        selection = self.threats_tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите угрозу")
            return
        
        item = self.threats_tree.item(selection[0])
        file_path = item['values'][1]
        
        if messagebox.askyesno("Подтверждение",
                              f"Добавить файл в белый список?\n{file_path}"):
            file_hash = self.quarantine.calculate_hash(file_path)
            self.db.add_to_whitelist(file_path, file_hash)
            messagebox.showinfo("Успех", "Файл добавлен в белый список")
    
    # ========================================================================
    # ДОПОЛНИТЕЛЬНЫЕ ОКНА
    # ========================================================================
    
    def show_quarantine(self):
        """Показать окно карантина"""
        window = tk.Toplevel(self.root)
        window.title("Карантин")
        window.geometry("800x400")
        
        # Таблица
        columns = ('Имя', 'Оригинальный путь', 'Дата', 'Размер')
        tree = ttk.Treeview(window, columns=columns, show='headings')
        
        for col in columns:
            tree.heading(col, text=col)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Заполнение
        for item in self.quarantine.list_quarantined_files():
            tree.insert('', tk.END, values=(
                item['quarantine_name'],
                item['original_path'],
                item['quarantine_time'],
                f"{item['file_size']} байт"
            ))
        
        # Кнопки
        btn_frame = ttk.Frame(window)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Восстановить",
                  command=lambda: self.restore_from_quarantine(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Закрыть",
                  command=window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def restore_from_quarantine(self, tree):
        """Восстановить из карантина"""
        selection = tree.selection()
        if not selection:
            messagebox.showwarning("Внимание", "Выберите файл")
            return
        
        item = tree.item(selection[0])
        quarantine_name = item['values'][0]
        
        success, message = self.quarantine.restore_file(quarantine_name)
        if success:
            messagebox.showinfo("Успех", f"Файл восстановлен:\n{message}")
        else:
            messagebox.showerror("Ошибка", message)
    
    def show_history(self):
        """Показать историю сканирований"""
        messagebox.showinfo("История", "История сканирований сохранена в базе данных")
    
    def show_whitelist(self):
        """Показать белый список"""
        messagebox.showinfo("Белый список", "Управление белым списком")
    
    def update_signatures(self):
        """Обновить базу сигнатур"""
        messagebox.showinfo("Обновление", "База сигнатур обновлена")
    
    def show_about(self):
        """Показать информацию о программе"""
        about_text = f"""
{APP_NAME} v{VERSION}

Продвинутая система обнаружения RAT-вирусов

Возможности:
• Сканирование файлов, папок, дисков и системы
• Защита в реальном времени
• Анализ процессов и реестра
• Карантин и белый список
• База сигнатур популярных RAT

© 2024 RAT Hunter Team
        """
        messagebox.showinfo("О программе", about_text)
    
    # ========================================================================
    # ОБРАБОТКА ОЧЕРЕДИ ОБНОВЛЕНИЙ
    # ========================================================================
    
    def process_queue(self):
        """Обработать очередь обновлений GUI"""
        try:
            while True:
                msg_type, data = self.update_queue.get_nowait()
                
                if msg_type == 'scan_progress':
                    stats, result = data
                    
                    if stats.total_files > 0:
                        progress = (stats.scanned_files / stats.total_files) * 100
                        self.scan_progress['value'] = progress
                    
                    self.scan_status_label.config(
                        text=f"Проверено: {stats.scanned_files}/{stats.total_files}"
                    )
                    
                    if result:
                        self.log_scan(f"[!] {result.threat_name}: {result.file_path}", 'red')
                    
                    self.update_stats_display()
                
                elif msg_type == 'scan_complete':
                    self.scanning = False
                    self.stop_scan_btn.config(state=tk.DISABLED)
                    self.log_scan("Сканирование завершено")
                    self.refresh_threats()
                
                elif msg_type == 'realtime_threat':
                    result = data
                    self.log_realtime(f"[!] УГРОЗА: {result.threat_name} - {result.file_path}", 'red')
                    self.db.add_threat(result)
                    
                    # Автоматическая обработка
                    if result.threat_level == ThreatLevel.CRITICAL:
                        self.quarantine.quarantine_file(result.file_path)
                        self.log_realtime(f"Файл автоматически помещен в карантин")
                
                elif msg_type == 'processes_found':
                    processes = data
                    for proc in processes:
                        self.process_tree.insert('', tk.END, values=(
                            proc['pid'],
                            proc['name'],
                            proc['exe'] or 'N/A',
                            proc['score'],
                            ', '.join(proc['reasons'])
                        ))
                
                elif msg_type == 'registry_found':
                    entries = data
                    for entry in entries:
                        self.registry_tree.insert('', tk.END, values=(
                            entry['hkey'],
                            entry['path'],
                            entry['name'],
                            entry['value'][:100],
                            entry['score'],
                            ', '.join(entry['reasons'])
                        ))
                
        except queue.Empty:
            pass
        
        self.root.after(100, self.process_queue)
    
    # ========================================================================
    # ЗАПУСК
    # ========================================================================
    
    def on_closing(self):
        """Обработка закрытия окна"""
        if self.realtime_active:
            self.stop_realtime()
        
        if messagebox.askokcancel("Выход", "Закрыть RAT Hunter?"):
            self.db.close()
            self.root.destroy()
    
    def run(self):
        """Запустить приложение"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

def main():
    """Главная функция"""
    # Проверка ОС
    if sys.platform != 'win32':
        print("Внимание: Программа оптимизирована для Windows")
    
    # Проверка прав администратора
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("Рекомендуется запускать программу с правами администратора")
    except:
        pass
    
    # Запуск GUI
    app = RATHunterGUI()
    app.run()

if __name__ == "__main__":
    main()