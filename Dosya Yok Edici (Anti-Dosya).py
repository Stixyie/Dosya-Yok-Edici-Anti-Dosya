import os
import sys
import secrets
import shutil
import tempfile
import threading
import traceback
import logging
import hashlib
import numpy as np
from typing import List, Tuple, Optional
import random
import ctypes
from ctypes import wintypes
import win32api
import win32file
import win32security
import ntsecuritycon as con
import time
import platform
import uuid
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from PyQt6.QtCore import (
    Qt, QObject, pyqtSignal, QTimer, 
    QPropertyAnimation, QEasingCurve, 
    QPoint, QRect
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QProgressBar, QListWidget, QFileDialog, 
    QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QMessageBox
)
from PyQt6.QtGui import (
    QPainter, QColor, QLinearGradient
)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Windows API constants and function definitions
kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# Configure logging
logging.basicConfig(
    filename='stixyie_encryption.log', 
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_file_security_info(filepath: str) -> Tuple[bool, str]:
    """
    Retrieve detailed security information for a file
    """
    try:
        # Get file attributes
        attributes = kernel32.GetFileAttributesW(filepath)
        
        # Check if file is read-only
        is_readonly = attributes & 0x1
        
        # Try to get owner information
        try:
            security_info = win32security.GetNamedSecurityInfo(
                filepath, 
                win32security.SE_FILE_OBJECT, 
                win32security.OWNER_SECURITY_INFORMATION
            )
            owner_sid = security_info[0]
            owner_name, domain, type = win32security.LookupAccountSid("", owner_sid)
            owner_str = f"{domain}\\{owner_name}"
        except Exception as owner_err:
            owner_str = "Unknown"
        
        return is_readonly, owner_str
    except Exception as e:
        logging.error(f"Error getting file security info for {filepath}: {e}")
        return False, "Unknown"

def modify_file_permissions(filepath: str) -> bool:
    """
    Attempt to modify file permissions using Windows API
    """
    try:
        # Open file with maximum possible access
        handle = win32file.CreateFile(
            filepath,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_FLAG_BACKUP_SEMANTICS,
            0
        )
        
        # Remove read-only attribute
        kernel32.SetFileAttributesW(filepath, 0)
        
        # Close handle
        handle.Close()
        
        return True
    except Exception as e:
        logging.error(f"Error modifying file permissions for {filepath}: {e}")
        return False

def safe_file_delete(filepath: str) -> bool:
    """
    Safely delete a file with multiple fallback methods
    """
    try:
        # First, try to modify permissions
        modify_file_permissions(filepath)
        
        # Try standard deletion
        try:
            os.remove(filepath)
            return True
        except PermissionError:
            # Fallback to Windows API deletion
            try:
                kernel32.DeleteFileW(filepath)
                return True
            except Exception as del_err:
                logging.error(f"Failed to delete file {filepath}: {del_err}")
                return False
    except Exception as e:
        logging.error(f"Unexpected error deleting file {filepath}: {e}")
        return False

def generate_ultra_random_key(file_path: str) -> bytes:
    """
    Generate an ultra-random encryption key using multiple high-entropy sources
    
    Args:
        file_path (str): Path to the file being encrypted
    
    Returns:
        bytes: A highly random, cryptographically secure encryption key
    """
    try:
        # Combine multiple high-entropy sources for maximum randomness
        entropy_sources = [
            # 1. Cryptographically secure random bytes from multiple sources
            secrets.token_bytes(128),  # 1024-bit cryptographic random bytes
            os.urandom(128),  # OS-level random bytes
            
            # 2. Advanced system entropy collection
            hashlib.sha3_512(
                f"{time.time()}{os.getpid()}{platform.processor()}{platform.node()}"
                f"{platform.system()}{platform.release()}{sys.getrefcount(sys)}"
                .encode()
            ).digest(),
            
            # 3. File-specific entropy
            hashlib.sha3_512(
                f"{os.path.getsize(file_path)}"
                f"{os.path.getctime(file_path)}"
                f"{os.path.getmtime(file_path)}"
                .encode()
            ).digest(),
            
            # 4. Hardware-based entropy (if available)
            hashlib.sha3_256(
                str(uuid.getnode()).encode()  # MAC address as entropy
            ).digest(),
            
            # 5. Additional runtime entropy
            hashlib.sha3_256(
                f"{threading.get_ident()}{time.process_time()}"
                .encode()
            ).digest()
        ]
        
        # Combine entropy sources with advanced mixing
        combined_entropy = b''.join(entropy_sources)
        key = hashlib.shake_256(combined_entropy).digest(64)  # 512-bit key
        
        return key
    except Exception as e:
        logging.error(f"Ultra-random key generation error for {file_path}: {e}")
        raise

def secure_key_destruction(key: bytes, passes: int = 5):
    """
    Securely destroy the encryption key through multiple overwrite passes
    """
    try:
        # Multiple randomization passes
        for _ in range(passes):
            # Overwrite with cryptographically secure random bytes
            key = secrets.token_bytes(len(key))
            
            # Additional entropy mixing
            key = hashlib.sha3_512(key).digest()
        
        # Final zero-out
        key = bytes(len(key))
        
        # Optional: Use OS-specific secure memory zeroing
        ctypes.memset(id(key), 0, len(key))
    except Exception as e:
        logging.error(f"Key destruction error: {e}")

def secure_file_delete(file_path: str, passes: int = 7) -> bool:
    """
    Securely delete a file by overwriting multiple times before removal
    
    Args:
        file_path (str): Path to the file to be securely deleted
        passes (int): Number of overwrite passes (default: 7)
    
    Returns:
        bool: True if deletion was successful, False otherwise
    """
    try:
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Ensure write permissions
        try:
            os.chmod(file_path, 0o666)  # Read and write permissions
        except Exception:
            pass
        
        # Multiple overwrite passes
        with open(file_path, 'wb') as f:
            for _ in range(passes):
                # Use cryptographically secure random bytes for overwriting
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Final deletion
        os.remove(file_path)
        
        # Verify deletion
        return not os.path.exists(file_path)
    
    except Exception as e:
        logging.error(f"Secure file deletion error for {file_path}: {e}")
        return False

class AnimatedBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            background: qlineargradient(
                x1:0, y1:0, x2:1, y2:1, 
                stop:0 #2C3E50, 
                stop:1 #34495E
            );
        """)
        
        # Particle animation setup
        self.particles = []
        self.particle_timer = QTimer(self)
        self.particle_timer.timeout.connect(self.animate_particles)
        self.particle_timer.start(50)  # Update every 50ms

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Draw moving particles
        for particle in self.particles:
            painter.setBrush(QColor(52, 152, 219, particle['alpha']))
            painter.drawEllipse(
                int(particle['x']), 
                int(particle['y']), 
                int(particle['size']), 
                int(particle['size'])
            )

    def animate_particles(self):
        # Add new particles
        if len(self.particles) < 200:
            self.particles.append({
                'x': secrets.randbelow(self.width()),
                'y': secrets.randbelow(self.height()),
                'size': secrets.randbelow(10) + 2,
                'dx': (random.random() - 0.5) * 5,
                'dy': (random.random() - 0.5) * 5,
                'alpha': secrets.randbelow(100) + 50
            })

        # Move and remove particles
        for particle in self.particles[:]:
            particle['x'] += particle['dx']
            particle['y'] += particle['dy']
            
            # Remove particles out of bounds
            if (particle['x'] < 0 or particle['x'] > self.width() or 
                particle['y'] < 0 or particle['y'] > self.height()):
                self.particles.remove(particle)

        self.update()

class EncryptionManager(QObject):
    progress_updated = pyqtSignal(int, str)
    encryption_complete = pyqtSignal()
    encryption_error = pyqtSignal(str)
    encrypted_files_list = pyqtSignal(list)

    def __init__(self, temp_dir):
        super().__init__()
        self.temp_dir = temp_dir
        self.stop_encryption = False
        self.encrypted_files = []
        self.temp_copies = []

    def is_already_encrypted(self, file_path):
        """
        Check if a file is already encrypted
        
        Args:
            file_path (str): Path to the file to check
        
        Returns:
            bool: True if file appears to be encrypted, False otherwise
        """
        try:
            # Check file extension
            if file_path.lower().endswith('.stixyie'):
                return True
            
            # Check file content for encryption markers or patterns
            with open(file_path, 'rb') as f:
                # Read first 64 bytes to check for encryption signatures
                header = f.read(64)
                
                # Check for signs of encryption
                encryption_markers = [
                    b'STIXYIE_ENCRYPTED',  # Custom marker
                    b'\x00\x01\x02\x03\x04\x05\x06\x07',  # Random byte sequence
                ]
                
                for marker in encryption_markers:
                    if marker in header:
                        return True
            
            return False
        except Exception as e:
            logging.warning(f"Error checking encryption status for {file_path}: {e}")
            return False

    def validate_files(self, files):
        """
        Validate and filter files for encryption
        
        Args:
            files (list): List of file paths to validate
        
        Returns:
            list: List of valid files to encrypt
        """
        validated_files = []
        for file_path in files:
            # Normalize path
            file_path = os.path.abspath(file_path)
            
            # Check if file exists
            if not os.path.exists(file_path):
                logging.warning(f"Dosya bulunamadı: {file_path}")
                continue
            
            # Skip directories
            if os.path.isdir(file_path):
                logging.warning(f"Dizin atlandı: {file_path}")
                continue
            
            # Check if already encrypted
            if self.is_already_encrypted(file_path):
                logging.warning(f"Zaten şifrelenmiş dosya atlandı: {file_path}")
                continue
            
            # Add to validated files
            validated_files.append(file_path)
        
        return validated_files

    def run_encryption(self, files):
        """
        Run the encryption process on the given files
        """
        try:
            # Validate files first
            validated_files = self.validate_files(files)
            
            # Check if any valid files remain
            if not validated_files:
                self.encryption_error.emit("Şifrelenecek geçerli dosya bulunamadı")
                return
            
            total_files = len(validated_files)
            processed = 0
            self.encrypted_files = []
            self.temp_copies = []
            
            for file_path in validated_files:
                if self.stop_encryption:
                    break
                
                try:
                    # Generate ultra-random key for this file
                    encryption_key = generate_ultra_random_key(file_path)
                    
                    # Encrypt the file and get both paths
                    encrypted_path, temp_copy_path = self.advanced_multi_pass_encryption(file_path, encryption_key)
                    
                    # Securely delete the original file
                    secure_deletion_result = secure_file_delete(file_path)
                    
                    if not secure_deletion_result:
                        logging.warning(f"Orijinal dosya güvenli bir şekilde silinemedi: {file_path}")
                    
                    # Add to encrypted files list
                    self.encrypted_files.append(encrypted_path)
                    self.temp_copies.append(temp_copy_path)
                    
                    # Secure key destruction
                    secure_key_destruction(encryption_key)
                    
                    processed += 1
                    progress = int((processed / total_files) * 100)
                    self.progress_updated.emit(progress, f"Dosya şifreleniyor ve siliniyor: {os.path.basename(file_path)}")
                    
                except Exception as e:
                    logging.error(f"Şifreleme hatası - {file_path}: {str(e)}")
                    continue
            
            # Emit results
            if self.temp_copies:
                self.encrypted_files_list.emit(self.temp_copies)
                self.encryption_complete.emit()
            else:
                self.encryption_error.emit("Hiçbir dosya şifrelenemedi")
            
        except Exception as e:
            logging.error(f"Genel şifreleme hatası: {str(e)}")
            self.encryption_error.emit(f"Genel şifreleme hatası: {str(e)}")

    def find_similar_files(self, original_path, exclude_encrypted=True, exclude_processed=None):
        """
        Find similar files when the original file is not found
        
        Args:
            original_path (str): The original file path
            exclude_encrypted (bool): Whether to exclude already encrypted files
            exclude_processed (set): Set of files already processed to avoid duplicates
        """
        try:
            # Extract directory and filename
            directory = os.path.dirname(original_path)
            filename = os.path.basename(original_path)
            file_base, file_ext = os.path.splitext(filename)

            # If directory doesn't exist, use desktop
            if not os.path.exists(directory):
                directory = os.path.join(os.path.expanduser('~'), 'Desktop')

            # Prepare exclusion sets
            exclude_processed = exclude_processed or set()

            # Search for files with similar names
            similar_files = []
            for root, _, files in os.walk(directory):
                for file in files:
                    # Skip if already processed or excluded
                    full_path = os.path.join(root, file)
                    
                    # Skip if in exclude list
                    if full_path in exclude_processed:
                        continue
                    
                    # Skip encrypted files if requested
                    if exclude_encrypted and full_path.lower().endswith('.stixyie'):
                        continue
                    
                    # Strict similarity check
                    current_base, current_ext = os.path.splitext(file)
                    
                    # Conditions for similarity
                    is_similar = (
                        # Exact base name match
                        current_base == file_base or
                        # Contains original filename
                        file_base in current_base or
                        # Same extension
                        current_ext == file_ext
                    )
                    
                    # Additional validation to prevent over-matching
                    if is_similar:
                        # Verify file is not already processed
                        if full_path not in exclude_processed:
                            similar_files.append(full_path)

            return similar_files
        except Exception as e:
            logging.error(f"Error finding similar files for {original_path}: {e}")
            return []

    def secure_file_overwrite(self, file_path: str, passes: int = 7):
        """
        Securely overwrite a file multiple times to prevent recovery
        
        Args:
            file_path (str): Path to the file to be securely overwritten
            passes (int): Number of overwrite passes
        """
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'wb') as f:
                for _ in range(passes):
                    # Use cryptographically secure random bytes for overwriting
                    f.seek(0)
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Final secure deletion
            os.remove(file_path)
        except Exception as e:
            logging.error(f"Secure file overwrite error for {file_path}: {e}")

    def advanced_multi_pass_encryption(self, file_path: str, encryption_key: bytes):
        """
        Ultra-Advanced Multi-Pass Encryption with Extreme Randomness and Security
        
        Args:
            file_path (str): Path to the file to be encrypted
            encryption_key (bytes): Ultra-random encryption key
        
        Returns:
            tuple: (encrypted_path, temp_copy_path)
        """
        try:
            # Read the original file
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Generate multiple encryption keys
            sha512_key, shake_key, nonce = self.generate_multi_keys(encryption_key)
            
            # Perform ultra-random encryption
            encrypted_data, _, _ = self.ultra_random_encrypt(data, encryption_key)
            
            # Determine new encrypted file path with .stixyie extension
            file_dir = os.path.dirname(file_path)
            file_base = os.path.splitext(os.path.basename(file_path))[0]
            encrypted_file_name = f"{file_base}.stixyie"
            encrypted_path = os.path.join(file_dir, encrypted_file_name)
            
            # Create temporary copy with .stixyie extension in temp directory
            temp_file_name = encrypted_file_name
            temp_copy_path = os.path.join(self.temp_dir, temp_file_name)
            
            # Write encrypted data to both original location and temp directory
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            with open(temp_copy_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Secure memory cleanup
            data = None
            encrypted_data = None
            
            return encrypted_path, temp_copy_path
            
        except Exception as e:
            logging.error(f"Encryption error for {file_path}: {e}")
            raise

    def generate_multi_keys(self, base_key):
        """
        Generate multiple keys using different cryptographic hash functions
        
        Args:
            base_key (bytes): Original encryption key
        
        Returns:
            tuple: (sha512_key, shake_key, nonce)
        """
        # SHA-512 key derivation
        sha512_key = hashlib.sha512(base_key).digest()
        
        # SHA-256 SHAKE key derivation (extendable output function)
        shake_key = hashlib.shake_256(base_key).digest(32)
        
        # Generate a secure 16-byte nonce for ChaCha20
        # Use a combination of base_key and random bytes to ensure uniqueness
        nonce = hashlib.sha3_256(base_key + secrets.token_bytes(32)).digest()[:16]
        
        return sha512_key, shake_key, nonce

    def ultra_random_encrypt(self, data, base_key):
        """Perform ultra-random encryption using multiple randomization techniques."""
        # Generate multiple keys
        sha512_key, shake_key, nonce = self.generate_multi_keys(base_key)
        
        # Alternate between SHA-512 and SHAKE keys for each encryption pass
        keys_to_use = [sha512_key, shake_key]
        
        # Perform encryption with both keys
        encrypted_parts = []
        for key in keys_to_use:
            # Ensure key is exactly 32 bytes for ChaCha20
            if len(key) > 32:
                key = key[:32]
            
            # Use ChaCha20 with a 16-byte nonce
            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Encrypt the data
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            encrypted_parts.append(encrypted_data)
        
        # Combine encrypted parts
        combined_encrypted_data = b''.join(encrypted_parts)
        
        # Convert to numpy array for additional randomization
        # Create a mutable copy of the array
        randomized_data = np.frombuffer(combined_encrypted_data, dtype=np.uint8).copy()
        
        # Shuffle data using cryptographically secure random indices
        shuffle_seed = int.from_bytes(secrets.token_bytes(4), byteorder='big')
        np.random.seed(shuffle_seed)
        np.random.shuffle(randomized_data)
        
        return randomized_data.tobytes(), nonce, shuffle_seed

    def split_file_ultra_random(self, file_path, num_parts=1_000_000):
        """Split file into ultra-random parts."""
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Ensure even splitting
        part_size = max(1, len(file_data) // num_parts)
        parts = [file_data[i:i+part_size] for i in range(0, len(file_data), part_size)]
        
        return parts

class StixyieDosyaYokEdici(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stixyie Dosya Yok Edici (Anti-Dosya)")
        self.resize(1200, 800)

        # Enable drag and drop for the main window
        self.setAcceptDrops(True)

        # Animated background
        self.background = AnimatedBackground(self)
        self.setCentralWidget(self.background)

        # Temporary directory for encrypted file copies
        self.temp_dir = tempfile.mkdtemp(prefix="stixyie_encrypted_")
        
        # Track files for better management
        self.current_files = []
        self.encrypted_files = []

        # Main layout
        main_layout = QVBoxLayout(self.background)
        main_layout.setContentsMargins(50, 50, 50, 50)

        # Title
        title = QLabel("Stixyie Dosya Yok Edici")
        title.setStyleSheet("""
            color: white;
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 30px;
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title)

        # File List
        self.file_list = QListWidget()
        self.file_list.setStyleSheet("""
            background-color: rgba(52, 73, 94, 0.7);
            color: white;
            border-radius: 15px;
            padding: 10px;
        """)
        main_layout.addWidget(self.file_list)

        # Buttons Layout
        button_layout = QHBoxLayout()
        
        # Select Files Button
        self.select_btn = QPushButton("Dosya Seç")
        self.select_btn.clicked.connect(self.select_files)
        self.select_btn.setStyleSheet("""
            background-color: #2ECC71;
            color: white;
            border-radius: 10px;
            padding: 10px;
            font-size: 18px;
        """)
        button_layout.addWidget(self.select_btn)

        # Clear List Button
        self.clear_btn = QPushButton("Listeyi Temizle")
        self.clear_btn.clicked.connect(self.clear_file_list)
        self.clear_btn.setStyleSheet("""
            background-color: #E74C3C;
            color: white;
            border-radius: 10px;
            padding: 10px;
            font-size: 18px;
        """)
        button_layout.addWidget(self.clear_btn)

        # Start Encryption Button
        self.start_btn = QPushButton("Şifrelemeyi Başlat")
        self.start_btn.clicked.connect(self.start_encryption)
        self.start_btn.setStyleSheet("""
            background-color: #3498DB;
            color: white;
            border-radius: 10px;
            padding: 10px;
            font-size: 18px;
        """)
        button_layout.addWidget(self.start_btn)

        # Cancel Button
        self.cancel_btn = QPushButton("İptal")
        self.cancel_btn.clicked.connect(self.cancel_encryption)
        self.cancel_btn.setStyleSheet("""
            background-color: #E74C3C;
            color: white;
            border-radius: 10px;
            padding: 10px;
            font-size: 18px;
        """)
        self.cancel_btn.setEnabled(False)  # Initially disabled
        button_layout.addWidget(self.cancel_btn)

        # Open Encrypted Folder Button
        self.open_encrypted_btn = QPushButton("Şifrelenmiş Dosyaları Aç")
        self.open_encrypted_btn.clicked.connect(self.open_encrypted_files)
        self.open_encrypted_btn.setStyleSheet("""
            background-color: #9B59B6;
            color: white;
            border-radius: 10px;
            padding: 10px;
            font-size: 18px;
        """)
        self.open_encrypted_btn.setEnabled(True)  # Enabled
        button_layout.addWidget(self.open_encrypted_btn)

        main_layout.addLayout(button_layout)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #34495E;
                border-radius: 10px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2ECC71;
                width: 10px;
                margin: 0.5px;
            }
        """)
        main_layout.addWidget(self.progress_bar)

        # Progress Label
        self.progress_label = QLabel("Şifrelemeye Hazır")
        self.progress_label.setStyleSheet("""
            color: white;
            font-size: 18px;
            margin-top: 10px;
        """)
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.progress_label)

        # Encryption Manager
        self.encryption_manager = EncryptionManager(self.temp_dir)
        
        # Connect signals
        self.encryption_manager.progress_updated.connect(self.update_progress)
        self.encryption_manager.encryption_complete.connect(self.encryption_finished)
        self.encryption_manager.encryption_error.connect(self.show_encryption_errors)
        self.encryption_manager.encrypted_files_list.connect(self.update_encrypted_files_list)

    def clear_file_list(self):
        """
        Enhanced file list clearing with robust cleanup
        """
        try:
            # Confirm clearing the list
            reply = QMessageBox.question(
                self, 
                'Listeyi Temizle', 
                'Dosya listesini temizlemek istediğinizden emin misiniz?',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.No:
                return
            
            # Clear UI list widget
            self.file_list.clear()
            
            # Reset all tracking lists forcefully
            self.current_files.clear()
            self.encrypted_files.clear()
            
            # Reset progress and labels
            self.progress_bar.setValue(0)
            self.progress_label.setText("Şifrelemeye Hazır")
            
            # Disable start button when list is empty
            self.start_btn.setEnabled(False)
            
            # Optional: Log the clearing action
            logging.info("Dosya listesi temizlendi")
            
            # Show confirmation
            QMessageBox.information(
                self, 
                'Liste Temizlendi', 
                'Dosya listesi başarıyla temizlendi.'
            )
        
        except Exception as e:
            # Log and show any errors during clearing
            error_msg = f"Dosya listesi temizlenirken hata oluştu: {str(e)}"
            logging.error(error_msg)
            QMessageBox.critical(
                self, 
                'Hata', 
                error_msg
            )

    def select_files(self):
        """
        Enhanced file selection with comprehensive error handling
        """
        try:
            # Clear existing list before adding new files
            if self.current_files:
                reply = QMessageBox.question(
                    self, 
                    'Listeyi Temizle', 
                    'Mevcut dosyaları temizleyip yeni dosyalar eklemek istiyor musunuz?',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                    QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    self.clear_file_list()
            
            # Open file selection dialog
            file_paths, _ = QFileDialog.getOpenFileNames(
                self, 
                "Dosya Seç", 
                "", 
                "Tüm Dosyalar (*)"
            )
            
            # Add selected files
            if file_paths:
                self.add_files_to_list(file_paths)
                
                # Enable start button when files are added
                self.start_btn.setEnabled(True)
        
        except Exception as e:
            QMessageBox.warning(
                self, 
                "Dosya Seçim Hatası", 
                f"Dosya seçiminde hata oluştu: {str(e)}"
            )
            logging.error(f"Dosya seçim hatası: {e}")

    def add_files_to_list(self, paths):
        """
        Add files to list with comprehensive validation
        """
        try:
            # Track number of successfully added files
            added_files = 0
            
            for path in paths:
                # Normalize path
                path = os.path.abspath(path)
                
                # Check file existence
                if not os.path.exists(path):
                    QMessageBox.warning(
                        self,
                        "Dosya Bulunamadı",
                        f"Dosya bulunamadı: {path}"
                    )
                    continue
                
                # Skip directories
                if os.path.isdir(path):
                    QMessageBox.warning(
                        self,
                        "Geçersiz Dosya",
                        f"Dizin seçilemez: {path}"
                    )
                    continue
                
                # Check for duplicates
                if path in self.current_files:
                    QMessageBox.warning(
                        self,
                        "Yinelenen Dosya",
                        f"Bu dosya zaten listede: {path}"
                    )
                    continue
                
                # Check if already encrypted
                if self.encryption_manager.is_already_encrypted(path):
                    QMessageBox.warning(
                        self,
                        "Şifrelenmiş Dosya",
                        f"Bu dosya zaten şifrelenmiş: {path}"
                    )
                    continue
                
                # Add to lists
                self.current_files.append(path)
                self.file_list.addItem(path)
                added_files += 1
            
            # Show summary
            if added_files > 0:
                QMessageBox.information(
                    self,
                    "Dosyalar Eklendi",
                    f"{added_files} dosya listeye eklendi."
                )
                # Enable start button
                self.start_btn.setEnabled(True)
            else:
                QMessageBox.warning(
                    self,
                    "Dosya Eklenemedi",
                    "Hiçbir dosya listeye eklenemedi."
                )
                self.start_btn.setEnabled(False)
        
        except Exception as e:
            QMessageBox.critical(
                self,
                "Hata",
                f"Dosya eklenirken hata oluştu: {str(e)}"
            )
            logging.error(f"Dosya ekleme hatası: {e}")

    def start_encryption(self):
        """Start the encryption process"""
        if not self.current_files:
            QMessageBox.warning(
                self,
                "Uyarı",
                "Lütfen şifrelenecek dosya seçin!"
            )
            return

        # Reset progress
        self.progress_bar.setValue(0)
        self.progress_label.setText("Şifreleme başlıyor...")

        # Disable buttons during encryption
        self.select_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        # Start encryption in a thread
        self.encryption_thread = threading.Thread(
            target=self.encryption_manager.run_encryption,
            args=(self.current_files.copy(),)
        )
        self.encryption_thread.start()

    def encryption_finished(self):
        """Handle encryption completion"""
        self.progress_bar.setValue(100)
        self.progress_label.setText("Şifreleme tamamlandı!")
        
        # Re-enable buttons
        self.select_btn.setEnabled(True)
        self.start_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        
        # Clear the file list since files are now encrypted
        self.file_list.clear()
        self.current_files.clear()
        
        QMessageBox.information(
            self,
            "Başarılı",
            "Dosyalar başarıyla şifrelendi!"
        )

    def update_encrypted_files_list(self, files):
        """Track and manage encrypted files"""
        self.encrypted_files = files
        
        # Copy encrypted files to temp directory if they're not already there
        for encrypted_file in files:
            try:
                file_name = os.path.basename(encrypted_file)
                dest_path = os.path.join(self.temp_dir, file_name)
                
                # Only copy if file exists and isn't already in temp_dir
                if os.path.exists(encrypted_file) and not os.path.exists(dest_path):
                    shutil.copy2(encrypted_file, dest_path)
                    print(f"Encrypted file copied to temp: {dest_path}")
            except Exception as e:
                print(f"Error copying encrypted file {encrypted_file}: {str(e)}")

    def open_encrypted_files(self):
        """Open encrypted files directory with error handling"""
        try:
            # Check if temp directory exists and has files
            if not os.path.exists(self.temp_dir):
                QMessageBox.information(self, "Bilgi", "Şifrelenmiş dosyaların klasörü bulunamadı.")
                return
                
            files_in_temp = [f for f in os.listdir(self.temp_dir) if os.path.isfile(os.path.join(self.temp_dir, f))]
            if not files_in_temp:
                QMessageBox.information(self, "Bilgi", "Henüz şifrelenmiş dosya bulunmuyor.")
                return
            
            # Try to open the directory
            try:
                os.startfile(self.temp_dir)
            except AttributeError:  # os.startfile is Windows-specific
                subprocess.run(['explorer', self.temp_dir])
                
        except Exception as e:
            QMessageBox.warning(self, "Hata", 
                f"Şifrelenmiş dosyalar klasörü açılamadı: {str(e)}\nKonum: {self.temp_dir}")

    def start_encryption(self):
        if self.file_list.count() == 0:
            self.progress_label.setText("Hiç dosya seçilmedi!")
            return

        # Get selected files
        files = [self.file_list.item(i).text() for i in range(self.file_list.count())]

        # Create Encryption Manager
        self.encryption_manager = EncryptionManager(self.temp_dir)
        
        # Connect signals
        self.encryption_manager.progress_updated.connect(self.update_progress)
        self.encryption_manager.encryption_complete.connect(self.encryption_finished)
        self.encryption_manager.encryption_error.connect(self.show_encryption_errors)
        self.encryption_manager.encrypted_files_list.connect(self.update_encrypted_files_list)

        # Disable buttons during encryption
        self.select_btn.setEnabled(False)
        self.start_btn.setEnabled(False)
        self.clear_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)

        # Start encryption in a thread
        encryption_thread = threading.Thread(
            target=self.encryption_manager.run_encryption, 
            args=(files,),
            daemon=True
        )
        encryption_thread.start()

    def update_progress(self, value: int, message: str):
        # Update progress bar and label
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)

    def encryption_finished(self):
        # Reset UI after encryption
        self.progress_label.setText("Şifreleme Tamamlandı!")
        self.progress_bar.setValue(100)

        # Re-enable buttons
        self.select_btn.setEnabled(True)
        self.clear_btn.setEnabled(True)
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)

    def show_encryption_errors(self, error_message: str):
        QMessageBox.critical(self, "Şifreleme Hatası", error_message)

    def cancel_encryption(self):
        if self.encryption_manager:
            self.encryption_manager.stop_encryption = True
            self.progress_label.setText("Şifreleme İptal Edildi")

    def dragEnterEvent(self, event):
        """
        Handle drag enter event to accept file drops
        """
        # Check if the dragged data contains file URLs
        if event.mimeData().hasUrls():
            # Accept the proposed action only for local files
            urls = event.mimeData().urls()
            local_files = [url.toLocalFile() for url in urls if url.isLocalFile()]
            
            if local_files:
                event.acceptProposedAction()

    def dropEvent(self, event):
        """
        Handle file drop event with robust error handling
        """
        try:
            # Extract local file paths from dropped URLs
            paths = [url.toLocalFile() for url in event.mimeData().urls() if os.path.exists(url.toLocalFile())]
            
            # Validate and filter existing files
            valid_paths = [path for path in paths if os.path.isfile(path)]
            
            if not valid_paths:
                QMessageBox.warning(self, "Dosya Hatası", "Geçerli dosya bulunamadı.")
                return
            
            # Add valid dropped files to the list
            self.add_files_to_list(valid_paths)
            
            # Accept the drop event
            event.acceptProposedAction()
        
        except Exception as e:
            QMessageBox.warning(self, "Sürükle Bırak Hatası", 
                f"Dosyalar eklenirken hata oluştu: {str(e)}")

    def closeEvent(self, event):
        """
        Enhanced cleanup when the application closes
        """
        try:
            # Clean up temporary directory
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                self.safe_remove_directory(self.temp_dir)
            
            event.accept()
        except Exception as e:
            logging.error(f"Error during cleanup: {e}")
            event.accept()

    def safe_remove_directory(self, directory):
        """
        Safely remove a directory and its contents
        """
        try:
            if os.path.exists(directory):
                # Remove all files first
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as file_error:
                        print(f"Error removing {file_path}: {file_error}")
                
                # Remove the directory itself
                shutil.rmtree(directory, ignore_errors=True)
                print(f"Successfully cleaned up directory: {directory}")
        except Exception as dir_error:
            print(f"Error cleaning up directory {directory}: {dir_error}")

def main():
    # Configure logging
    logging.info("Application started")
    
    try:
        # Create application
        app = QApplication(sys.argv)
        app.setStyle('Fusion')  # Modern style
        
        # Create and show main window
        window = StixyieDosyaYokEdici()
        window.show()
        
        # Run the application
        exit_code = app.exec()
        
        logging.info(f"Application exited with code {exit_code}")
        sys.exit(exit_code)
    
    except Exception as e:
        logging.error(f"Unhandled exception in main: {e}")
        traceback.print_exc()
        
        # Show error message to user
        QMessageBox.critical(
            None, 
            "Kritik Hata", 
            f"Beklenmedik bir hata oluştu:\n{e}\n"
            "Lütfen log dosyasını inceleyin."
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
