import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import struct

# Cryptography 라이브러리 임포트
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# ==============================================================================
# I. 핵심 함수 및 고정 경로 설정 
# ==============================================================================

# --- 키 파일 저장 경로를 사용자가 지정한 폴더로 고정 ---
FIXED_KEY_DIR = ""
AES_KEY_PATH = os.path.join(FIXED_KEY_DIR, "aes_256.key")
PRIVATE_KEY_PATH = os.path.join(FIXED_KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(FIXED_KEY_DIR, "public.pem")

# 확장자 상수 정의
AES_EXT = ".aes_enc" # 9글자
HYB_EXT = ".hyb_enc" # 8글자

# GUI 표시용 파일 이름
AES_KEY_FILE = "aes_256.key"
PRIVATE_KEY_FILE = "private.pem"
PUBLIC_KEY_FILE = "public.pem"

# 대용량 파일 스트리밍을 위한 청크 크기 (1MB)
CHUNK_SIZE = 1024 * 1024 


# --- A. 포트 스캐너 함수 ---
def port_scan_worker(target_ip, port):
    """단일 포트를 스캔하는 워커 함수"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 스캔 속도를 위해 타임아웃을 짧게 설정
        sock.settimeout(0.1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            sock.close(); return port
        sock.close()
    except Exception: pass
    return None

def run_port_scanner(target_ip, start_port, end_port, callback):
    """주어진 범위의 포트를 멀티 스레드로 스캔"""
    open_ports = []
    callback(f"** 대상: {target_ip} 포트 스캔 시작 ({start_port}-{end_port}) **\n")
    try:
        # 최대 50개의 스레드를 사용하여 병렬 스캔
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(port_scan_worker, target_ip, port) for port in range(start_port, end_port + 1)]
            for future in futures:
                port = future.result()
                if port is not None:
                    open_ports.append(port); callback(f"  [+] 포트 {port} 열림\n")
        callback(f"\n** 스캔 완료. 총 {len(open_ports)}개 포트 열림: {sorted(open_ports)} **\n")
    except Exception as e:
        callback(f"❌ 스캔 오류 발생: {e}\n")


# --- B. AES-256 GCM (대칭키) 함수 ---
def load_aes_key(): 
    """저장된 AES 키를 로드"""
    try: return open(AES_KEY_PATH, "rb").read()
    except FileNotFoundError: return None

def generate_aes_key():
    """새로운 AES-256 (32바이트) 키 생성"""
    return os.urandom(32)

def encrypt_file_auto_delete_aes_gcm(filename, key, progress_callback): 
    """AES-256 GCM으로 파일 암호화 및 원본 삭제"""
    nonce = os.urandom(12) 
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_filename = filename + AES_EXT 
    
    file_size = os.path.getsize(filename)
    bytes_processed = 0
    
    progress_callback(0, f"암호화 시작: {os.path.basename(filename)}")
    
    with open(filename, "rb") as infile, open(encrypted_filename, "wb") as outfile:
        # 1. 헤더 기록: Nonce 길이 (4바이트), Nonce (12바이트)
        outfile.write(struct.pack('<I', len(nonce))) 
        outfile.write(nonce)
        
        # 2. 데이터 암호화 (청크 스트리밍)
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk: break
            
            outfile.write(encryptor.update(chunk))
            
            bytes_processed += len(chunk)
            percent = min(100, int((bytes_processed / file_size) * 100)) if file_size > 0 else 100
            progress_callback(percent, f"암호화 중... {percent}%")

        # 3. 최종 처리 및 Tag 기록
        outfile.write(encryptor.finalize())
        tag = encryptor.tag
        
        # Tag 길이 (4바이트), Tag (16바이트) 기록
        outfile.write(struct.pack('<I', len(tag))) 
        outfile.write(tag)
        
    # 암호화 성공 시 원본 파일 삭제
    os.remove(filename) 
    progress_callback(100, "암호화 완료!")
    return encrypted_filename 

def decrypt_file_auto_delete_aes_gcm(encrypted_filename, key, progress_callback): 
    """
    AES-256 GCM 복호화.
      성공 시에만 암호화 파일 삭제. 오류 발생 시 모든 파일 보존. 
    """
    # 원본 파일 이름 복원 (확장자 문자열 기반 제거)
    if encrypted_filename.lower().endswith(AES_EXT):
        original_filename = encrypted_filename[:-len(AES_EXT)] 
    else:
        original_filename = encrypted_filename 
        
    progress_callback(0, f"복호화 시작: {os.path.basename(encrypted_filename)}")
    
    try:
        with open(encrypted_filename, "rb") as infile, open(original_filename, "wb") as outfile:
            # 1. Nonce 읽기
            nonce_len = struct.unpack('<I', infile.read(4))[0]
            if nonce_len != 12: raise ValueError("Invalid Nonce Length")
            nonce = infile.read(nonce_len)
            
            # 2. 파일 크기 계산 및 Tag 읽기 (파일 끝에서부터)
            infile.seek(0, os.SEEK_END)
            total_size = infile.tell()
            
            infile.seek(total_size - 4 - 16)
            
            tag_len = struct.unpack('<I', infile.read(4))[0]
            if tag_len != 16: raise ValueError("Invalid Tag Length")
            tag = infile.read(tag_len)
            
            # 3. 데이터 시작점으로 돌아가기
            data_start_pos = 4 + nonce_len
            infile.seek(data_start_pos)

            # 4. 복호화 객체 생성 및 데이터 크기 계산
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            encrypted_data_size = total_size - data_start_pos - 4 - tag_len
            
            # 5. 청크 단위 복호화 및 쓰기
            bytes_read = 0
            while bytes_read < encrypted_data_size:
                chunk_to_read = min(CHUNK_SIZE, encrypted_data_size - bytes_read)
                chunk = infile.read(chunk_to_read)
                if not chunk: break
                
                outfile.write(decryptor.update(chunk))
                
                bytes_read += len(chunk)
                percent = min(100, int((bytes_read / encrypted_data_size) * 100)) if encrypted_data_size > 0 else 100
                progress_callback(percent, f"복호화 중... {percent}%")

            # 6. 최종 복호화 (Tag 인증)
            outfile.write(decryptor.finalize())
            
        # 복호화 및 인증이 성공했을 때만 암호화 파일을 삭제합니다. 
        os.remove(encrypted_filename) 

    except InvalidTag as e:
        # 인증 오류 발생 시: 불완전한 원본 파일만 삭제하고 암호화 파일은 유지
        if os.path.exists(original_filename): os.remove(original_filename) 
        progress_callback(0, "복호화 실패 (인증 오류)")
        raise e
    except Exception as e:
        # 기타 오류 발생 시: 불완전한 원본 파일만 삭제하고 암호화 파일은 유지
        if os.path.exists(original_filename): os.remove(original_filename) 
        progress_callback(0, "복호화 실패 (오류 발생)")
        raise e
        
    progress_callback(100, "복호화 완료!")
    return original_filename


# --- C. RSA (비대칭키) 함수 ---

def generate_rsa_key_pair(): 
    """RSA 키 쌍 (공개키/개인키) 생성 및 저장"""
    os.makedirs(FIXED_KEY_DIR, exist_ok=True) 
    # 개인키 생성 (2048비트)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open(PRIVATE_KEY_PATH, 'wb') as f: f.write(pem)
    # 공개키 저장
    public_key = private_key.public_key()
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(PUBLIC_KEY_PATH, 'wb') as f: f.write(pem)
    return PUBLIC_KEY_FILE, PRIVATE_KEY_FILE

def load_public_key(): 
    """저장된 RSA 공개키 로드"""
    with open(PUBLIC_KEY_PATH, "rb") as key_file: return serialization.load_pem_public_key(key_file.read())

def load_private_key(): 
    """저장된 RSA 개인키 로드"""
    with open(PRIVATE_KEY_PATH, "rb") as key_file: return serialization.load_pem_private_key(key_file.read(), password=None)

# AES-GCM 기반 하이브리드 암호화
def hybrid_encrypt_file_auto_delete(filename, public_key, progress_callback): 
    """RSA-AES 하이브리드 암호화 및 원본 삭제"""
    aes_key = os.urandom(32) 
    nonce = os.urandom(12) 
    
    # 1. AES 키를 RSA 공개키로 암호화 (OAEP 패딩 사용)
    encrypted_aes_key = public_key.encrypt(
        aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    # 2. AES-GCM 암호화 설정
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    output_filename = filename + HYB_EXT
    
    file_size = os.path.getsize(filename)
    bytes_processed = 0
    
    progress_callback(0, f"하이브리드 암호화 시작: {os.path.basename(filename)}")
    
    with open(filename, "rb") as infile, open(output_filename, "wb") as outfile:
        # 3. 헤더 기록 (암호화된 AES 키)
        outfile.write(struct.pack('<I', len(encrypted_aes_key))) 
        outfile.write(encrypted_aes_key)
        
        # 4. 헤더 기록 (Nonce)
        outfile.write(struct.pack('<I', len(nonce))) 
        outfile.write(nonce)
        
        # 5. 데이터 암호화 (스트리밍)
        while True:
            chunk = infile.read(CHUNK_SIZE)
            if not chunk: break
            
            outfile.write(encryptor.update(chunk))
            
            bytes_processed += len(chunk)
            percent = min(100, int((bytes_processed / file_size) * 100)) if file_size > 0 else 100
            progress_callback(percent, f"하이브리드 암호화 중... {percent}%")

        # 6. 최종 암호화 및 Tag 생성 및 기록
        outfile.write(encryptor.finalize())
        tag = encryptor.tag
        
        outfile.write(struct.pack('<I', len(tag))) 
        outfile.write(tag)
        
    os.remove(filename) # 암호화 성공 시 원본 삭제
    progress_callback(100, "하이브리드 암호화 완료!")
    return output_filename

# AES-GCM 기반 하이브리드 복호화
def hybrid_decrypt_file_auto_delete(encrypted_filename, private_key, progress_callback): 
    """
    RSA-AES 하이브리드 복호화.
    성공 시에만 암호화 파일 삭제. 오류 발생 시 모든 파일 보존. 
    """
    # 원본 파일 이름 복원 (확장자 문자열 기반 제거)
    if encrypted_filename.lower().endswith(HYB_EXT):
        original_filename = encrypted_filename[:-len(HYB_EXT)] 
    else:
        original_filename = encrypted_filename

    progress_callback(0, f"하이브리드 복호화 시작: {os.path.basename(encrypted_filename)}")

    try:
        with open(encrypted_filename, "rb") as infile, open(original_filename, "wb") as outfile:
            # 1. 암호화된 AES 키 길이 읽기
            encrypted_key_len = struct.unpack('<I', infile.read(4))[0]
            encrypted_aes_key = infile.read(encrypted_key_len)
            
            # 2. 개인키로 AES 키 복호화
            aes_key = private_key.decrypt(
                encrypted_aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            
            # 3. Nonce 읽기
            nonce_len = struct.unpack('<I', infile.read(4))[0]
            if nonce_len != 12: raise ValueError("Invalid Nonce Length")
            nonce = infile.read(nonce_len)
            
            # 4. Tag 읽기 및 데이터 크기 계산 
            header_size = 4 + encrypted_key_len + 4 + nonce_len
            infile.seek(0, os.SEEK_END)
            total_size = infile.tell()
            
            infile.seek(total_size - 4 - 16)
            tag_len = struct.unpack('<I', infile.read(4))[0]
            if tag_len != 16: raise ValueError("Invalid Tag Length")
            tag = infile.read(tag_len)
            
            # 5. 데이터 시작점으로 돌아가기
            infile.seek(header_size)

            # 6. 복호화 객체 생성 및 암호화된 데이터 크기 계산
            cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            encrypted_data_size = total_size - header_size - 4 - tag_len
            
            # 7. 청크 단위 복호화 및 쓰기
            bytes_read = 0
            while bytes_read < encrypted_data_size:
                chunk_to_read = min(CHUNK_SIZE, encrypted_data_size - bytes_read)
                chunk = infile.read(chunk_to_read)
                if not chunk: break
                
                outfile.write(decryptor.update(chunk))
                
                bytes_read += len(chunk)
                percent = min(100, int((bytes_read / encrypted_data_size) * 100)) if encrypted_data_size > 0 else 100
                progress_callback(percent, f"하이브리드 복호화 중... {percent}%")

            # 8. 최종 복호화 (Tag 인증)
            outfile.write(decryptor.finalize())
            
        # 복호화 및 인증이 성공했을 때만 암호화 파일을 삭제합니다. 
        os.remove(encrypted_filename)

    except InvalidTag as e:
        # 인증 오류 발생 시: 불완전한 원본 파일만 삭제하고 암호화 파일은 유지
        if os.path.exists(original_filename): os.remove(original_filename)
        progress_callback(0, "복호화 실패 (인증 오류)")
        raise e
    except Exception as e:
        # 기타 오류 발생 시: 불완전한 원본 파일만 삭제하고 암호화 파일은 유지
        if os.path.exists(original_filename): os.remove(original_filename)
        progress_callback(0, "복호화 실패 (오류 발생)")
        raise e
        
    progress_callback(100, "복호화 완료!")
    return original_filename


# ==============================================================================
# II. GUI 클래스 
# ==============================================================================

class SecurityToolGUI:
    def __init__(self, master):
        self.master = master
        master.title("🛡️ 교육용 파이썬 보안 도구(V2.0)")
        
        # --- 1. 전역 스타일 설정 ---
        style = ttk.Style(master)
        
        DEFAULT_FONT = ('Malgun Gothic', 10)
        
        style.configure('.', font=DEFAULT_FONT)
        style.configure('TNotebook.Tab', font=('Malgun Gothic', 10, 'bold'))
        style.configure('TLabel', foreground='#333333') 
        
        # 버튼 스타일
        style.configure('Encrypt.TButton', background='#B0BEC5', foreground='black', font=('Malgun Gothic', 10, 'bold'), padding=8)
        style.map('Encrypt.TButton', background=[('active', '#DEDEDE')]) 
        style.configure('Decrypt.TButton', background='#90A4AE', foreground='black', font=('Malgun Gothic', 10, 'bold'), padding=8)
        style.map('Decrypt.TButton', background=[('active', '#BEC5CB')]) 

        # 키 생성 버튼 스타일
        style.configure('Key.TButton', foreground='#1E88E5', padding=5)
        
        # 탭 노트북 생성
        self.notebook = ttk.Notebook(master)
        
        self.create_port_scanner_tab()
        self.create_aes_tab() 
        self.create_rsa_tab()
        self.create_developer_tab() 
        
        self.notebook.pack(expand=1, fill="both", padx=15, pady=15)
        
    # 백그라운드 스레드에서 GUI 업데이트를 안전하게 처리
    def update_progress(self, progress_var, label_var, percent, status_text):
        """진행률 및 상태 텍스트를 안전하게 업데이트"""
        progress_var.set(percent)
        label_var.set(status_text)
        self.master.update_idletasks() # GUI 강제 업데이트

    # --- 1. 포트 스캐너 탭 ---
    def create_port_scanner_tab(self):
        port_frame = ttk.Frame(self.notebook, padding="15") 
        self.notebook.add(port_frame, text="🌐 포트 스캐너")
        
        port_frame.columnconfigure(1, weight=1) 
        
        ttk.Label(port_frame, text="대상 IP 주소:").grid(row=0, column=0, pady=7, padx=(0, 10), sticky='w')
        self.ip_entry = ttk.Entry(port_frame, width=35); self.ip_entry.grid(row=0, column=1, pady=7, padx=5, sticky='ew'); self.ip_entry.insert(0, "127.0.0.1")
        
        ttk.Label(port_frame, text="포트 범위 (시작-끝):").grid(row=1, column=0, pady=7, padx=(0, 10), sticky='w')
        port_range_frame = ttk.Frame(port_frame) 
        port_range_frame.grid(row=1, column=1, sticky='w')
        self.port_start_entry = ttk.Entry(port_range_frame, width=10); self.port_start_entry.pack(side='left', padx=(5, 5)); self.port_start_entry.insert(0, "1")
        ttk.Label(port_range_frame, text="-").pack(side='left')
        self.port_end_entry = ttk.Entry(port_range_frame, width=10); self.port_end_entry.pack(side='left', padx=(5, 5)); self.port_end_entry.insert(0, "1024")
        
        ttk.Button(port_frame, text="🚀 스캔 시작", command=self.start_scan, style='Encrypt.TButton').grid(row=2, column=0, columnspan=2, pady=(15, 10), sticky='ew', padx=5)
        
        ttk.Label(port_frame, text="🔍 스캔 결과 (최대 50 스레드):").grid(row=3, column=0, columnspan=2, pady=(10, 5), sticky='w')
        self.port_result_text = tk.Text(port_frame, height=12, width=50, wrap='word', relief='groove'); self.port_result_text.grid(row=4, column=0, columnspan=2, sticky='nsew', padx=5)
        scroll = ttk.Scrollbar(port_frame, command=self.port_result_text.yview); scroll.grid(row=4, column=2, sticky='ns'); self.port_result_text.config(yscrollcommand=scroll.set)
        
        port_frame.grid_columnconfigure(1, weight=1)
        port_frame.grid_rowconfigure(4, weight=1)

    def update_port_result(self, message):
        """포트 스캔 결과를 텍스트 위젯에 추가"""
        self.port_result_text.insert(tk.END, message); self.port_result_text.see(tk.END)

    def start_scan(self):
        """스캔 시작 및 유효성 검사"""
        self.port_result_text.delete(1.0, tk.END) 
        try:
            ip = self.ip_entry.get(); start_port = int(self.port_start_entry.get()); end_port = int(self.port_end_entry.get())
            if not 1 <= start_port <= 65535 or not 1 <= end_port <= 65535 or start_port > end_port:
                messagebox.showerror("입력 오류", "유효한 포트 범위(1-65535)를 입력하세요."); return
            # 스레드를 사용하여 GUI가 멈추지 않도록 함
            threading.Thread(target=run_port_scanner, args=(ip, start_port, end_port, self.update_port_result)).start()
        except ValueError:
            messagebox.showerror("입력 오류", "IP 주소와 포트 번호를 확인하세요.")
        except Exception as e:
            messagebox.showerror("오류 발생", f"스캔 초기화 오류: {e}")
            
    # --- 2. AES-256 GCM (대칭키) 탭 ---
    def create_aes_tab(self):
        aes_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(aes_frame, text="🔒 AES-256 GCM")
        
        aes_frame.columnconfigure(1, weight=1) 
        
        ttk.Label(aes_frame, text="대상 파일 경로:").grid(row=0, column=0, pady=7, padx=(0, 10), sticky='w')
        self.aes_file_path = ttk.Entry(aes_frame, width=35); self.aes_file_path.grid(row=0, column=1, pady=7, padx=5, sticky='ew')
        ttk.Button(aes_frame, text="📂 선택", command=lambda: self.browse_file(self.aes_file_path)).grid(row=0, column=2, padx=5)

        ttk.Label(aes_frame, text="키 관리:").grid(row=1, column=0, pady=7, sticky='w')
        key_info_frame = ttk.Frame(aes_frame)
        key_info_frame.grid(row=1, column=1, columnspan=2, pady=7, sticky='ew')
        ttk.Label(key_info_frame, text=f"키 파일: {AES_KEY_FILE}").pack(side='left', padx=(5, 10))
        ttk.Button(key_info_frame, text="🔑 키 생성", command=self.generate_aes_key_gui, style='Key.TButton').pack(side='right')

        ttk.Separator(aes_frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky='ew', pady=10)
        
        # 암호화/복호화 버튼
        ttk.Button(aes_frame, text="🔒 파일 암호화 (원본 삭제)", style='Encrypt.TButton', command=self.execute_aes_encrypt_thread).grid(row=3, column=0, pady=(15, 5), columnspan=3, sticky='ew', padx=5)
        # 🌟 성공 시 삭제 로직 재적용
        ttk.Button(aes_frame, text="✅ 파일 복호화 (암호파일 삭제)", style='Decrypt.TButton', command=self.execute_aes_decrypt_thread).grid(row=4, column=0, pady=5, columnspan=3, sticky='ew', padx=5)
        
        ttk.Separator(aes_frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky='ew', pady=10)
        
        # --- 진행률 표시 위젯 ---
        self.aes_progress_var = tk.DoubleVar()
        self.aes_status_var = tk.StringVar(value="📢 대기 중...")
        
        ttk.Label(aes_frame, textvariable=self.aes_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=6, column=0, columnspan=3, pady=(5, 2), sticky='w')
        self.aes_progress_bar = ttk.Progressbar(aes_frame, orient="horizontal", length=350, mode="determinate", variable=self.aes_progress_var)
        self.aes_progress_bar.grid(row=7, column=0, columnspan=3, pady=5, sticky='ew', padx=5)


    def generate_aes_key_gui(self):
        """AES 키 생성 GUI 래퍼"""
        try:
            os.makedirs(FIXED_KEY_DIR, exist_ok=True) 
            key = generate_aes_key()
            with open(AES_KEY_PATH, "wb") as f: f.write(key)
            messagebox.showinfo("성공", f"✅ 새 AES-256 키가 '{AES_KEY_FILE}'에 저장되었습니다.\n(경로: {FIXED_KEY_DIR})")
        except Exception as e: messagebox.showerror("오류", f"키 생성 실패: {e}")

    def execute_aes_encrypt_thread(self):
        """AES 암호화 스레드 시작"""
        filename = self.aes_file_path.get()
        key = load_aes_key()
        if not filename: messagebox.showerror("오류", "대상 파일을 선택해주세요."); return
        if not key: messagebox.showerror("오류", f"키 파일('{AES_KEY_FILE}')을 찾을 수 없습니다. 키를 먼저 생성하세요."); return
        
        progress_callback = lambda p, s: self.update_progress(self.aes_progress_var, self.aes_status_var, p, s)
        threading.Thread(target=self._run_aes_encrypt, args=(filename, key, progress_callback)).start()

    def _run_aes_encrypt(self, filename, key, progress_callback):
        """실제 AES 암호화 로직"""
        try:
            output_file = encrypt_file_auto_delete_aes_gcm(filename, key, progress_callback)
            self.master.after(0, lambda: self.show_success_message(self.aes_file_path, "암호화", output_file))
        except FileNotFoundError: self.master.after(0, lambda: messagebox.showerror("오류", "대상 파일을 찾을 수 없습니다."))
        except Exception as e: self.master.after(0, lambda err=e: messagebox.showerror("암호화 실패", f"오류: {err}"))
        finally:
            self.master.after(0, lambda: progress_callback(0, "📢 대기 중..."))


    def execute_aes_decrypt_thread(self):
        """AES 복호화 스레드 시작"""
        filename = self.aes_file_path.get(); key = load_aes_key()
        if not filename: messagebox.showerror("오류", "대상 파일을 선택해주세요."); return
        if not key: messagebox.showerror("오류", f"키 파일('{AES_KEY_FILE}')을 찾을 수 없습니다."); return
        
        if not filename.lower().endswith(AES_EXT):
            if not messagebox.askyesno("경고", f"복호화할 파일이 '{AES_EXT}' 확장자가 아닙니다.\n계속 진행하시겠습니까?"): return
            
        progress_callback = lambda p, s: self.update_progress(self.aes_progress_var, self.aes_status_var, p, s)
        threading.Thread(target=self._run_aes_decrypt, args=(filename, key, progress_callback)).start()

    def _run_aes_decrypt(self, filename, key, progress_callback):
        """실제 AES 복호화 로직"""
        try:
            output_file = decrypt_file_auto_delete_aes_gcm(filename, key, progress_callback)
            self.master.after(0, lambda: self.show_success_message(self.aes_file_path, "복호화", output_file))
        
        except InvalidTag:
            self.master.after(0, lambda: messagebox.showerror("복호화 실패", "키가 올바르지 않거나 파일이 손상되었습니다. (AES-GCM 인증 실패)"))
            
        except Exception as e:
            self.master.after(0, lambda err=e: messagebox.showerror("복호화 실패", f"예기치 않은 오류 발생: {err}"))
            
        finally:
            self.master.after(0, lambda: progress_callback(0, "📢 대기 중..."))


    # --- 3. RSA (비대칭키) 탭 ---
    def create_rsa_tab(self):
        rsa_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(rsa_frame, text="🔑 RSA 하이브리드")
        
        rsa_frame.columnconfigure(1, weight=1) 
        
        ttk.Label(rsa_frame, text="대상 파일 경로:").grid(row=0, column=0, pady=7, padx=(0, 10), sticky='w')
        self.rsa_file_path = ttk.Entry(rsa_frame, width=35); self.rsa_file_path.grid(row=0, column=1, pady=7, padx=5, sticky='ew')
        ttk.Button(rsa_frame, text="📂 선택", command=lambda: self.browse_file(self.rsa_file_path)).grid(row=0, column=2, padx=5)

        ttk.Label(rsa_frame, text="키 관리:").grid(row=1, column=0, pady=7, sticky='w')
        key_info_frame = ttk.Frame(rsa_frame)
        key_info_frame.grid(row=1, column=1, columnspan=2, pady=7, sticky='ew')
        ttk.Label(key_info_frame, text=f"키 쌍: {PUBLIC_KEY_FILE} / {PRIVATE_KEY_FILE}").pack(side='left', padx=(5, 10))
        ttk.Button(key_info_frame, text="🔑 키 쌍 생성", command=self.generate_rsa_key_pair_gui, style='Key.TButton').pack(side='right')

        ttk.Separator(rsa_frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky='ew', pady=10)

        # 암호화/복호화 버튼
        ttk.Button(rsa_frame, text="🔒 파일 암호화 (원본 삭제)", style='Encrypt.TButton', command=self.execute_rsa_encrypt_thread).grid(row=3, column=0, pady=(15, 5), columnspan=3, sticky='ew', padx=5)
        # 🌟 성공 시 삭제 로직 재적용
        ttk.Button(rsa_frame, text="✅ 파일 복호화 (암호파일 삭제)", style='Decrypt.TButton', command=self.execute_rsa_decrypt_thread).grid(row=4, column=0, pady=5, columnspan=3, sticky='ew', padx=5)
        
        ttk.Separator(rsa_frame, orient='horizontal').grid(row=5, column=0, columnspan=3, sticky='ew', pady=10)
        
        # --- 진행률 표시 위젯 ---
        self.rsa_progress_var = tk.DoubleVar()
        self.rsa_status_var = tk.StringVar(value="📢 대기 중...")
        
        ttk.Label(rsa_frame, textvariable=self.rsa_status_var, font=('Malgun Gothic', 10, 'italic')).grid(row=6, column=0, columnspan=3, pady=(5, 2), sticky='w')
        self.rsa_progress_bar = ttk.Progressbar(rsa_frame, orient="horizontal", length=350, mode="determinate", variable=self.rsa_progress_var)
        self.rsa_progress_bar.grid(row=7, column=0, columnspan=3, pady=5, sticky='ew', padx=5)


    def generate_rsa_key_pair_gui(self):
        """RSA 키 쌍 생성 GUI 래퍼"""
        try:
            pub, priv = generate_rsa_key_pair()
            messagebox.showinfo("성공", f"✅ RSA 키 쌍이 성공적으로 생성되었습니다.\n(경로: {FIXED_KEY_DIR})")
        except Exception as e: messagebox.showerror("오류", f"키 쌍 생성 실패: {e}")

    def execute_rsa_encrypt_thread(self):
        """RSA 하이브리드 암호화 스레드 시작"""
        filename = self.rsa_file_path.get()
        if not filename: messagebox.showerror("오류", "대상 파일을 선택해주세요."); return
        
        try:
            pub_key = load_public_key()
        except FileNotFoundError:
            messagebox.showerror("오류", "공개키(public.pem)를 찾을 수 없습니다. 키 쌍을 먼저 생성하세요."); return
        
        progress_callback = lambda p, s: self.update_progress(self.rsa_progress_var, self.rsa_status_var, p, s)
        threading.Thread(target=self._run_rsa_encrypt, args=(filename, pub_key, progress_callback)).start()

    def _run_rsa_encrypt(self, filename, pub_key, progress_callback):
        """실제 RSA 하이브리드 암호화 로직"""
        try:
            output_file = hybrid_encrypt_file_auto_delete(filename, pub_key, progress_callback)
            self.master.after(0, lambda: self.show_success_message(self.rsa_file_path, "하이브리드 암호화", output_file))
        except FileNotFoundError: self.master.after(0, lambda: messagebox.showerror("오류", "대상 파일을 찾을 수 없습니다."))
        except Exception as e: self.master.after(0, lambda err=e: messagebox.showerror("암호화 실패", f"오류: {err}"))
        finally:
            self.master.after(0, lambda: progress_callback(0, "📢 대기 중..."))


    def execute_rsa_decrypt_thread(self):
        """RSA 하이브리드 복호화 스레드 시작"""
        filename = self.rsa_file_path.get()
        if not filename: messagebox.showerror("오류", "대상 파일을 선택해주세요."); return
        
        if not filename.lower().endswith(HYB_EXT): 
            if not messagebox.askyesno("경고", f"복호화할 파일이 '{HYB_EXT}' 확장자가 아닙니다.\n계속 진행하시겠습니까?"): return
            
        try:
            priv_key = load_private_key()
        except FileNotFoundError:
            messagebox.showerror("오류", "개인키(private.pem)를 찾을 수 없습니다. 키 쌍을 먼저 생성하세요."); return
        
        progress_callback = lambda p, s: self.update_progress(self.rsa_progress_var, self.rsa_status_var, p, s)
        threading.Thread(target=self._run_rsa_decrypt, args=(filename, priv_key, progress_callback)).start()

    def _run_rsa_decrypt(self, filename, priv_key, progress_callback):
        """실제 RSA 하이브리드 복호화 로직"""
        try:
            output_file = hybrid_decrypt_file_auto_delete(filename, priv_key, progress_callback)
            self.master.after(0, lambda: self.show_success_message(self.rsa_file_path, "하이브리드 복호화", output_file))
        
        except InvalidTag: 
            self.master.after(0, lambda: messagebox.showerror("복호화 실패", "개인키가 올바르지 않거나 암호화 파일이 손상되었습니다. (AES-GCM 인증 실패)"))
            
        except Exception as e: 
            self.master.after(0, lambda err=e: messagebox.showerror("복호화 실패", f"예기치 않은 오류 발생: {err}"))
            
        finally:
            self.master.after(0, lambda: progress_callback(0, "📢 대기 중..."))


    # --- 4. 제작자 정보 탭 ---
    def create_developer_tab(self):
        dev_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(dev_frame, text="💡 제작자 정보")
        
        # 폰트 스타일 적용
        TITLE_FONT = ('Malgun Gothic', 13, 'bold')
        HEADER_FONT = ('Malgun Gothic', 11, 'bold')
        TEXT_FONT = ('Malgun Gothic', 10)
        
        ttk.Label(dev_frame, text="--- 🛡️ 교육용 파이썬 보안 도구 (V2.0) ---", font=TITLE_FONT, foreground='#3F51B5').pack(pady=(10, 5)) 
        ttk.Label(dev_frame, text="프로젝트: 통합 파일 암호화 및 네트워크 보안 학습용 도구", font=TEXT_FONT).pack(pady=2, anchor='w')
        ttk.Label(dev_frame, text="제작자: Dangel", font=HEADER_FONT).pack(pady=5, anchor='w')
        
        ttk.Separator(dev_frame, orient='horizontal').pack(fill='x', pady=10)

        ttk.Label(dev_frame, text="📚 개발 배경 및 학습 과정", font=HEADER_FONT).pack(pady=5, anchor='w')
        
        text_container = ttk.Frame(dev_frame)
        text_container.pack(fill='both', expand=True, pady=5) 
        info_text = tk.Text(text_container, height=10, width=50, wrap='word', bd=1, relief='flat', font=TEXT_FONT, background='#f5f5f5') 
        scroll = ttk.Scrollbar(text_container, command=info_text.yview)
        info_text.config(yscrollcommand=scroll.set)
        
        scroll.pack(side='right', fill='y')
        info_text.pack(side='left', fill='both', expand=True) 

        info_text.insert(tk.END, "이 도구는 보안도구 공부를 하기위해 만든것입니다. 학습에 도움이 되기를 바랍니다.\n\n")
        info_text.insert(tk.END, "📅 최근 업데이트: 2025_11_10 RSA와 Fernet(AES)의 파일 이름이 확장자가 없어지거나 내용이 없어지면서 복호화되는 버그를 수정했습니다.\n")
        info_text.insert(tk.END, "💡 주요 업데이트: 대용량 파일 멈춤 현상 방지를 위한 청크 스트리밍 도입 및 진행률 표시 기능 추가 .\n\n")
        info_text.insert(tk.END, "⚠️ 책임 고지: 이 도구는 교육 및 학습 목적으로만 사용해야 합니다. 타인의 컴퓨터에 악용하여 발생하는 모든 피해는 사용자 본인의 책임입니다.\n\n")
        info_text.insert(tk.END, "주요 학습 내용:\n")
        info_text.insert(tk.END, "    - 비동기 멀티스레딩을 활용한 포트 스캐너 구현\n")
        info_text.insert(tk.END, "    - AES-256 GCM 대칭키 스트리밍 암호화\n")
        info_text.insert(tk.END, "    - RSA(비대칭키) 하이브리드 암호화 로직 및 키 관리\n")
        
        info_text.config(state='disabled') 
        
        ttk.Label(dev_frame, text="📢 제작자도 현재 배우는 중입니다. 오류 보고 및 피드백은 언제나 환영합니다.", foreground='#007BFF', font=('Malgun Gothic', 10, 'italic')).pack(pady=10)

    # --- 공통 유틸리티 ---
    def browse_file(self, entry_widget):
        """파일 선택 대화 상자를 열고 경로를 엔트리 위젯에 채움"""
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)
            
    def show_success_message(self, entry_widget, operation_type, output_file):
        """
        성공 메시지를 띄우고 입력 필드를 최종 결과 파일 경로로 업데이트합니다.
        """
        
        # 1. 기존 내용 삭제
        entry_widget.delete(0, tk.END) 
        
        # 2. 최종 결과 파일 경로를 필드에 다시 채웁니다.
        entry_widget.insert(0, output_file) 
        
        # 3. 메시지 박스 표시
        if operation_type.startswith("암호화"):
            icon = "🔒"
            msg = f"{icon} 파일이 성공적으로 {operation_type}되었으며, 원본 파일이 삭제되었습니다.\n출력: {os.path.basename(output_file)}"
        else:
            icon = "🔓"
            # 🌟 수정된 부분: 복호화 성공 시 암호화 파일이 삭제됨을 명시
            msg = f"{icon} 파일이 성공적으로 {operation_type}되었으며, 암호화 파일이 삭제되었습니다.\n출력: {os.path.basename(output_file)}"
            
        messagebox.showinfo("성공", msg)


# ==============================================================================
# III. 메인 실행
# ==============================================================================

if __name__ == '__main__':
    # 키 저장 디렉토리 생성 시도
    try:
        if not os.path.exists(FIXED_KEY_DIR):
            os.makedirs(FIXED_KEY_DIR, exist_ok=True)
    except Exception as e:
        # 키 저장 경로 문제 발생 시 경고
        messagebox.showwarning("경로 오류", f"키 저장 경로 '{FIXED_KEY_DIR}' 생성에 실패했습니다. 권한을 확인하세요. : {e}")
        
    root = tk.Tk()
    app = SecurityToolGUI(root)
    root.mainloop()