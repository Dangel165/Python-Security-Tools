import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import os
import threading
from concurrent.futures import ThreadPoolExecutor

# Cryptography 라이브러리 임포트
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# ==============================================================================
# I. 핵심 함수 및 고정 경로 설정 
# ==============================================================================

# --- 키 파일 저장 경로를 사용자가 지정한 폴더로 고정 ---
FIXED_KEY_DIR = r""
# 키 파일의 전체 절대 경로 설정
FERNET_KEY_PATH = os.path.join(FIXED_KEY_DIR, "fernet.key")
PRIVATE_KEY_PATH = os.path.join(FIXED_KEY_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(FIXED_KEY_DIR, "public.pem")

# GUI 표시용 파일 이름
FERNET_KEY_FILE = "fernet.key"
PRIVATE_KEY_FILE = "private.pem"
PUBLIC_KEY_FILE = "public.pem"


# --- A. 포트 스캐너 함수 ---
def port_scan_worker(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            sock.close(); return port
        sock.close()
    except Exception: pass
    return None

def run_port_scanner(target_ip, start_port, end_port, callback):
    open_ports = []
    callback(f"** 대상: {target_ip} 포트 스캔 시작 ({start_port}-{end_port}) **\n")
    try:
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(port_scan_worker, target_ip, port) for port in range(start_port, end_port + 1)]
            for future in futures:
                port = future.result()
                if port is not None:
                    open_ports.append(port); callback(f"  [+] 포트 {port} 열림\n")
        callback(f"\n** 스캔 완료. 총 {len(open_ports)}개 포트 열림: {sorted(open_ports)} **\n")
    except Exception as e:
        callback(f"❌ 스캔 오류 발생: {e}\n")


# --- B. Fernet (대칭키) 함수 (생략) ---
def load_fernet_key(): 
    try: return open(FERNET_KEY_PATH, "rb").read()
    except FileNotFoundError: return None

def encrypt_file_auto_delete(filename, key): 
    base, ext = os.path.splitext(filename) 
    f = Fernet(key)
    with open(filename, "rb") as file: encrypted_data = f.encrypt(file.read())
    
    encrypted_filename = base + ".fnet" 
    
    with open(encrypted_filename, "wb") as file: file.write(encrypted_data)
        
    os.remove(filename) 
    return encrypted_filename 

def decrypt_file_auto_delete(encrypted_filename, key): 
    if encrypted_filename.lower().endswith(".fnet"):
        original_filename = encrypted_filename[:-5] 
    else:
        original_filename = encrypted_filename
        
    f = Fernet(key)
    with open(encrypted_filename, "rb") as file: decrypted_data = f.decrypt(file.read())
    
    with open(original_filename, "wb") as file: file.write(decrypted_data)
    
    os.remove(encrypted_filename) 
    return original_filename

# --- C. RSA (비대칭키) 함수  ---
def generate_rsa_key_pair(): 
    os.makedirs(FIXED_KEY_DIR, exist_ok=True) 
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open(PRIVATE_KEY_PATH, 'wb') as f: 
        f.write(pem)
    
    public_key = private_key.public_key()
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open(PUBLIC_KEY_PATH, 'wb') as f: 
        f.write(pem)
    
    return PUBLIC_KEY_FILE, PRIVATE_KEY_FILE

def load_public_key(): 
    with open(PUBLIC_KEY_PATH, "rb") as key_file: 
        return serialization.load_pem_public_key(key_file.read())

def load_private_key(): 
    with open(PRIVATE_KEY_PATH, "rb") as key_file: 
        return serialization.load_pem_private_key(key_file.read(), password=None)

def hybrid_encrypt_file_auto_delete(filename, public_key): 
    base, ext = os.path.splitext(filename) 
    
    fernet_key = Fernet.generate_key()
    f = Fernet(fernet_key)
    encrypted_fernet_key = public_key.encrypt(
        fernet_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    with open(filename, "rb") as file: encrypted_file_data = f.encrypt(file.read())
    
    output_filename = base + ".rsa_enc"
    
    with open(output_filename, "wb") as file:
        file.write(len(encrypted_fernet_key).to_bytes(4, byteorder='big')) 
        file.write(encrypted_fernet_key)
        file.write(encrypted_file_data)
    
    os.remove(filename)
    return output_filename

def hybrid_decrypt_file_auto_delete(encrypted_filename, private_key): 
    if encrypted_filename.lower().endswith(".rsa_enc"):
        original_filename = encrypted_filename[:-8] 
    else:
        original_filename = encrypted_filename

    with open(encrypted_filename, "rb") as file:
        encrypted_key_len = int.from_bytes(file.read(4), byteorder='big')
        encrypted_fernet_key = file.read(encrypted_key_len)
        encrypted_file_data = file.read()
    
    fernet_key = private_key.decrypt(
        encrypted_fernet_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    
    f = Fernet(fernet_key)
    decrypted_data = f.decrypt(encrypted_file_data)
    
    with open(original_filename, "wb") as file: file.write(decrypted_data)
        
    os.remove(encrypted_filename)
    return original_filename


# ==============================================================================
# II. GUI 클래스 
# ==============================================================================

class SecurityToolGUI:
    def __init__(self, master):
        self.master = master
        master.title("🛡️ 교륙용 파이썬 통합 보안 도구 ")
        
        self.notebook = ttk.Notebook(master)
        
        self.create_port_scanner_tab()
        self.create_fernet_tab()
        self.create_rsa_tab()
        self.create_developer_tab() 
        
        self.notebook.pack(expand=1, fill="both", padx=10, pady=10)

    # --- 1. 포트 스캐너 탭 (생략) ---
    def create_port_scanner_tab(self):
        port_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(port_frame, text="🌐 포트 스캐너")
        
        ttk.Label(port_frame, text="대상 IP 주소:").grid(row=0, column=0, pady=5, sticky='w')
        self.ip_entry = ttk.Entry(port_frame, width=30); self.ip_entry.grid(row=0, column=1, pady=5, padx=5, columnspan=2); self.ip_entry.insert(0, "127.0.0.1")
        ttk.Label(port_frame, text="포트 범위 (시작-끝):").grid(row=1, column=0, pady=5, sticky='w')
        self.port_start_entry = ttk.Entry(port_frame, width=10); self.port_start_entry.grid(row=1, column=1, sticky='w', padx=5); self.port_start_entry.insert(0, "1")
        self.port_end_entry = ttk.Entry(port_frame, width=10); self.port_end_entry.grid(row=1, column=2, sticky='w', padx=5); self.port_end_entry.insert(0, "1024")
        
        ttk.Button(port_frame, text="스캔 시작", command=self.start_scan).grid(row=2, column=0, columnspan=3, pady=10)
        
        ttk.Label(port_frame, text="스캔 결과:").grid(row=3, column=0, columnspan=3, pady=5, sticky='w')
        self.port_result_text = tk.Text(port_frame, height=12, width=50); self.port_result_text.grid(row=4, column=0, columnspan=3)
        scroll = ttk.Scrollbar(port_frame, command=self.port_result_text.yview); scroll.grid(row=4, column=3, sticky='ns'); self.port_result_text.config(yscrollcommand=scroll.set)

    def update_port_result(self, message):
        self.port_result_text.insert(tk.END, message); self.port_result_text.see(tk.END)

    def start_scan(self):
        self.port_result_text.delete(1.0, tk.END) 
        try:
            ip = self.ip_entry.get(); start_port = int(self.port_start_entry.get()); end_port = int(self.port_end_entry.get())
            if not 1 <= start_port <= 65535 or not 1 <= end_port <= 65535 or start_port > end_port:
                 messagebox.showerror("입력 오류", "유효한 포트 범위(1-65535)를 입력하세요."); return
            threading.Thread(target=run_port_scanner, args=(ip, start_port, end_port, self.update_port_result)).start()
        except ValueError:
            messagebox.showerror("입력 오류", "IP 주소와 포트 번호를 확인하세요.")
        except Exception as e:
            messagebox.showerror("오류 발생", f"스캔 초기화 오류: {e}")
            
    # --- 2. Fernet (대칭키) 탭 (생략) ---
    def create_fernet_tab(self):
        fernet_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(fernet_frame, text="🔒 Fernet 암호화")
        
        ttk.Label(fernet_frame, text="대상 파일:").grid(row=0, column=0, pady=5, sticky='w')
        self.fernet_file_path = ttk.Entry(fernet_frame, width=30); self.fernet_file_path.grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(fernet_frame, text="찾아보기", command=lambda: self.browse_file(self.fernet_file_path)).grid(row=0, column=2, padx=5)

        ttk.Label(fernet_frame, text="키 파일:").grid(row=1, column=0, pady=5, sticky='w')
        ttk.Label(fernet_frame, text=FERNET_KEY_FILE).grid(row=1, column=1, sticky='w')
        ttk.Button(fernet_frame, text="키 생성", command=self.generate_fernet_key).grid(row=1, column=2, padx=5)

        ttk.Button(fernet_frame, text="파일 암호화 및 원본 삭제", command=self.execute_fernet_encrypt).grid(row=2, column=0, pady=15, columnspan=3)
        ttk.Button(fernet_frame, text="파일 복호화 및 암호파일 삭제", command=self.execute_fernet_decrypt).grid(row=3, column=0, pady=5, columnspan=3)

    def generate_fernet_key(self):
        try:
            os.makedirs(FIXED_KEY_DIR, exist_ok=True) 

            key = Fernet.generate_key()
            with open(FERNET_KEY_PATH, "wb") as f:
                f.write(key)
            
            messagebox.showinfo("성공", f"✅ 새 Fernet 키가 '{FERNET_KEY_FILE}'에 저장되었습니다.\n(경로: {FIXED_KEY_DIR})")
        except Exception as e: messagebox.showerror("오류", f"키 생성 실패: {e}")

    def execute_fernet_encrypt(self):
        filename = self.fernet_file_path.get(); key = load_fernet_key()
        if not key: messagebox.showerror("오류", f"키 파일('{FERNET_KEY_FILE}')을 찾을 수 없습니다. 키를 먼저 생성하세요."); return
        try:
            output_file = encrypt_file_auto_delete(filename, key)
            messagebox.showinfo("성공", f"🔒 파일이 성공적으로 암호화되었으며, 원본 파일이 삭제되었습니다.\n출력: {output_file}")
        except FileNotFoundError: messagebox.showerror("오류", "대상 파일을 찾을 수 없습니다.")
        except Exception as e: messagebox.showerror("암호화 실패", f"오류: {e}")

    def execute_fernet_decrypt(self):
        filename = self.fernet_file_path.get(); key = load_fernet_key()
        if not key: messagebox.showerror("오류", f"키 파일('{FERNET_KEY_FILE}')을 찾을 수 없습니다."); return
        
        if not filename.lower().endswith(".fnet"):
            messagebox.showwarning("경고", "복호화할 파일이 '.fnet' 확장자가 아닙니다. 진행하시겠습니까?")
            
        try:
            output_file = decrypt_file_auto_delete(filename, key)
            messagebox.showinfo("성공", f"🔓 파일이 성공적으로 복호화되었으며, 암호화 파일이 삭제되었습니다.\n출력: {output_file}")
        except Exception:
            messagebox.showerror("복호화 실패", "키가 올바르지 않거나 파일이 손상되었습니다.")

    # --- 3. RSA (비대칭키) 탭 (생략) ---
    def create_rsa_tab(self):
        rsa_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(rsa_frame, text="🔑 RSA 하이브리드")
        
        ttk.Label(rsa_frame, text="대상 파일:").grid(row=0, column=0, pady=5, sticky='w')
        self.rsa_file_path = ttk.Entry(rsa_frame, width=30); self.rsa_file_path.grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(rsa_frame, text="찾아보기", command=lambda: self.browse_file(self.rsa_file_path)).grid(row=0, column=2, padx=5)

        ttk.Label(rsa_frame, text="키 파일:").grid(row=1, column=0, pady=5, sticky='w')
        ttk.Label(rsa_frame, text=f"{PUBLIC_KEY_FILE} / {PRIVATE_KEY_FILE}").grid(row=1, column=1, sticky='w', columnspan=2)
        ttk.Button(rsa_frame, text="키 쌍 생성", command=self.generate_rsa_key_pair_gui).grid(row=2, column=0, pady=5, columnspan=3)

        ttk.Button(rsa_frame, text="파일 암호화 및 원본 삭제", command=self.execute_rsa_encrypt).grid(row=3, column=0, pady=15, columnspan=3)
        ttk.Button(rsa_frame, text="파일 복호화 및 암호파일 삭제", command=self.execute_rsa_decrypt).grid(row=4, column=0, pady=5, columnspan=3)
        
    def generate_rsa_key_pair_gui(self):
        try:
            pub, priv = generate_rsa_key_pair()
            messagebox.showinfo("성공", f"✅ RSA 키 쌍이 성공적으로 생성되었습니다.\n(경로: {FIXED_KEY_DIR})")
        except Exception as e: messagebox.showerror("오류", f"키 쌍 생성 실패: {e}")


    def execute_rsa_encrypt(self):
        filename = self.rsa_file_path.get()
        try:
            pub_key = load_public_key()
            output_file = hybrid_encrypt_file_auto_delete(filename, pub_key)
            messagebox.showinfo("성공", f"🔒 파일이 성공적으로 RSA 암호화되었으며, 원본 파일이 삭제되었습니다.\n출력: {output_file}")
        except FileNotFoundError: messagebox.showerror("오류", "대상 파일 또는 공개키(public.pem)를 찾을 수 없습니다. 키 쌍을 먼저 생성하세요.")
        except Exception as e: messagebox.showerror("암호화 실패", f"오류: {e}")

    def execute_rsa_decrypt(self):
        filename = self.rsa_file_path.get()
        if not filename.lower().endswith(".rsa_enc"): messagebox.showwarning("경고", "복호화할 파일이 '.rsa_enc' 확장자가 아닙니다. 진행하시겠습니까?")
        
        try:
            priv_key = load_private_key()
            output_file = hybrid_decrypt_file_auto_delete(filename, priv_key)
            messagebox.showinfo("성공", f"🔓 파일이 성공적으로 복호화되었으며, 암호화 파일이 삭제되었습니다.\n출력: {output_file}")
        except FileNotFoundError: 
            messagebox.showerror("오류", "대상 파일 또는 개인키(private.pem)를 찾을 수 없습니다. 키 쌍을 먼저 생성하세요.")
        except Exception: 
            messagebox.showerror("복호화 실패", "개인키가 올바르지 않거나 파일이 손상되었습니다.")

    # --- 4. 제작자 정보 탭 (새로 추가됨) ---
    def create_developer_tab(self):
        dev_frame = ttk.Frame(self.notebook, padding="15")
        self.notebook.add(dev_frame, text="💡 제작자 정보")
        
        ttk.Label(dev_frame, text="--- 🛡️ 교육용 파이썬 보안 도구 ---", font=('Helvetica', 14, 'bold')).pack(pady=(10, 5))
        
        ttk.Label(dev_frame, text="프로젝트: 통합 파일 암호화 및 네트워크 보안 학습용 도구", font=('Helvetica', 10)).pack(pady=2, anchor='w')
        ttk.Label(dev_frame, text="제작자:Dangel", font=('Helvetica', 10, 'bold')).pack(pady=5, anchor='w')
        
        ttk.Separator(dev_frame, orient='horizontal').pack(fill='x', pady=10)

        ttk.Label(dev_frame, text="📚 개발 배경 및 학습 과정", font=('Helvetica', 12, 'bold')).pack(pady=5, anchor='w')
        
        info_text = tk.Text(dev_frame, height=8, width=50, wrap='word', bd=1, relief='sunken', font=('Helvetica', 10))
        info_text.insert(tk.END, "이 도구는 제가 보안도구 공부를 하기위해 만든것입니다 근데 나머지 기능은 잘되나 복호화가 안돼는 문제가 있어 암호화기능은 안쓰시는걸 권장합니다\n\n")
        info_text.insert(tk.END, "주요 학습 내용:\n")
        info_text.insert(tk.END, "- 비동기 멀티스레딩을 활용한 포트 스캐너 구현\n")
        info_text.insert(tk.END, "- Fernet(대칭키) 암호화 및 안전한 파일 입출력\n")
        info_text.insert(tk.END, "- RSA(비대칭키) 하이브리드 암호화 로직 및 키 관리\n")
        info_text.config(state='disabled') # 읽기 전용으로 설정
        info_text.pack(pady=5)
        
        ttk.Label(dev_frame, text="📢 제작자도 현재 배우는 중입니다. 오류 보고 및 피드백은 언제나 환영합니다.", foreground='blue').pack(pady=10)


    # --- 공통 유틸리티 ---
    def browse_file(self, entry_widget):
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, file_path)


# ==============================================================================
# III. 메인 실행
# ==============================================================================

if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityToolGUI(root)
    root.mainloop()