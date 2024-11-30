import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox


def calculate_hash(file_path):
    """파일의 MD5 해시 계산"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except Exception as e:
        print(f"Error reading file: {file_path}, {e}")
    return hash_md5.hexdigest()


def find_duplicates(folder_path):
    """폴더 내 중복 파일 확인 및 삭제"""
    if not folder_path:
        return []

    file_hashes = {}
    duplicates = []

    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_hash = calculate_hash(file_path)

            if file_hash in file_hashes:
                duplicates.append(file_path)
            else:
                file_hashes[file_hash] = file_path

    # 중복 파일 삭제
    for file_path in duplicates:
        os.remove(file_path)

    return duplicates


def select_folder():
    """폴더 선택 다이얼로그"""
    folder_path = filedialog.askdirectory()
    folder_var.set(folder_path)


def process_duplicates():
    """중복 확인 및 삭제 실행"""
    folder_path = folder_var.get()
    if not folder_path:
        messagebox.showwarning("경고", "폴더를 선택하세요!")
        return

    duplicates = find_duplicates(folder_path)

    if duplicates:
        messagebox.showinfo("결과", f"중복된 파일 {len(duplicates)}개를 삭제했습니다.")
    else:
        messagebox.showinfo("결과", "중복된 파일이 없습니다.")


# GUI 설계
app = tk.Tk()
app.title("중복 파일 제거기")
app.geometry("400x200")

# 폴더 선택
folder_var = tk.StringVar()
folder_label = tk.Label(app, text="폴더 경로:")
folder_label.pack(pady=5)
folder_entry = tk.Entry(app, textvariable=folder_var, width=50)
folder_entry.pack(pady=5)
folder_button = tk.Button(app, text="폴더 선택", command=select_folder)
folder_button.pack(pady=5)

# 실행 버튼
process_button = tk.Button(app, text="중복 제거 실행", command=process_duplicates)
process_button.pack(pady=20)

# 실행
app.mainloop()
