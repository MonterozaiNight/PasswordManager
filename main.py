import os
import json
import base64
from tkinter import *
from tkinter import ttk
import secrets
import string
import Credentials

rng = secrets.SystemRandom()

letters = [rng.choice(string.ascii_letters) for _ in range(26)]
numbers = [rng.choice(string.digits) for _ in range(10)]
symbols = "!@#$%^&*()-_=+"

def limit_char(str):
    return len(str) <= 22

def generate_passphrase():

    ### マスターパスワードを取得
    master_password = master_password_entry.get()

    ### マスターパスワードの入力チェック
    if not master_password:
        message_label.config(text="マスターパスワードを入力してください。")
        return

    ### パスフレーズ生成
    # 4～10文字のランダムな英字、3～6文字のランダムな数字、3～6文字のランダムな記号を組み合わせてパスフレーズを生成
    passphrase_list = [secrets.choice(letters) for _ in range(rng.randint(4, 10))]
    passphrase_list.extend([secrets.choice(numbers) for _ in range(rng.randint(3, 6))])
    passphrase_list.extend([secrets.choice(symbols) for _ in range(rng.randint(3, 6))])
    rng.shuffle(passphrase_list)

    # ソルトを生成
    salt_bytes = os.urandom(16)

    # マスターパスワードをコマンドラインに入力します。
    user_password = master_password_entry.get()

    ### パスフレーズを暗号化します。
    # Credentialsクラスをインスタンス化
    cred = Credentials.Credentials()
    # 暗号化パスフレーズを取得します。
    encrypted_passphrase = cred.encrypted_passphrase("".join(passphrase_list), user_password, salt_bytes)

    ### ソルトと暗号化パスフレーズをJSON形式で保存
    passphrase_json = {
        "salt": base64.b64encode(salt_bytes).decode("utf-8"),
        "encrypted_data": encrypted_passphrase.decode("utf-8")
    }

    ### JSONファイルに保存
    with open("passphrase.json", "w") as json_file:
        json.dump(passphrase_json, json_file)

    ### メッセージを表示
    message_label.config(text="パスフレーズが正常に保存されました。")

def generate_password():

    ### パスワード原案を作成
    password_list = [secrets.choice(letters) for _ in range(rng.randint(4, 10))]
    password_list.extend([secrets.choice(numbers) for _ in range(rng.randint(3, 6))])
    password_list.extend([secrets.choice(symbols) for _ in range(rng.randint(3, 6))])
    rng.shuffle(password_list)

    ### パスワードをエントリーに表示
    password = "".join(password_list)
    password_entry.delete(0, END)
    password_entry.insert(0, password)

def decrypt_password():
    ### 暗号化パスフレーズ用JSONがあるかどうか確認
    if not os.path.exists("passphrase.json"):
        message_label.config(text="暗号化パスフレーズ用JSONがPasswordManagerフォルダに存在しません。")
        return

    ### 秘密鍵ファイルがあるかどうか確認
    if not os.path.exists("private_key.pem"):
        message_label.config(text="秘密鍵ファイルがPasswordManagerフォルダに存在しません。")
        return

    ### マスターパスワードを取得
    master_password = master_password_entry.get()

    ### 認証情報JSONからログインIDとパスワードを取得
    with open("credentials.json", "r") as f:
        credentials = json.load(f)

    ### 暗号化パスフレーズ用JSONから暗号化パスフレーズとソルトを取得
    with open("passphrase.json", "r") as f:
        passphrase = json.load(f)

    ### Credentialsクラスのインスタンスを作成し、CredentialsクラスにログインIDと暗号化パスワードを割り当てます。
    # インスタンス化
    cred = Credentials.Credentials()
    # ログインID
    cred.username = credentials["login_id"]
    # 暗号化パスワード
    cred.password = credentials["encrypted_password"]

    ### パスフレーズを復号する
    rslt = cred.decrypted_passphrase(
        passphrase["encrypted_data"],
        master_password,
        base64.b64decode(passphrase["salt"].encode("utf-8"))
    )

    if not rslt:
        message_label.config(text="パスフレーズ復号に失敗しました。")
        return

    ### 秘密鍵を読み込む
    with open("private_key.pem", "rb") as private_file:
        cred.private_key = private_file.read()

    ### 暗号化されたパスワードを復号化
    decrypted_password = cred.decrypt_password(rslt, bytes.fromhex(credentials["encrypted_password"]))

    ### 復号化されたパスワードをクリップボードにコピー
    window.clipboard_clear()
    window.clipboard_append(decrypted_password)

    ### メッセージを表示
    message_label.config(text="復号化パスワードをコピーしました。15秒後に消去します。")

    ### 15秒後にクリップボードを消去
    window.after(15000, lambda: window.clipboard_clear())

def register_credentials():

    ### マスターパスワード、ログインID/Eメール、パスワードを取得
    master_password = master_password_entry.get()
    login_id = loginId_entry.get()
    password = password_entry.get()

    ### ログインID/Eメール、パスワードの入力チェック
    if not master_password or not login_id or not password:
        message_label.config(text="マスターパスワードとログインID/Eメールとパスワードを入力してください。")
        return

    ### 暗号化パスフレーズ用JSONから暗号化パスフレーズとソルトを取得
    with open("passphrase.json", "r") as f:
        data = json.load(f)

    ### 秘密鍵と公開鍵の生成
    # Credentialsクラスのインスタンスを作成し、ログインIDとパスワードをCredentialsクラスに設定します。
    cred = Credentials.Credentials()
    cred.username = login_id
    cred.password = password

    ### パスフレーズを復号する
    rslt = cred.decrypted_passphrase(
        data["encrypted_data"],
        master_password,
        base64.b64decode(data["salt"].encode("utf-8"))
    )

    if not rslt:
        message_label.config(text="パスフレーズ復号に失敗しました。")
        return

    # 生成された秘密鍵と公開鍵をファイルに保存します。
    cred.generate_keys(rslt)

    ### パスワードを暗号化してJSON形式で保存
    credentials = {
        "login_id": cred.username,
        "encrypted_password": cred.encrypt_password().hex()  # バイト列を16進数文字列に変換して保存
    }

    ### JSONファイルに保存
    with open("credentials.json", "w") as json_file:
        json.dump(credentials, json_file)

    ### メッセージを表示
    message_label.config(text="認証情報が正常に登録されました。")

### Tkinterウィンドウの生成
# 1, ウィンドウの作成
window = Tk()
window.title("Password Manager")
window.config(padx=80, pady=60)

# 入力制限のためのバリデーション関数を登録
vc = (window.register(limit_char), "%P")

# 2, ラベルの設定
master_password_label = Label(text="パスフレーズ復号化用マスターパスワード", padx=5, pady=5)
master_password_label.grid(row=0, column=0)
separator = ttk.Separator(window, orient="horizontal")
separator.grid(row=1, column=0, columnspan=4, sticky="ew", pady=5)
loginId_label = Label(text="ログインID/Eメール", padx=5, pady=5)
loginId_label.grid(row=2, column=0)
password_label = Label(text="パスワード", padx=5, pady=5)
password_label.grid(row=3, column=0)
message_label = Label(padx=5, pady=5)
message_label.grid(row=5, column=0, columnspan=4)

# 3, エントリーの設定
master_password_entry = Entry(width=35, show="*")
master_password_entry.grid(row=0, column=1, padx=5, pady=5)
master_password_entry.insert(0, "パスフレーズ復号化用マスターパスワードを入力")
master_password_entry.focus()  # ウィンドウ起動時にフォーカスを当てる
loginId_entry = Entry(width=35)
loginId_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
password_entry = Entry(width=35, validate="key", validatecommand=vc)
password_entry.grid(row=3, column=1, padx=5, pady=5)

# 4, ボタンの設定
generate_passphrase_button = Button(text="パスフレーズ生成", command=generate_passphrase)
generate_passphrase_button.grid(row=0, column=3)
generate_password_button = Button(text="パスワード生成", command=generate_password)
generate_password_button.grid(row=2, column=3)
decrypt_password_button = Button(text="復号化パスワードをコピー", command=decrypt_password)
decrypt_password_button.grid(row=3, column=3)
register_credentials_button = Button(text="認証情報登録", width=65, command=register_credentials)
register_credentials_button.grid(row=4, column=0, columnspan=4)

window.mainloop()