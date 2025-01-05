import sys
import sqlite3
import hashlib

import bcrypt
from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QWidget, QMessageBox, QListWidget, QInputDialog)
from PyQt5.QtCore import Qt
import qrcode
from PyQt5.QtGui import QPixmap
from io import BytesIO
import pyotp

class  Database:
    """class responsible for connection with SQLLITE Database, and operations on it"""
    def __init__(self, db_name='key_keeper.db'):
        self.conn = sqlite3.connect(db_name)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        """Creates tables in database if already do not exist"""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                account_name TEXT NOT NULL,
                account_password TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        self.conn.commit()

    def hash_password(self, password: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def register_user(self, username: str, password: str, totp_secret: str) -> bool:
        try:
            hashed = self.hash_password(password)
            self.cursor.execute("""
                INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)
            """, (username, hashed, totp_secret))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user_by_username(self, username: str):
        self.cursor.execute("""
            SELECT * FROM users WHERE username = ?
        """, (username,))
        return self.cursor.fetchone()

    def verify_password(self, username: str, password: str) -> bool:
        user = self.get_user_by_username(username)
        if not user:
            return False

        stored_hash = user['password']
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

    def insert_account(self, user_id: int, account_name: str, account_password: str):
        """
        Inserts new account(instance) into accounts table, related with users data
        """
        self.cursor.execute("""
            INSERT INTO accounts (user_id, account_name, account_password) VALUES (?, ?, ?)
        """, (user_id, account_name, account_password))
        self.conn.commit()

    def get_accounts_for_user(self, user_id: int):
        self.cursor.execute("""
            SELECT * FROM accounts WHERE user_id = ?
        """, (user_id,))
        return self.cursor.fetchall()

class LoginScreen(QWidget):

    def __init__(self, switch_to_register, switch_to_dashboard, db: Database):
        super().__init__()
        self.db = db
        self.switch_to_register = switch_to_register
        self.switch_to_dashboard = switch_to_dashboard

        # Layouts
        main_layout = QVBoxLayout()
        form_layout = QVBoxLayout()
        button_layout = QHBoxLayout()

        # App Title
        title = QLabel("Klucznik - bezpieczna skrzynka")
        title.setStyleSheet("font-size: 24px; font-weight: bold; text-align: center;")
        title.setAlignment(Qt.AlignCenter)

        # Login Fields
        username_label = QLabel("Nazwa użytkownika")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Wpisz nazwę użytkownika")

        password_label = QLabel("Hasło")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Wpisz hasło")

        # Buttons
        login_button = QPushButton("Zaloguj się")
        register_link = QPushButton("Nie masz konta? Zarejestruj się")
        register_link.setFlat(True)
        register_link.setStyleSheet("text-decoration: underline; color: blue;")

        register_link.clicked.connect(self.switch_to_register)
        login_button.clicked.connect(self.login_button)

        # Assemble Form Layout
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)

        button_layout.addWidget(login_button)

        # Assemble Main Layout
        main_layout.addWidget(title)
        main_layout.addSpacing(20)
        main_layout.addLayout(form_layout)
        main_layout.addSpacing(10)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(register_link)

        self.setLayout(main_layout)


    def login_button(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if username == "":
            QMessageBox.warning(self, "Błąd", "Wpisz nazwę użytkownika.")
            return

        if not self.db.verify_password(username, password):
            QMessageBox.warning(self, 'Błąd', 'Nieprawidłowa nazwa użykownika lub hasło.')
            return
        
        self.verify_two_factor()


    def verify_two_factor(self):
        username = self.username_input.text()
        user = self.db.get_user_by_username(username)

        if user is None:
            QMessageBox.warning(self, 'Błąd', 'Użytkownik nie istnieje.')
            return

        secret_key = user['totp_secret']
        if not secret_key:
            #If user lacks 2FA, he can be immediately switched to dashboard
            self.switch_to_dashboard(user['id'])
            return

        totp = pyotp.TOTP(secret_key)
        current_code = totp.now()

        code_input = QLineEdit()
        code_input.setPlaceholderText("Wpisz kod z aplikacji uwierzytelniającej")

        msg = QMessageBox()
        msg.setWindowTitle("Dwustopniowa weryfikacja")
        msg.setText("Wprowadź kod wygenerowany przez aplikację uwierzytelniającą.")
        msg.setDetailedText("Jeśli kod jest poprawny, proces logowania zostanie zakończony.")
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        msg.setInformativeText("Wprowadź kod:")
        msg.layout().addWidget(code_input, 1, 1)

        if msg.exec_() == QMessageBox.Ok:
            if code_input.text() == current_code:
                QMessageBox.information(self, "Sukces", "Kod został zweryfikowany pomyślnie!")
                self.switch_to_dashboard(user['id'])
            else:
                QMessageBox.warning(self, "Błąd", "Weryfikacja kodu nie powiodła się.")


class RegisterScreen(QWidget):
    def __init__(self, switch_to_login, db: Database):
        super().__init__()
        self.db = db
        self.switch_to_login = switch_to_login

        # Layouts
        main_layout = QVBoxLayout()
        form_layout = QVBoxLayout()
        button_layout = QHBoxLayout()

        # App Title
        title = QLabel("Klucznik - rejestracja")
        title.setStyleSheet("font-size: 24px; font-weight: bold; text-align: center;")
        title.setAlignment(Qt.AlignCenter)

        # Registration Fields
        username_label = QLabel("Nazwa użytkownika")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Wpisz nazwę użytkownika")

        password_label = QLabel("Hasło")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Wpisz hasło")

        confirm_password_label = QLabel("Potwierdź hasło")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Wpisz ponownie hasło")

        # Buttons
        register_button = QPushButton("Zarejestruj się")
        login_link = QPushButton("Masz już konto? Zaloguj się")
        login_link.setFlat(True)
        login_link.setStyleSheet("text-decoration: underline; color: blue;")

        login_link.clicked.connect(self.switch_to_login)
        register_button.clicked.connect(self.reg_button)

        # Assemble Form Layout
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)
        form_layout.addWidget(confirm_password_label)
        form_layout.addWidget(self.confirm_password_input)

        button_layout.addWidget(register_button)

        # Assemble Main Layout
        main_layout.addWidget(title)
        main_layout.addSpacing(20)
        main_layout.addLayout(form_layout)
        main_layout.addSpacing(10)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(login_link)

        self.setLayout(main_layout)


    def two_factor(self, username):
        # Generate QR Code
        secret = pyotp.random_base32()
        user = self.db.get_user_by_username(username)
        if user:
            self.db.cursor.execute("UPDATE users SET totp_secret=? WHERE id=?", (secret, user['id']))
            self.db.conn.commit()

        otpauth_str = f'otpauth://totp/Klucznik:{username}?secret={secret}&issuer=Klucznik'

        qr = qrcode.QRCode(box_size=10, border=5)
        qr.add_data(otpauth_str)
        qr.make(fit=True)

        img = qr.make_image(fill="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        pixmap = QPixmap()
        pixmap.loadFromData(buffer.read())

        # Show QR Code in a message box
        msg = QMessageBox()
        msg.setIconPixmap(pixmap)
        msg.setWindowTitle("Dwustopniowa weryfikacja")
        msg.setText("Zeskanuj kod QR w aplikacji uwierzytelniającej.")
        msg.setStandardButtons(QMessageBox.Ok)

        if msg.exec_() == QMessageBox.Ok:
            QMessageBox.information(self, "Rejestracja zakończona", "Kod QR został zeskanowany. Możesz teraz się zalogować.")
            self.switch_to_login()


    def reg_button(self):

        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if username == "":
            QMessageBox.warning(self, "Błąd", "Wpisz nazwę użytkownika.")
            return
        
        if password == "":
            QMessageBox.warning(self, "Błąd", "Wpisz hasło.")
            return
        
        if confirm_password == "":
            QMessageBox.warning(self, "Błąd", "Potwierdź hasło.")
            return
        
        if len(username) < 4:
            QMessageBox.warning(self, "Błąd", "Nazwa użytkownika musi zawierać co najmniej 4 znaki.")
            return

        if len(password) < 8:
            QMessageBox.warning(self, "Błąd", "Hasło musi zawierać co najmniej 8 znaków.")
            return

        if password != confirm_password:
            QMessageBox.warning(self, "Błąd", "Podane hasła różnią się od siebie.")
            return

        success = self.db.register_user(username, password, totp_secret=None)
        if not success:
            QMessageBox.warning(self, 'Błąd', 'Nazwa użytkownik jest zajęta')
            return

        self.two_factor(username)


class DashboardScreen(QWidget):
    def __init__(self, switch_to_login, db: Database):
        super().__init__()
        self.db = db
        self.switch_to_login = switch_to_login
        self.user_id = None

        # Layout
        main_layout = QVBoxLayout()

        # Title
        title = QLabel("Twoje konta")
        title.setStyleSheet("font-size: 24px; font-weight: bold; text-align: center;")
        title.setAlignment(Qt.AlignCenter)

        # Password List
        self.password_list = QListWidget()

        # Buttons
        add_account_button = QPushButton("Dodaj konto")
        add_account_button.clicked.connect(self.add_account_dialog)

        back_to_login_button = QPushButton("Wyloguj się")
        back_to_login_button.clicked.connect(self.logout)

        # Assemble Layout
        main_layout.addWidget(title)
        main_layout.addWidget(self.password_list)
        main_layout.addWidget(add_account_button)
        main_layout.addWidget(back_to_login_button)

        self.setLayout(main_layout)

    def show_dashboard_for_user(self, user_id: int):
        self.user_id = user_id
        self.update_account_list()

    def update_account_list(self):
        """
        Downloads from database list of accounts for logged user and updates QListWidgets
        """
        self.password_list.clear()
        if self.user_id is None:
            return

        accounts = self.db.get_accounts_for_user(self.user_id)
        for account in accounts:
            display_text = f"{account['account_name']} - {account['account_password']}"
            self.password_list.addItem(display_text)

    def add_account_dialog(self):
        """
        Adds new account instance for logged user
        """
        account_name, ok = QInputDialog.getText(self, 'Dodaj konto', 'Nazwa konta:')
        if not ok or not account_name:
            return

        account_password, ok = QInputDialog.getText(self, 'Dodaj konto', 'Hasło konta', QLineEdit.Password)
        if not ok:
            return

        self.db.insert_account(self.user_id, account_name, account_password)
        self.update_account_list()

    def logout(self):
        self.user_id = None
        self.switch_to_login()

class MainApp(QWidget):

    def __init__(self):
        super().__init__()

        self.db = Database()

        # Stacked Widget
        self.stacked_widget = QStackedWidget()

        # Screens
        self.login_screen = LoginScreen(
            switch_to_register=self.show_register_screen,
            switch_to_dashboard=self.show_dashboard_screen,
            db=self.db
        )
        self.register_screen = RegisterScreen(
            switch_to_login=self.show_login_screen,
            db=self.db
        )
        self.dashboard_screen = DashboardScreen(
            switch_to_login=self.show_login_screen,
            db=self.db
        )

        self.stacked_widget.addWidget(self.login_screen)
        self.stacked_widget.addWidget(self.register_screen)
        self.stacked_widget.addWidget(self.dashboard_screen)

        # Main Layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.stacked_widget)
        self.setLayout(main_layout)

        self.setWindowTitle("Klucznik - bezpieczna skrzynka")
        self.resize(400, 300)

    def show_login_screen(self):
        self.stacked_widget.setCurrentWidget(self.login_screen)

    def show_register_screen(self):
        self.stacked_widget.setCurrentWidget(self.register_screen)

    def show_dashboard_screen(self, user_id: int):
        self.dashboard_screen.show_dashboard_for_user(user_id)
        self.stacked_widget.setCurrentWidget(self.dashboard_screen)
 