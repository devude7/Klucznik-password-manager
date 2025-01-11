import sys
import sqlite3
import hashlib
import string
import random

import bcrypt
from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QWidget, QMessageBox, QListWidget, QInputDialog,
                             QListWidgetItem, QDesktopWidget, QDialog)
from PyQt5.QtCore import Qt, QTimer, QSize
import qrcode
from PyQt5.QtGui import QPixmap, QIcon
from io import BytesIO
import pyotp

from cryptography.fernet import Fernet
import os
import keyring

SERVICE_NAME = 'KlucznikApp'
USERNAME = "encryption_key"

def generate_and_store_key():
    key = Fernet.generate_key()
    keyring.set_password(SERVICE_NAME, USERNAME, key.decode('utf-8'))
    return key

def load_key():
    key = keyring.get_password(SERVICE_NAME, USERNAME)
    if key is None:
        key = generate_and_store_key()
    else:
        key = key.encode('utf-8')
    return key

class  Database:
    """class responsible for connection with SQLLITE Database, and operations on it"""
    def __init__(self, db_name='key_keeper.db'):
        self.conn = sqlite3.connect(db_name)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.create_tables()

        key = load_key()
        self.cipher_suite = Fernet(key)

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

    def encrypt_password(self, plain_text_password: str) -> str:
        encrypted = self.cipher_suite.encrypt(plain_text_password.encode('utf-8'))
        return encrypted.decode('utf-8')

    def decrypt_password(self, encrypted_text_password: str) -> str:
        decrypted = self.cipher_suite.decrypt(encrypted_text_password.encode('utf-8'))
        return decrypted.decode('utf-8')

    def insert_account(self, user_id: int, account_name: str, account_password: str):
        """
        Inserts new account(instance) into accounts table, related with users data
        """
        encrypted_password = self.encrypt_password(account_password)
        self.cursor.execute("""
            INSERT INTO accounts (user_id, account_name, account_password) VALUES (?, ?, ?)
        """, (user_id, account_name, encrypted_password))
        self.conn.commit()

    def get_accounts_for_user(self, user_id: int):
        self.cursor.execute("""
            SELECT * FROM accounts WHERE user_id = ?
        """, (user_id,))
        accounts = self.cursor.fetchall()
        decrypted_accounts = []
        for account in accounts:
            decrypted_password = self.decrypt_password(account['account_password']) if account['account_password'] else None
            decrypted_account = dict(account)
            decrypted_account['account_password'] = decrypted_password
            decrypted_accounts.append(decrypted_account)
        return decrypted_accounts

    def get_account_by_name(self, user_id, account_name):
        self.cursor.execute("""
            SELECT * FROM accounts WHERE user_id = ? AND account_name = ?
        """, (user_id, account_name))
        account = self.cursor.fetchone()
        if account and account['account_password']:
            decrypted_password = self.decrypt_password(account['account_password'])
            decrypted_account = dict(account)
            decrypted_account['account_password'] = decrypted_password
            return decrypted_account
        return account

    def update_password(self, user_id: int, account_name: str, new_password: str):
        """Updates the password for a specific account"""
        encrypted_password = self.encrypt_password(new_password)
        self.cursor.execute("""
            UPDATE accounts
            SET account_password = ?
            WHERE user_id = ? AND account_name = ?
        """, (encrypted_password, user_id, account_name))
        self.conn.commit()

    def delete_account(self, user_id: int, account_name: str):
        """Deletes a specific account from the database"""
        self.cursor.execute("""
            DELETE FROM accounts
            WHERE user_id = ? AND account_name = ?
        """, (user_id, account_name))
        self.conn.commit()


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

        #App logo
        logo = QLabel()
        pixmap = QPixmap('assets/app_logo_transparent.png')
        pixmap = pixmap.scaled(350, 350, Qt.KeepAspectRatio)  # Maksymalny rozmiar 350px
        logo.setPixmap(pixmap)
        logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo)

        # App Title
        # title = QLabel("Klucznik - bezpieczna skrzynka")
        # title.setStyleSheet("font-size: 28px; font-weight: bold; color: #ff8c00;")
        # title.setAlignment(Qt.AlignCenter)

        # Login Fields
        username_label = QLabel("Nazwa użytkownika")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Wpisz nazwę użytkownika")
        # Przeskok między polami za pomocą Enter
        self.username_input.returnPressed.connect(self.login_button)

        password_label = QLabel("Hasło")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Wpisz hasło")
        self.password_input.returnPressed.connect(self.login_button)

        # Buttons
        login_button = QPushButton("Zaloguj się")
        login_button.setIcon(QIcon('assets/login_icon.png'))
        login_button.setStyleSheet("padding-left: 10px; font-size: 24px")

        # Zmiana ikony przy hover
        def change_icon_on_hover():
            login_button.setIcon(QIcon('assets/login_icon_hover.png'))

        def reset_icon():
            login_button.setIcon(QIcon('assets/login_icon.png'))

        # Ustawienie akcji na hover
        login_button.enterEvent = lambda event: change_icon_on_hover()
        login_button.leaveEvent = lambda event: reset_icon()


        register_link = QPushButton("Nie masz konta? Zarejestruj się")
        register_link.setFlat(True)
        register_link.setStyleSheet("""
            font-weight: normal;
            font-size: 12px;
            text-decoration: underline;
            color: orange;
            background: transparent;
            border-radius: 100px;

            /* Efekt hover */
            :hover {
                background: yellow;
                cursor: pointer;
            }
        """)

        register_link.clicked.connect(self.switch_to_register)
        login_button.clicked.connect(self.login_button)

        # Assemble Form Layout
        form_layout.addWidget(username_label)
        form_layout.addWidget(self.username_input)
        form_layout.addWidget(password_label)
        form_layout.addWidget(self.password_input)

        button_layout.addWidget(login_button)

        # Assemble Main Layout
        # main_layout.addWidget(title)
        main_layout.addSpacing(20)
        main_layout.addLayout(form_layout)
        main_layout.addSpacing(10)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(register_link)

        self.setLayout(main_layout)

    def login_button(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if username == "" and password == "":
            return  # Jeśli oba pola są puste, nie rób nic

        if username == "":
            self.username_input.setFocus()  # Jeśli brak nazwy użytkownika, ustaw focus na tym polu
            return

        if password == "":
            self.password_input.setFocus()  # Jeśli brak hasła, ustaw focus na tym polu
            return

        if not self.db.verify_password(username, password):
            QMessageBox.warning(self, 'Błąd', 'Nieprawidłowa nazwa użytkownika lub hasło.')
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
            # If user lacks 2FA, they can be immediately switched to the dashboard
            self.switch_to_dashboard(user['id'])
            return

        totp = pyotp.TOTP(secret_key)
        current_code = totp.now()

        code_input = QLineEdit()
        code_input.setPlaceholderText("Wpisz kod z aplikacji uwierzytelniającej")

        # Stylizacja dla wiadomości
        msg = QMessageBox()
        msg.setWindowTitle("Dwustopniowa weryfikacja")
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)

        # Załaduj logo jako ikonę okna
        logo = QPixmap('assets/app_logo_image.png')  # Ścieżka do logo
        msg.setWindowIcon(QIcon(logo))

        # Dodanie pola wejściowego do layoutu wiadomości
        msg.layout().addWidget(code_input, 1, 1)

        # Stylizacja okna wiadomości
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #1e1e1e;
                color: #ff8c00;  /* Pomarańczowy kolor tekstu */
            }
            QLineEdit {
                background-color: #2e2e2e;
                border: 1px solid #ff8c00;
                padding: 6px;
                border-radius: 4px;
                color: #f0e68c;
            }
            QPushButton {
                background: transparent;
                border: 2px solid #ff8c00;
                color: #ff8c00;
                font-weight: bold;
                font-size: 14px;
                padding: 10px 20px;
                width: 50%;
                margin: 10px auto;
                border-radius: 15px;
            }
            QPushButton:hover {
                background-color: #ff8c00;
                color: white;
                cursor: pointer;
            }
            QPushButton:pressed {
                background-color: #cc7a00;
            }
            QPushButton:focus {
                outline: none;
            }
        """)

        # Ustawienie kursora na pole wpisywania kodu
        code_input.setFocus()

        if msg.exec_() == QMessageBox.Ok:
            if code_input.text() == current_code:
                #QMessageBox.information(self, "Sukces", "Kod został zweryfikowany pomyślnie!")
                self.switch_to_dashboard(user['id'])
            else:
                QMessageBox.warning(self, "Błąd", "Weryfikacja kodu nie powiodła się.")

    def clear_fields(self):
        """
        Clears the login fields
        """
        self.username_input.clear()
        self.password_input.clear()


class RegisterScreen(QWidget):
    def __init__(self, switch_to_login, db: Database):
        super().__init__()
        self.db = db
        self.switch_to_login = switch_to_login

        # Layouts
        main_layout = QVBoxLayout()
        form_layout = QVBoxLayout()
        button_layout = QHBoxLayout()

        # App logo
        logo = QLabel()
        pixmap = QPixmap('assets/app_logo_transparent.png')
        pixmap = pixmap.scaled(200, 200, Qt.KeepAspectRatio)  # Maksymalny rozmiar 350px
        logo.setPixmap(pixmap)
        logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo)

        # App Title
        title = QLabel("Rejestracja")
        title.setStyleSheet("font-size: 24px; font-weight: bold; text-align: center;")
        title.setAlignment(Qt.AlignCenter)

        # Registration Fields
        username_label = QLabel("Nazwa użytkownika")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Wpisz nazwę użytkownika")
        self.username_input.returnPressed.connect(self.focus_next_widget)

        password_label = QLabel("Hasło")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Wpisz hasło")
        self.password_input.returnPressed.connect(self.focus_next_widget)

        confirm_password_label = QLabel("Potwierdź hasło")
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Wpisz ponownie hasło")
        self.confirm_password_input.returnPressed.connect(self.reg_button)  # Automatycznie kliknie "Zarejestruj się"

        # Buttons
        register_button = QPushButton("Zarejestruj się")
        register_button.setIcon(QIcon('assets/register_icon.png'))
        register_button.setStyleSheet("padding-left: 10px; font-size: 24px")

        # Zmiana ikony przy hover
        def change_icon_on_hover():
            register_button.setIcon(QIcon('assets/register_icon_hover.png'))

        def reset_icon():
            register_button.setIcon(QIcon('assets/register_icon.png'))

        # Ustawienie akcji na hover
        register_button.enterEvent = lambda event: change_icon_on_hover()
        register_button.leaveEvent = lambda event: reset_icon()

        login_link = QPushButton("Masz już konto? Zaloguj się")
        login_link.setFlat(True)
        login_link.setStyleSheet("""
            font-weight: normal;
            font-size: 12px;
            text-decoration: underline;
            color: orange;
            background: transparent;
            border-radius: 100px;

            /* Efekt hover */
            :hover {
                background: yellow;
                cursor: pointer;
            }
        """)

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

    def focus_next_widget(self):
        # Move focus to next widget if Enter is pressed
        widget = self.focusWidget()
        if widget is self.username_input:
            self.password_input.setFocus()
        elif widget is self.password_input:
            self.confirm_password_input.setFocus()

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

        # Zaokrąglone rogi dla okna
        msg.setStyleSheet("""
            QMessageBox {
                background-color: #1e1e1e;
                color: #ff8c00;  /* Pomarańczowy kolor tekstu */
                border-radius: 15px;
            }
            QMessageBox QLabel {
                font-size: 16px;
                font-weight: bold;
                font-style: italic;
                color: #ff8c00;
            }
            QMessageBox QPushButton {
                background: transparent;
                border: 2px solid #ff8c00;
                color: #ff8c00;
                font-weight: bold;
                font-size: 14px;
                padding: 10px 20px;
                width: 50%;
                margin: 10px auto;
                border-radius: 15px;
            }
            QMessageBox QPushButton:hover {
                background-color: #ff8c00;
                color: white;
                cursor: pointer;
            }
        """)

        # Load logo as icon for the message box
        logo = QPixmap('assets/app_logo_image.png')  # Ścieżka do logo

        # Set window icon to logo
        msg.setWindowIcon(QIcon(logo))
        msg.setWindowTitle("Dwustopniowa weryfikacja")

        # Set the QR code as the icon of the message box
        msg.setIconPixmap(pixmap)

        # Ustawienie stylu dla tekstu pod kodem QR
        msg.setText(
            "<p style='font-weight: bold; font-style: italic; text-align: center; color: #ff8c00; padding-top: 20px;'>Zeskanuj kod QR w aplikacji uwierzytelniającej.</p>")

        msg.setStandardButtons(QMessageBox.Ok)

        # Show the message box
        if msg.exec_() == QMessageBox.Ok:
            QMessageBox.information(self, "Rejestracja zakończona",
                                    "Kod QR został zeskanowany. Możesz teraz się zalogować.")
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


from PyQt5.QtWidgets import QListWidgetItem, QLabel, QVBoxLayout
import pyperclip


class DashboardScreen(QWidget):
    def __init__(self, switch_to_login, db: Database):
        super().__init__()
        self.db = db
        self.switch_to_login = switch_to_login
        self.user_id = None

        # Layout
        main_layout = QVBoxLayout()

        # App logo
        logo = QLabel()
        pixmap = QPixmap('assets/app_logo_image.png')
        pixmap = pixmap.scaled(100, 100, Qt.KeepAspectRatio)  # Maksymalny rozmiar 100px
        logo.setPixmap(pixmap)
        logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo)

        # Title
        title = QLabel("Twoje konta")
        title.setStyleSheet("font-size: 24px; font-weight: bold; text-align: center;")
        title.setAlignment(Qt.AlignCenter)

        # Password List
        self.password_list = QListWidget()
        self.password_list.setStyleSheet("font-size: 18px;")

        # Connect click event to copy password to clipboard
        self.password_list.itemClicked.connect(self.copy_password_to_clipboard)

        # Initialize notification label
        self.notification_label = QLabel(self)
        self.notification_label.setStyleSheet(
            "font-size: 18px; color: #e7673b; background-color: #ffbf69; padding: 5px; border-radius: 5px;")
        self.notification_label.setAlignment(Qt.AlignCenter)
        self.notification_label.setVisible(False)  # Initially hidden
        main_layout.addWidget(self.notification_label)

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
        def add_icon_hover_effect(button: QPushButton, normal_icon_path: str, hover_icon_path: str):
            """
            Dodaje efekt zmiany ikony na hover dla przycisku QPushButton.
            """
            normal_icon = QIcon(normal_icon_path)
            hover_icon = QIcon(hover_icon_path)

            def on_hover_enter(event):
                button.setIcon(hover_icon)
                super(QPushButton, button).enterEvent(event)

            def on_hover_leave(event):
                button.setIcon(normal_icon)
                super(QPushButton, button).leaveEvent(event)

            button.setIcon(normal_icon)
            button.enterEvent = on_hover_enter
            button.leaveEvent = on_hover_leave
        """
        Downloads from the database list of accounts for the logged user and updates QListWidget
        """
        self.password_list.clear()
        if self.user_id is None:
            return

        accounts = self.db.get_accounts_for_user(self.user_id)
        for account in accounts:
            # Initially display passwords as masked
            masked_password = '*********'
            account_text = f"{account['account_name']} - {masked_password}"

            # Create QListWidgetItem to display account info
            account_item = QListWidgetItem(account_text)
            account_item.setData(Qt.UserRole, account['account_password'])
            account_item.setTextAlignment(Qt.AlignLeft)

            # Add edit and delete icons
            edit_icon = QIcon('assets/ic_edit.png')
            delete_icon = QIcon('assets/ic_delete.png')

            # Create buttons for edit and delete
            edit_button = QPushButton(edit_icon, "")
            delete_button = QPushButton(delete_icon, "")

            # Set the buttons to be 30x30
            edit_button.setFixedSize(30, 30)
            delete_button.setFixedSize(30, 30)

            # Make buttons flat and transparent
            edit_button.setFlat(True)
            delete_button.setFlat(True)

            # Set tooltip text for hover
            edit_button.setToolTip("Kliknij, aby edytować")
            delete_button.setToolTip("Kliknij, aby usunąć")

            add_icon_hover_effect(edit_button, 'assets/ic_edit.png', 'assets/ic_edit_hover.png')
            add_icon_hover_effect(delete_button, 'assets/ic_delete.png', 'assets/ic_delete_hover.png')

            # Add hover effect for changing icons
            edit_button.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    border: none;
                    image: url('assets/ic_edit.png');
                }
                QPushButton:hover {
                    image: url('assets/ic_edit_hover.png');
                }
            """)

            delete_button.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    border: none;
                    image: url('assets/ic_delete.png');
                }
                QPushButton:hover {
                    image: url('assets/ic_delete_hover.png');
                }
            """)

            # Connect the edit and delete buttons to their respective methods
            edit_button.clicked.connect(lambda checked, item=account_item: self.edit_password_dialog(item))
            delete_button.clicked.connect(lambda checked, item=account_item: self.delete_password_dialog(item))

            # Create a layout for text and buttons
            layout = QHBoxLayout()

            # Add the account name text as a QLabel (this keeps the text visible)
            account_label = QLabel(account_text)
            account_label.setAlignment(Qt.AlignLeft)

            # Add the buttons to the layout, with spacing
            layout.addWidget(account_label)
            layout.addStretch()  # This makes sure the text is pushed to the left
            layout.addWidget(edit_button)
            layout.addSpacing(15)  # Add space between the icons
            layout.addWidget(delete_button)
            layout.setContentsMargins(0, 0, 10, 0)  # Add padding on the right

            # Create a QWidget for the layout and add it to the item
            button_widget = QWidget()
            button_widget.setLayout(layout)

            # Add the item and the button widget to the list
            self.password_list.addItem(account_item)
            self.password_list.setItemWidget(account_item, button_widget)

            # Add hover effect for account items
            self.add_hover_effect(account_item, layout)

            # Set tooltip for the account password (only for hover or click)
            account_item.setToolTip(account['account_password'])

    def add_hover_effect(self, account_item, layout):
        """
        Adds hover effect for account items in the list
        """

        def on_hover_enter():
            # Change background color to light gray when hover begins
            layout.setStyleSheet("background-color: rgba(169, 169, 169, 0.2);")  # Light gray hover effect

        def on_hover_leave():
            # Reset background color when hover ends
            layout.setStyleSheet("")

        layout.installEventFilter(self)

        # Connect hover events
        layout.mouseMoveEvent = on_hover_enter
        layout.mouseLeaveEvent = on_hover_leave

    def on_item_hovered(self, item):
        """
        Show password on hover
        """
        if not item.data(Qt.UserRole + 1):  # Check if password is currently masked
            original_password = item.data(Qt.UserRole)
            item.setText(f"{item.text().split(' - ')[0]} - {original_password}")
            item.setData(Qt.UserRole + 1, True)  # Set to unmasked
        else:
            masked_password = '*********'
            item.setText(f"{item.text().split(' - ')[0]} - {masked_password}")
            item.setData(Qt.UserRole + 1, False)  # Set back to masked


    def hide_notification(self):
        """
        Hides the notification label
        """
        self.notification_label.setVisible(False)

    def edit_password_dialog(self, item):
        """
        Opens a dialog to edit the password
        """
        current_password = item.data(Qt.UserRole)
        account_name = item.text().split(" - ")[0]

        dialog = QDialog(self)
        dialog.setWindowTitle(f'Edycja hasła dla {account_name}')
        layout = QVBoxLayout(dialog)

        # New password input fields
        new_password_label = QLabel('Nowe hasło:', dialog)
        new_password_input = QLineEdit(dialog)
        new_password_input.setEchoMode(QLineEdit.Password)

        # Eye icon for password visibility toggle
        toggle_eye_button = QPushButton(dialog)
        toggle_eye_button.setIcon(QIcon('assets/ic_eye_inline.png'))  # Default eye icon
        toggle_eye_button.setFixedSize(30, 30)
        toggle_eye_button.setStyleSheet("""
            QPushButton {
                border: none;
                padding: 10px;
                background: transparent;
            }
            QPushButton:hover {
                icon-size: 35px;
                background: transparent;
            }
        """)

        # Layout for password input and the eye icon
        password_layout = QHBoxLayout()
        password_layout.addWidget(new_password_input)
        password_layout.addWidget(toggle_eye_button)
        layout.addWidget(new_password_label)
        layout.addLayout(password_layout)

        # Confirm password input
        confirm_password_label = QLabel('Potwierdź hasło:', dialog)
        confirm_password_input = QLineEdit(dialog)
        confirm_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(confirm_password_label)
        layout.addWidget(confirm_password_input)

        # Function to toggle password visibility
        def toggle_password_visibility():
            if new_password_input.echoMode() == QLineEdit.Password:
                new_password_input.setEchoMode(QLineEdit.Normal)
                toggle_eye_button.setIcon(QIcon('assets/ic_eye_outline.png'))
            else:
                new_password_input.setEchoMode(QLineEdit.Password)
                toggle_eye_button.setIcon(QIcon('assets/ic_eye_inline.png'))

        toggle_eye_button.clicked.connect(toggle_password_visibility)

        # Function to generate a new password
        def generate_password():
            allowed_punctuation = ''.join(c for c in string.punctuation if c not in r'\/\'":;|<>')
            all_characters = string.ascii_letters + string.digits + allowed_punctuation
            password = ''.join(random.choices(all_characters, k=30))
            new_password_input.setText(password)
            confirm_password_input.setText(password)  # Set the same password in confirm field

        generate_button = QPushButton('Wygeneruj hasło', dialog)
        generate_button.clicked.connect(generate_password)
        layout.addWidget(generate_button)

        # Buttons
        buttons_layout = QHBoxLayout()
        ok_button = QPushButton('Zapisz', dialog)
        cancel_button = QPushButton('Anuluj', dialog)
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        layout.addLayout(buttons_layout)

        # Use a lambda to pass the item to update_password function
        ok_button.clicked.connect(
            lambda: self.update_password(item, new_password_input.text(), confirm_password_input.text(), dialog)
        )
        cancel_button.clicked.connect(dialog.reject)

        dialog.exec_()

    def update_password(self, item, new_password, confirm_password, dialog):
        """
        Updates the password if valid
        """
        if len(new_password) < 8:
            QMessageBox.warning(self, "Błąd", "Hasło musi mieć co najmniej 8 znaków!")
            return

        if new_password != confirm_password:
            QMessageBox.warning(self, "Błąd", "Hasła nie są zgodne!")
            return

        account_name = item.text().split(" - ")[0]

        try:
            self.db.update_password(self.user_id, account_name, new_password)
            item.setData(Qt.UserRole, new_password)  # Update password in list
            self.update_account_list()
            QMessageBox.information(self, "Sukces", "Hasło zostało zaktualizowane.")
            dialog.accept()  # Close the dialog upon success
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie udało się zaktualizować hasła: {e}")

    def delete_password_dialog(self, item):
        """
        Shows a confirmation dialog to delete the password
        """
        account_name = item.text().split(" - ")[0]

        reply = QMessageBox(self)
        reply.setWindowTitle('Potwierdzenie')
        reply.setText(f"Czy na pewno chcesz usunąć hasło do konta {account_name}?")
        reply.setStandardButtons(QMessageBox.Yes | QMessageBox.No)

        # Zamień tekst przycisków
        yes_button = reply.button(QMessageBox.Yes)
        no_button = reply.button(QMessageBox.No)
        yes_button.setText("Tak")
        no_button.setText("Nie")

        # Ustaw domyślny przycisk
        reply.setDefaultButton(QMessageBox.No)

        if reply.exec_() == QMessageBox.Yes:
            self.db.delete_account(self.user_id, account_name)
            self.update_account_list()

        if reply == QMessageBox.Yes:
            self.db.delete_account(self.user_id, account_name)
            self.update_account_list()

    def logout(self):
        """
        Logs out the user and clears login fields
        """
        self.user_id = None
        self.switch_to_login()
        self.clear_login_fields()  # Clear the login fields after logout

    def add_account_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Dodaj konto')
        layout = QVBoxLayout(dialog)

        # Account name input
        name_label = QLabel('Nazwa konta:', dialog)
        name_input = QLineEdit(dialog)
        layout.addWidget(name_label)
        layout.addWidget(name_input)

        # Password input with eye icon button
        password_label = QLabel('Hasło:', dialog)
        password_input = QLineEdit(dialog)
        password_input.setEchoMode(QLineEdit.Password)

        # Tworzenie przycisku do podglądu hasła
        toggle_eye_button = QPushButton(dialog)
        toggle_eye_button.setIcon(QIcon('assets/ic_eye_inline.png'))  # Początkowa ikonka oczka
        toggle_eye_button.setFixedSize(30, 30)
        toggle_eye_button.setStyleSheet("""
            QPushButton {
                border: none;
                padding: 10px;  /* Zwiększenie klikalnego obszaru */
                background: transparent; 
            }
            QPushButton:hover {
                icon-size: 35px;  /* Powiększenie ikonki przy najechaniu */
                background: transparent; 
            }
        """)

        # Kontener na pole hasła i przycisk z oczkiem
        password_layout = QHBoxLayout()
        password_layout.addWidget(password_input)
        password_layout.addWidget(toggle_eye_button)
        layout.addWidget(password_label)
        layout.addLayout(password_layout)

        def toggle_password_visibility():
            """Przełącza widoczność hasła i zmienia ikonę przycisku."""
            if password_input.echoMode() == QLineEdit.Password:
                password_input.setEchoMode(QLineEdit.Normal)
                toggle_eye_button.setIcon(QIcon('assets/ic_eye_outline.png'))
            else:
                password_input.setEchoMode(QLineEdit.Password)
                toggle_eye_button.setIcon(QIcon('assets/ic_eye_inline.png'))

        toggle_eye_button.clicked.connect(toggle_password_visibility)

        # Generate password button
        def generate_password():
            allowed_punctuation = ''.join(c for c in string.punctuation if c not in r'\/\'":;|<>')
            all_characters = string.ascii_letters + string.digits + allowed_punctuation
            password = ''.join(random.choices(all_characters, k=random.randint(25,30)))
            password_input.setText(password)

        generate_button = QPushButton('Wygeneruj hasło', dialog)
        generate_button.clicked.connect(generate_password)
        layout.addWidget(generate_button)

        # Add buttons for OK and Cancel
        buttons_layout = QHBoxLayout()
        ok_button = QPushButton('OK', dialog)
        cancel_button = QPushButton('Anuluj', dialog)
        buttons_layout.addWidget(ok_button)
        buttons_layout.addWidget(cancel_button)

        # Ograniczenie obszaru klikalnego do wnętrza przycisku
        ok_button.setStyleSheet("""
            QPushButton {
                background: transparent;
                border: 2px solid #ff8c00;
                color: #ff8c00;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ff8c00;
                color: white;
            }
            QPushButton:pressed {
                background-color: #cc7a00;
            }
            QPushButton:focus {
                outline: none;
            }
        """)
        cancel_button.setStyleSheet(ok_button.styleSheet())  # Taki sam styl jak dla OK

        ok_button.clicked.connect(dialog.accept)
        cancel_button.clicked.connect(dialog.reject)
        layout.addLayout(buttons_layout)

        def on_enter_pressed():
            ok_button.click()

        # Nasłuchujemy na naciśnięcie klawisza Enter
        name_input.returnPressed.connect(on_enter_pressed)
        password_input.returnPressed.connect(on_enter_pressed)

        if dialog.exec_() == QDialog.Accepted:
            account_name = name_input.text()
            account_password = password_input.text()

            if not account_name:
                QMessageBox.critical(self, 'Błąd', 'Nazwa konta nie może być pusta!')
                return

            existing_account = self.db.get_account_by_name(self.user_id, account_name)
            if existing_account:
                QMessageBox.critical(self, 'Błąd', f"Konto o nazwie '{account_name}' już istnieje!")
                return

            self.db.insert_account(self.user_id, account_name, account_password)
            self.update_account_list()

    def show_error_notification(self, message):
        """
        Shows an error notification with the given message
        """
        self.notification_label.setText(message)
        self.notification_label.setStyleSheet(
            "font-size: 18px; color: #e7673b; background-color: #ffbf69; padding: 5px; border-radius: 5px;")
        self.notification_label.setVisible(True)

        # Hide the notification after 3 seconds
        QTimer.singleShot(3000, self.hide_notification)

    def logout(self):
        self.user_id = None
        self.switch_to_login()

    def copy_password_to_clipboard(self, item):
        """
        Copies password to clipboard when clicked
        """
        password = item.data(Qt.UserRole)
        account_name = item.text().split(" - ")[0]  # Get the account name from the text
        pyperclip.copy(password)

        # Show notification
        self.notification_label.setText(f"Skopiowano hasło do {account_name}")
        self.notification_label.setVisible(True)

        # Hide the notification after 3 seconds
        QTimer.singleShot(3000, self.hide_notification)

    def hide_notification(self):
        """
        Hides the notification label
        """
        self.notification_label.setVisible(False)


class MainApp(QWidget):

    def __init__(self):
        super().__init__()

        self.db = Database()
        self.resize(700, 400)
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #f0e68c;
            }
            QPushButton {
                background: transparent;
                border: 2px solid #ff8c00;
                color: #ff8c00;
                font-weight: bold;
                font-size: 14px;
                padding: 10px 20px;
                width: 50%;
                margin: 10px auto;
                border-radius: 15px;
            }
            QPushButton:hover {
                background-color: #ff8c00;
                color: white;
                cursor: pointer;
            }
            QPushButton:pressed {
                background-color: #cc7a00;
            }
            QPushButton:focus {
                outline: none;
            }
            QLineEdit {
                background-color: #2e2e2e;
                border: 1px solid #ff8c00;
                padding: 6px;
                border-radius: 4px;
                color: #f0e68c;
            }
            QLabel {
                font-size: 14px;
            }
            QInputDialog QLineEdit {
                background-color: #2e2e2e;
                border: 1px solid #ff8c00;
                padding: 6px;
                border-radius: 4px;
                color: #f0e68c;
            }
        """)

        # Ustawienie ikony aplikacji (ikona w górnym pasku i ikona aplikacji na pulpicie)
        self.setWindowIcon(QIcon('assets/app_logo_image.png'))

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

        self.setWindowTitle("Klucznik - bezpieczna skrytka")
        self.resize(450, 300)

        # Wyśrodkowanie aplikacji
        self.center()

    def center(self):
        """Wyśrodkowanie okna na ekranie"""
        screen = QDesktopWidget().screenGeometry()  # Pobierz rozmiar ekranu
        size = self.geometry()  # Pobierz rozmiar okna
        x = (screen.width() - size.width()) // 2
        y = 150
        self.move(x, y)  # Przesuń okno na wyśrodkowaną pozycję

    def show_login_screen(self):
        self.login_screen.clear_fields()  # Clear fields when showing login screen
        self.stacked_widget.setCurrentWidget(self.login_screen)

    def show_register_screen(self):
        self.stacked_widget.setCurrentWidget(self.register_screen)

    def show_dashboard_screen(self, user_id: int):
        self.dashboard_screen.show_dashboard_for_user(user_id)
        self.stacked_widget.setCurrentWidget(self.dashboard_screen)

