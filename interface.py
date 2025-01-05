import sys
import sqlite3
import hashlib

import bcrypt
from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QWidget, QMessageBox, QListWidget, QInputDialog,
                             QListWidgetItem, QDesktopWidget)
from PyQt5.QtCore import Qt, QTimer
import qrcode
from PyQt5.QtGui import QPixmap, QIcon
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

    def get_account_by_name(self, user_id, account_name):
        self.cursor.execute("""
            SELECT * FROM accounts WHERE user_id = ? AND account_name = ?
        """, (user_id, account_name))
        return self.cursor.fetchone()


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
        """
        Downloads from database list of accounts for logged user and updates QListWidget
        """
        self.password_list.clear()
        if self.user_id is None:
            return

        accounts = self.db.get_accounts_for_user(self.user_id)
        for account in accounts:
            # Initially display passwords as masked
            masked_password = '*********'
            account_item = QListWidgetItem(f"{account['account_name']} - {masked_password}")
            account_item.setData(Qt.UserRole, account['account_password'])
            account_item.setTextAlignment(Qt.AlignLeft)
            self.password_list.addItem(account_item)

            # Add hover event to reveal password
            account_item.setToolTip(account['account_password'])  # Optional: tool tip
            account_item.setData(Qt.UserRole + 1, False)  # Track if password is currently masked

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

    def add_account_dialog(self):
        """
        Adds new account instance for logged user
        """
        account_name, ok = QInputDialog.getText(self, 'Dodaj konto', 'Nazwa konta:')
        if not ok or not account_name:
            # Show error notification if account name is empty
            self.show_error_notification("Nazwa konta nie może być pusta!")
            return

        # Check if the account name already exists
        existing_account = self.db.get_account_by_name(self.user_id, account_name)
        if existing_account:
            # Show error notification if account already exists
            self.show_error_notification(f"Konto o nazwie '{account_name}' już istnieje!")
            return

        account_password, ok = QInputDialog.getText(self, f'Ustaw hasło', f'Hasło do konta {account_name}',
                                                    QLineEdit.Password)
        if not ok:
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
        self.stacked_widget.setCurrentWidget(self.login_screen)

    def show_register_screen(self):
        self.stacked_widget.setCurrentWidget(self.register_screen)

    def show_dashboard_screen(self, user_id: int):
        self.dashboard_screen.show_dashboard_for_user(user_id)
        self.stacked_widget.setCurrentWidget(self.dashboard_screen)
