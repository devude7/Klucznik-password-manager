from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QWidget, QMessageBox, QListWidget)
from PyQt5.QtCore import Qt
import qrcode
from PyQt5.QtGui import QPixmap
from io import BytesIO
import pyotp

class LoginScreen(QWidget):

    def __init__(self, switch_to_register, switch_to_dashboard):
        super().__init__()

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

        register_link.clicked.connect(switch_to_register)
        login_button.clicked.connect(lambda: self.verify_two_factor(switch_to_dashboard))

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


        if username != "Klucznik" or password != "Klucznik":
            QMessageBox.warning(self, "Błąd", "Nieprawidłowa nazwa użytkownika lub hasło.")
            return
        
        self.verify_two_factor()


    def verify_two_factor(self, switch_to_dashboard):
        username = self.username_input.text()

        if username == "":
            QMessageBox.warning(self, "Błąd", "Wpisz nazwę użytkownika.")
            return

        secret_key = "EXAMPLESECRET"
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
                switch_to_dashboard()
            else:
                QMessageBox.warning(self, "Błąd", "Weryfikacja kodu nie powiodła się.")


class RegisterScreen(QWidget):
    def __init__(self, switch_to_login):
        super().__init__()

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

        login_link.clicked.connect(switch_to_login)
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


    def two_factor(self):
        # Generate QR Code
        secret = "otpauth://totp/Klucznik?secret=EXAMPLESECRET&issuer=Klucznik"
        qr = qrcode.QRCode(box_size=10, border=5)
        qr.add_data(secret)
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
            self.parentWidget().parentWidget().show_login_screen()


    def reg_button(self):

        username = self.username_input.text()
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

        if username == "Klucznik":
            QMessageBox.warning(self, "Błąd", "Nazwa użytkownika zajęta.")
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
        
        self.two_factor()


class DashboardScreen(QWidget):
    def __init__(self, switch_to_login):
        super().__init__()

        # Layout
        main_layout = QVBoxLayout()

        # Title
        title = QLabel("Twoje konta")
        title.setStyleSheet("font-size: 24px; font-weight: bold; text-align: center;")
        title.setAlignment(Qt.AlignCenter)

        # Password List
        self.password_list = QListWidget()
        self.password_list.addItem("Przykładowe konto 1")
        self.password_list.addItem("Przykładowe konto 2")

        # Buttons
        add_account_button = QPushButton("Dodaj konto")
        back_to_login_button = QPushButton("Wyloguj się")
        back_to_login_button.clicked.connect(switch_to_login)

        # Assemble Layout
        main_layout.addWidget(title)
        main_layout.addWidget(self.password_list)
        main_layout.addWidget(add_account_button)
        main_layout.addWidget(back_to_login_button)

        self.setLayout(main_layout)


class MainApp(QWidget):

    def __init__(self):
        super().__init__()

        # Stacked Widget
        self.stacked_widget = QStackedWidget()

        # Screens
        self.login_screen = LoginScreen(self.show_register_screen, self.show_dashboard_screen)
        self.register_screen = RegisterScreen(self.show_login_screen)
        self.dashboard_screen = DashboardScreen(self.show_login_screen)

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

    def show_dashboard_screen(self):
        self.stacked_widget.setCurrentWidget(self.dashboard_screen)
 