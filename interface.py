from PyQt5.QtWidgets import (QApplication, QLabel, QLineEdit, QPushButton, QVBoxLayout,
                             QHBoxLayout, QStackedWidget, QWidget)
from PyQt5.QtCore import Qt


class LoginScreen(QWidget):
    def __init__(self, switch_to_register):
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


class MainApp(QWidget):
    def __init__(self):
        super().__init__()

        # Stacked Widget
        self.stacked_widget = QStackedWidget()

        # Screens
        self.login_screen = LoginScreen(self.show_register_screen)
        self.register_screen = RegisterScreen(self.show_login_screen)

        self.stacked_widget.addWidget(self.login_screen)
        self.stacked_widget.addWidget(self.register_screen)

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