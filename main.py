from PyQt5.QtWidgets import QApplication
from interface import MainApp

if __name__ == "__main__":
    import sys

    app = QApplication(sys.argv)
    main_app = MainApp()
    main_app.show()
    sys.exit(app.exec_())