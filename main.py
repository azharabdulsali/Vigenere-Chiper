import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.uic import loadUi

class MainMenu(QMainWindow):
    def __init__(self):
        super().__init__()
        ui_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "views/VeginereChiper.ui")
        loadUi(ui_path, self)

        self.pushButton_encrypt.clicked.connect(self.encrypt)
        self.pushButton_decrypt.clicked.connect(self.decrypt)
        self.pushButton_clear.clicked.connect(self.clear)

    def encrypt(self):
        plaintext = self.plainTextEdit_plain.text().upper()
        key = self.plainTextEdit_key.text().upper()
        if not key:
            QMessageBox.critical(self, "Error", "Key tidak boleh kosong!")
            return
        encrypted_text = self.vigenere_encrypt(plaintext, key)
        self.plainTextEdit_cipher.setText(encrypted_text)

    def decrypt(self):
        ciphertext = self.plainTextEdit_cipher.text().upper()
        key = self.plainTextEdit_key.text().upper()
        if not key:
            QMessageBox.critical(self, "Error", "Key tidak boleh kosong!")
            return
        decrypted_text = self.vigenere_decrypt(ciphertext, key)
        self.plainTextEdit_plain2.setText(decrypted_text)
        
    def clear(self):
        self.plainTextEdit_plain.clear()
        self.plainTextEdit_key.clear()
        self.plainTextEdit_cipher.clear()
        self.plainTextEdit_plain2.clear()

    def vigenere_encrypt(self, plaintext, key):
        encrypted_text = ""
        key_length = len(key)
        j = 0
        for i in range(len(plaintext)):
            char = plaintext[i]
            if char.isalpha():
                shift = ord(key[j % key_length]) - 65
                encrypted_char = chr(((ord(char) - 65 + shift) % 26) + 65)
                encrypted_text += encrypted_char
                j += 1
            else:
                encrypted_text += char
        return encrypted_text

    def vigenere_decrypt(self, ciphertext, key):
        decrypted_text = ""
        key_length = len(key)
        j = 0
        for i in range(len(ciphertext)):
            char = ciphertext[i]
            if char.isalpha():
                shift = ord(key[j % key_length]) - 65
                decrypted_char = chr(((ord(char) - 65 - shift) % 26) + 65)
                decrypted_text += decrypted_char
                j += 1
            else:
                decrypted_text += char
        return decrypted_text

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainMenu = MainMenu()
    mainMenu.show()
    sys.exit(app.exec_())
