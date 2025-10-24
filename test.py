"""
S-DES加密算法扩展版
支持ASCII字符串加解密和暴力破解功能
"""
import sys
import itertools
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QGroupBox, QRadioButton, QLineEdit, QPushButton,
                             QTextEdit, QLabel, QWidget, QMessageBox, QTabWidget)
from PyQt5.QtCore import Qt

# 置换表
IP = [2, 6, 3, 1, 4, 8, 5, 7]  # 初始
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]  # 最终
EP = [4, 1, 2, 3, 2, 3, 4, 1]  # 扩展
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]  # 密钥置换1
P8 = [6, 3, 7, 4, 8, 5, 10, 9]  # 密钥置换2
P4 = [2, 4, 3, 1]  # 轮内置换

# S盒定义
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]

S1 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]


# 通用置换函数
def permute(input_bits, table):
    return ''.join(input_bits[i - 1] for i in table)


# 循环左移
def left_shift(bits, n):
    return bits[n:] + bits[:n]


# 密钥生成
def generate_keys(key):
    if len(key) != 10:
        raise ValueError("密钥必须是10位二进制字符串")

    key_perm = permute(key, P10)

    left = left_shift(key_perm[:5], 1)
    right = left_shift(key_perm[5:], 1)

    # k1生成
    k1 = permute(left + right, P8)

    left1 = left_shift(left, 2)
    right1 = left_shift(right, 2)

    # k2生成
    k2 = permute(left1 + right1, P8)

    return k1, k2


# 轮函数
def f_k(bits, key):
    left, right = bits[:4], bits[4:]

    expanded = permute(right, EP)

    # 与子密钥异或
    xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, key))

    s0_in = xor_result[:4]
    s1_in = xor_result[4:]

    # S0盒处理
    row0 = int(s0_in[0] + s0_in[3], 2)
    col0 = int(s0_in[1] + s0_in[2], 2)
    s0_out = bin(S0[row0][col0])[2:].zfill(2)

    # S1盒处理
    row1 = int(s1_in[0] + s1_in[3], 2)
    col1 = int(s1_in[1] + s1_in[2], 2)
    s1_out = bin(S1[row1][col1])[2:].zfill(2)

    # P4置换
    s_out = s0_out + s1_out
    p4_result = permute(s_out, P4)

    new_left = ''.join(str(int(a) ^ int(b)) for a, b in zip(left, p4_result))

    return new_left + right


# S_DES加密函数
def encrypt(plaintext, key):
    if len(plaintext) != 8:
        raise ValueError("明文必须是8位二进制字符串")

    # 生成子密钥
    k1, k2 = generate_keys(key)

    # 初始置换
    permuted = permute(plaintext, IP)

    # 第一轮
    round1 = f_k(permuted, k1)

    swapped = round1[4:] + round1[:4]

    # 第二轮
    round2 = f_k(swapped, k2)

    # 最终置换
    ciphertext = permute(round2, IP_INV)

    return ciphertext


# S_DES解密函数
def decrypt(ciphertext, key):
    if len(ciphertext) != 8:
        raise ValueError("密文必须是8位二进制字符串")

    k1, k2 = generate_keys(key)

    permuted = permute(ciphertext, IP)

    # 第一轮
    round1 = f_k(permuted, k2)

    swapped = round1[4:] + round1[:4]

    # 第二轮
    round2 = f_k(swapped, k1)

    # 最终置换
    plaintext = permute(round2, IP_INV)

    return plaintext


# ASCII字符串到二进制转换
def ascii_to_binary(text):
    """将ASCII字符串转换为二进制字符串"""
    binary_result = ""
    for char in text:
        # 将每个字符转换为8位二进制
        binary_char = bin(ord(char))[2:].zfill(8)
        binary_result += binary_char
    return binary_result


def binary_to_ascii(binary_text):
    """将二进制字符串转换为ASCII字符串"""
    ascii_result = ""
    # 每8位一组处理
    for i in range(0, len(binary_text), 8):
        binary_char = binary_text[i:i + 8]
        if len(binary_char) == 8:
            ascii_char = chr(int(binary_char, 2))
            ascii_result += ascii_char
    return ascii_result


# ASCII字符串加密
def encrypt_ascii(plaintext_ascii, key):
    """加密ASCII字符串"""
    # 将明文转换为二进制
    binary_plaintext = ascii_to_binary(plaintext_ascii)

    # 分组加密（每8位一组）
    ciphertext_binary = ""
    for i in range(0, len(binary_plaintext), 8):
        block = binary_plaintext[i:i + 8]
        if len(block) == 8:
            encrypted_block = encrypt(block, key)
            ciphertext_binary += encrypted_block

    # 将二进制密文转换为ASCII（可能是乱码）
    ciphertext_ascii = binary_to_ascii(ciphertext_binary)
    return ciphertext_ascii, ciphertext_binary


# ASCII字符串解密
def decrypt_ascii(ciphertext_ascii, key):
    """解密密文ASCII字符串"""
    # 将密文转换为二进制
    binary_ciphertext = ascii_to_binary(ciphertext_ascii)

    # 分组解密（每8位一组）
    plaintext_binary = ""
    for i in range(0, len(binary_ciphertext), 8):
        block = binary_ciphertext[i:i + 8]
        if len(block) == 8:
            decrypted_block = decrypt(block, key)
            plaintext_binary += decrypted_block

    # 将二进制明文转换为ASCII
    plaintext_ascii = binary_to_ascii(plaintext_binary)
    return plaintext_ascii, plaintext_binary


# 暴力破解函数
def brute_force_attack(known_plaintext, known_ciphertext):
    """
    暴力破解S-DES密钥
    已知明文和对应的密文，尝试所有可能的10位密钥
    """
    possible_keys = []

    # 生成所有可能的10位二进制密钥
    for i in range(1024):  # 2^10 = 1024
        key = bin(i)[2:].zfill(10)

        try:
            # 尝试用当前密钥加密已知明文
            test_ciphertext = encrypt(known_plaintext, key)

            # 如果加密结果匹配已知密文，则找到可能密钥
            if test_ciphertext == known_ciphertext:
                possible_keys.append(key)

        except:
            # 跳过无效密钥
            continue

    return possible_keys


def brute_force_attack_ascii(known_plaintext_ascii, known_ciphertext_ascii):
    """
    暴力破解ASCII版本的S-DES密钥
    """
    possible_keys = []

    # 将已知明文和密文转换为二进制
    binary_plaintext = ascii_to_binary(known_plaintext_ascii)
    binary_ciphertext = ascii_to_binary(known_ciphertext_ascii)

    # 只处理第一个8位块进行匹配（简化计算）
    plaintext_block = binary_plaintext[:8]
    ciphertext_block = binary_ciphertext[:8]

    if len(plaintext_block) == 8 and len(ciphertext_block) == 8:
        for i in range(1024):  # 2^10 = 1024
            key = bin(i)[2:].zfill(10)

            try:
                test_ciphertext = encrypt(plaintext_block, key)
                if test_ciphertext == ciphertext_block:
                    possible_keys.append(key)
            except:
                continue

    return possible_keys


class SDESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-DES加解密工具 - 扩展版')
        self.setGeometry(100, 100, 700, 600)

        # 中央窗口部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        layout = QVBoxLayout()

        # 创建标签页
        self.tabs = QTabWidget()

        # 二进制加解密标签页
        self.binary_tab = self.create_binary_tab()
        # ASCII加解密标签页
        self.ascii_tab = self.create_ascii_tab()
        # 暴力破解标签页
        self.brute_force_tab = self.create_brute_force_tab()

        self.tabs.addTab(self.binary_tab, "二进制加解密")
        self.tabs.addTab(self.ascii_tab, "ASCII加解密")
        self.tabs.addTab(self.brute_force_tab, "暴力破解")

        layout.addWidget(self.tabs)
        central_widget.setLayout(layout)

    def create_binary_tab(self):
        """创建二进制加解密标签页"""
        tab = QWidget()
        layout = QVBoxLayout()

        # 模式选择
        mode_group = QGroupBox("选择模式")
        mode_layout = QHBoxLayout()

        self.encrypt_radio_bin = QRadioButton("加密")
        self.decrypt_radio_bin = QRadioButton("解密")
        self.encrypt_radio_bin.setChecked(True)

        mode_layout.addWidget(self.encrypt_radio_bin)
        mode_layout.addWidget(self.decrypt_radio_bin)
        mode_group.setLayout(mode_layout)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 明文/密文输入
        text_layout = QHBoxLayout()
        text_layout.addWidget(QLabel("输入文本 (8位二进制):"))
        self.text_input_bin = QLineEdit()
        self.text_input_bin.setPlaceholderText("例如: 10101010")
        text_layout.addWidget(self.text_input_bin)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (10位二进制):"))
        self.key_input_bin = QLineEdit()
        self.key_input_bin.setPlaceholderText("例如: 1010101010")
        key_layout.addWidget(self.key_input_bin)

        input_layout.addLayout(text_layout)
        input_layout.addLayout(key_layout)
        input_group.setLayout(input_layout)

        # 按钮区域
        button_layout = QHBoxLayout()
        self.execute_btn_bin = QPushButton("执行")
        self.clear_btn_bin = QPushButton("清空")

        button_layout.addWidget(self.execute_btn_bin)
        button_layout.addWidget(self.clear_btn_bin)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.output_text_bin = QTextEdit()
        self.output_text_bin.setReadOnly(True)
        output_layout.addWidget(self.output_text_bin)
        output_group.setLayout(output_layout)

        # 将所有组件添加到布局
        layout.addWidget(mode_group)
        layout.addWidget(input_group)
        layout.addLayout(button_layout)
        layout.addWidget(output_group)

        # 连接信号和槽
        self.execute_btn_bin.clicked.connect(self.execute_binary_operation)
        self.clear_btn_bin.clicked.connect(self.clear_binary)

        tab.setLayout(layout)
        return tab

    def create_ascii_tab(self):
        """创建ASCII加解密标签页"""
        tab = QWidget()
        layout = QVBoxLayout()

        # 模式选择
        mode_group = QGroupBox("选择模式")
        mode_layout = QHBoxLayout()

        self.encrypt_radio_ascii = QRadioButton("加密")
        self.decrypt_radio_ascii = QRadioButton("解密")
        self.encrypt_radio_ascii.setChecked(True)

        mode_layout.addWidget(self.encrypt_radio_ascii)
        mode_layout.addWidget(self.decrypt_radio_ascii)
        mode_group.setLayout(mode_layout)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 文本输入
        text_layout = QHBoxLayout()
        text_layout.addWidget(QLabel("输入文本:"))
        self.text_input_ascii = QLineEdit()
        self.text_input_ascii.setPlaceholderText("例如: Hello")
        text_layout.addWidget(self.text_input_ascii)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (10位二进制):"))
        self.key_input_ascii = QLineEdit()
        self.key_input_ascii.setPlaceholderText("例如: 1010101010")
        key_layout.addWidget(self.key_input_ascii)

        input_layout.addLayout(text_layout)
        input_layout.addLayout(key_layout)
        input_group.setLayout(input_layout)

        # 按钮区域
        button_layout = QHBoxLayout()
        self.execute_btn_ascii = QPushButton("执行")
        self.clear_btn_ascii = QPushButton("清空")

        button_layout.addWidget(self.execute_btn_ascii)
        button_layout.addWidget(self.clear_btn_ascii)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.output_text_ascii = QTextEdit()
        self.output_text_ascii.setReadOnly(True)
        output_layout.addWidget(self.output_text_ascii)
        output_group.setLayout(output_layout)

        layout.addWidget(mode_group)
        layout.addWidget(input_group)
        layout.addLayout(button_layout)
        layout.addWidget(output_group)

        # 连接信号和槽
        self.execute_btn_ascii.clicked.connect(self.execute_ascii_operation)
        self.clear_btn_ascii.clicked.connect(self.clear_ascii)

        tab.setLayout(layout)
        return tab

    def create_brute_force_tab(self):
        """创建暴力破解标签页"""
        tab = QWidget()
        layout = QVBoxLayout()

        # 输入区域
        input_group = QGroupBox("已知明密文对")
        input_layout = QVBoxLayout()

        # 明文输入
        plain_layout = QHBoxLayout()
        plain_layout.addWidget(QLabel("已知明文:"))
        self.known_plaintext = QLineEdit()
        self.known_plaintext.setPlaceholderText("8位二进制或ASCII字符串")
        plain_layout.addWidget(self.known_plaintext)

        # 密文输入
        cipher_layout = QHBoxLayout()
        cipher_layout.addWidget(QLabel("已知密文:"))
        self.known_ciphertext = QLineEdit()
        self.known_ciphertext.setPlaceholderText("8位二进制或ASCII字符串")
        cipher_layout.addWidget(self.known_ciphertext)

        # 模式选择
        mode_layout = QHBoxLayout()
        self.binary_mode_bf = QRadioButton("二进制模式")
        self.ascii_mode_bf = QRadioButton("ASCII模式")
        self.binary_mode_bf.setChecked(True)
        mode_layout.addWidget(self.binary_mode_bf)
        mode_layout.addWidget(self.ascii_mode_bf)
        mode_layout.addStretch()

        input_layout.addLayout(plain_layout)
        input_layout.addLayout(cipher_layout)
        input_layout.addLayout(mode_layout)
        input_group.setLayout(input_layout)

        # 按钮区域
        button_layout = QHBoxLayout()
        self.attack_btn = QPushButton("开始暴力破解")
        self.clear_btn_bf = QPushButton("清空")

        button_layout.addWidget(self.attack_btn)
        button_layout.addWidget(self.clear_btn_bf)

        # 输出区域
        output_group = QGroupBox("破解结果")
        output_layout = QVBoxLayout()
        self.output_text_bf = QTextEdit()
        self.output_text_bf.setReadOnly(True)
        output_layout.addWidget(self.output_text_bf)
        output_group.setLayout(output_layout)

        layout.addWidget(input_group)
        layout.addLayout(button_layout)
        layout.addWidget(output_group)

        # 连接信号和槽
        self.attack_btn.clicked.connect(self.execute_brute_force)
        self.clear_btn_bf.clicked.connect(self.clear_brute_force)

        tab.setLayout(layout)
        return tab

    def execute_binary_operation(self):
        """执行二进制加解密操作"""
        try:
            input_text = self.text_input_bin.text().strip()
            key = self.key_input_bin.text().strip()

            if not input_text or not key:
                QMessageBox.warning(self, "输入错误", "请输入文本和密钥!")
                return

            if not all(bit in '01' for bit in input_text):
                QMessageBox.warning(self, "输入错误", "文本必须是二进制格式!")
                return

            if not all(bit in '01' for bit in key):
                QMessageBox.warning(self, "输入错误", "密钥必须是二进制格式!")
                return

            if self.encrypt_radio_bin.isChecked():
                if len(input_text) != 8:
                    QMessageBox.warning(self, "输入错误", "明文必须是8位二进制!")
                    return
                if len(key) != 10:
                    QMessageBox.warning(self, "输入错误", "密钥必须是10位二进制!")
                    return

                result = encrypt(input_text, key)
                operation = "加密"
                input_type = "明文"
                output_type = "密文"
            else:
                if len(input_text) != 8:
                    QMessageBox.warning(self, "输入错误", "密文必须是8位二进制!")
                    return
                if len(key) != 10:
                    QMessageBox.warning(self, "输入错误", "密钥必须是10位二进制!")
                    return

                result = decrypt(input_text, key)
                operation = "解密"
                input_type = "密文"
                output_type = "明文"

            output = f"{operation}结果:\n"
            output += f"{input_type}: {input_text}\n"
            output += f"密钥: {key}\n"
            output += f"{output_type}: {result}\n"
            output += "-" * 50

            self.append_output(self.output_text_bin, output)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"处理过程中发生错误: {str(e)}")

    def execute_ascii_operation(self):
        """执行ASCII加解密操作"""
        try:
            input_text = self.text_input_ascii.text().strip()
            key = self.key_input_ascii.text().strip()

            if not input_text or not key:
                QMessageBox.warning(self, "输入错误", "请输入文本和密钥!")
                return

            if not all(bit in '01' for bit in key) or len(key) != 10:
                QMessageBox.warning(self, "输入错误", "密钥必须是10位二进制!")
                return

            if self.encrypt_radio_ascii.isChecked():
                # 加密
                ciphertext_ascii, ciphertext_binary = encrypt_ascii(input_text, key)

                output = "加密结果:\n"
                output += f"明文: {input_text}\n"
                output += f"密钥: {key}\n"
                output += f"密文(ASCII): {ciphertext_ascii}\n"
                output += f"密文(二进制): {ciphertext_binary}\n"
                output += "-" * 50
            else:
                # 解密
                plaintext_ascii, plaintext_binary = decrypt_ascii(input_text, key)

                output = "解密结果:\n"
                output += f"密文: {input_text}\n"
                output += f"密钥: {key}\n"
                output += f"明文(ASCII): {plaintext_ascii}\n"
                output += f"明文(二进制): {plaintext_binary}\n"
                output += "-" * 50

            self.append_output(self.output_text_ascii, output)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"处理过程中发生错误: {str(e)}")

    def execute_brute_force(self):
        """执行暴力破解"""
        try:
            known_plain = self.known_plaintext.text().strip()
            known_cipher = self.known_ciphertext.text().strip()

            if not known_plain or not known_cipher:
                QMessageBox.warning(self, "输入错误", "请输入已知明文和密文!")
                return

            start_time = QApplication.instance().startTimer(0)  # 开始计时

            if self.binary_mode_bf.isChecked():
                # 二进制模式暴力破解
                if len(known_plain) != 8 or len(known_cipher) != 8:
                    QMessageBox.warning(self, "输入错误", "二进制模式下明文和密文都必须是8位!")
                    return

                if not all(bit in '01' for bit in known_plain) or not all(bit in '01' for bit in known_cipher):
                    QMessageBox.warning(self, "输入错误", "二进制模式下必须输入二进制字符串!")
                    return

                possible_keys = brute_force_attack(known_plain, known_cipher)
            else:
                # ASCII模式暴力破解
                possible_keys = brute_force_attack_ascii(known_plain, known_cipher)

            QApplication.instance().killTimer(start_time)  # 结束计时

            output = "暴力破解结果:\n"
            output += f"已知明文: {known_plain}\n"
            output += f"已知密文: {known_cipher}\n"
            output += f"模式: {'二进制' if self.binary_mode_bf.isChecked() else 'ASCII'}\n\n"

            if possible_keys:
                output += f"找到 {len(possible_keys)} 个可能的密钥:\n"
                for i, key in enumerate(possible_keys, 1):
                    output += f"密钥{i}: {key} (十进制: {int(key, 2)})\n"
            else:
                output += "未找到匹配的密钥!\n"
            output += "=" * 50 + "\n"

            self.append_output(self.output_text_bf, output)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"暴力破解过程中发生错误: {str(e)}")

    def append_output(self, output_widget, text):
        """向输出文本框追加文本"""
        current_output = output_widget.toPlainText()
        if current_output:
            output_widget.setText(current_output + "\n" + text)
        else:
            output_widget.setText(text)

    def clear_binary(self):
        self.text_input_bin.clear()
        self.key_input_bin.clear()
        self.output_text_bin.clear()

    def clear_ascii(self):
        self.text_input_ascii.clear()
        self.key_input_ascii.clear()
        self.output_text_ascii.clear()

    def clear_brute_force(self):
        self.known_plaintext.clear()
        self.known_ciphertext.clear()
        self.output_text_bf.clear()


def main():
    app = QApplication(sys.argv)
    window = SDESGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()