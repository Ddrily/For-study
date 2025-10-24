"""
S-DES加密算法扩展版
支持ASCII字符串加解密、暴力破解和密码分析功能
"""
import sys
import itertools
import random
from collections import defaultdict
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                             QGroupBox, QRadioButton, QLineEdit, QPushButton,
                             QTextEdit, QLabel, QWidget, QMessageBox, QTabWidget,
                             QTableWidget, QTableWidgetItem, QHeaderView)
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


# 扩展的分析函数
def analyze_key_uniqueness():
    """分析密钥唯一性：对于随机明密文对，有多少个密钥满足条件"""
    results = []

    # 测试多个随机明文
    test_plaintexts = ['01101100', '11001010', '00110011', '10101010', '01010101']

    for plaintext in test_plaintexts:
        # 使用随机密钥加密
        random_key = bin(random.randint(0, 1023))[2:].zfill(10)
        ciphertext = encrypt(plaintext, random_key)

        # 查找所有能产生相同明密文对的密钥
        matching_keys = brute_force_attack(plaintext, ciphertext)

        results.append({
            'plaintext': plaintext,
            'ciphertext': ciphertext,
            'original_key': random_key,
            'matching_keys': matching_keys,
            'num_keys': len(matching_keys)
        })

    return results


def analyze_encryption_collisions():
    """分析加密碰撞：不同密钥加密同一明文得到相同密文的情况"""
    collision_analysis = defaultdict(list)

    # 选择一个测试明文
    test_plaintext = '01101100'

    # 遍历所有密钥
    for i in range(1024):
        key = bin(i)[2:].zfill(10)
        try:
            ciphertext = encrypt(test_plaintext, key)
            collision_analysis[ciphertext].append(key)
        except:
            continue

    # 统计碰撞情况
    collision_stats = {}
    for ciphertext, keys in collision_analysis.items():
        collision_stats[ciphertext] = len(keys)

    return collision_analysis, collision_stats


def find_key_collisions_for_all_plaintexts():
    """对所有明文分析密钥碰撞情况"""
    collision_results = {}

    # 抽样分析（完整分析需要256×1024次加密，计算量较大）
    sample_plaintexts = [
        '00000000', '11111111', '01010101', '10101010',
        '00110011', '11001100', '00001111', '11110000'
    ]

    for plaintext in sample_plaintexts:
        ciphertext_map = defaultdict(list)

        # 遍历所有密钥
        for i in range(1024):
            key = bin(i)[2:].zfill(10)
            try:
                ciphertext = encrypt(plaintext, key)
                ciphertext_map[ciphertext].append(key)
            except:
                continue

        collision_results[plaintext] = ciphertext_map

    return collision_results


class SDESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-DES加解密工具 - 扩展版')
        self.setGeometry(100, 100, 800, 700)

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
        # 密码分析标签页
        self.analysis_tab = self.create_analysis_tab()

        self.tabs.addTab(self.binary_tab, "二进制加解密")
        self.tabs.addTab(self.ascii_tab, "ASCII加解密")
        self.tabs.addTab(self.brute_force_tab, "暴力破解")
        self.tabs.addTab(self.analysis_tab, "密码分析")

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

    def create_analysis_tab(self):
        """创建密码分析标签页"""
        tab = QWidget()
        layout = QVBoxLayout()

        # 分析类型选择
        analysis_group = QGroupBox("分析类型")
        analysis_layout = QHBoxLayout()

        self.uniqueness_radio = QRadioButton("密钥唯一性分析")
        self.collision_radio = QRadioButton("加密碰撞分析")
        self.comprehensive_radio = QRadioButton("全面碰撞分析")
        self.uniqueness_radio.setChecked(True)

        analysis_layout.addWidget(self.uniqueness_radio)
        analysis_layout.addWidget(self.collision_radio)
        analysis_layout.addWidget(self.comprehensive_radio)
        analysis_group.setLayout(analysis_layout)

        # 按钮区域
        button_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("开始分析")
        self.clear_analysis_btn = QPushButton("清空结果")

        button_layout.addWidget(self.analyze_btn)
        button_layout.addWidget(self.clear_analysis_btn)

        # 结果区域
        result_group = QGroupBox("分析结果")
        result_layout = QVBoxLayout()
        self.analysis_result = QTextEdit()
        self.analysis_result.setReadOnly(True)
        result_layout.addWidget(self.analysis_result)

        # 表格用于显示详细结果
        self.analysis_table = QTableWidget()
        self.analysis_table.setColumnCount(4)
        self.analysis_table.setHorizontalHeaderLabels(["明文", "密文", "密钥数量", "密钥列表"])
        result_layout.addWidget(self.analysis_table)

        result_group.setLayout(result_layout)

        layout.addWidget(analysis_group)
        layout.addLayout(button_layout)
        layout.addWidget(result_group)

        # 连接信号
        self.analyze_btn.clicked.connect(self.perform_analysis)
        self.clear_analysis_btn.clicked.connect(self.clear_analysis)

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

            output = "暴力破解结果:\n"
            output += f"已知明文: {known_plain}\n"
            output += f"已知密文: {known_cipher}\n"
            output += f"模式: {'二进制' if self.binary_mode_bf.isChecked() else 'ASCII'}\n\n"

            if possible_keys:
                output += f"找到 {len(possible_keys)} 个可能的密钥:\n"
                for i, key in enumerate(possible_keys, 1):
                    output += f"密钥{i}: {key} (十进制: {int(key, 2)})\n"

                output += f"\n分析结论:\n"
                output += f"- 对于这个明密文对，存在 {len(possible_keys)} 个可能的密钥\n"
                output += f"- 平均每个明密文对对应约 4 个密钥 (1024/256)\n"
                output += f"- 仅凭一个明密文对无法唯一确定密钥\n"
            else:
                output += "未找到匹配的密钥!\n"
            output += "=" * 50 + "\n"

            self.append_output(self.output_text_bf, output)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"暴力破解过程中发生错误: {str(e)}")

    def perform_analysis(self):
        """执行密码分析"""
        try:
            if self.uniqueness_radio.isChecked():
                self.analyze_key_uniqueness()
            elif self.collision_radio.isChecked():
                self.analyze_encryption_collisions()
            else:
                self.analyze_comprehensive_collisions()

        except Exception as e:
            QMessageBox.critical(self, "分析错误", f"分析过程中发生错误: {str(e)}")

    def analyze_key_uniqueness(self):
        """分析密钥唯一性"""
        self.analysis_result.append("正在进行密钥唯一性分析...")
        QApplication.processEvents()  # 更新界面

        results = analyze_key_uniqueness()

        output = "=== 密钥唯一性分析结果 ===\n\n"
        output += "理论分析:\n"
        output += "- 密钥空间大小: 1024\n"
        output += "- 明文空间大小: 256\n"
        output += "- 密文空间大小: 256\n"
        output += "- 平均每个(明文,密文)对对应的密钥数: ~4\n\n"
        output += "实验验证:\n"

        self.analysis_table.setRowCount(len(results))

        for i, result in enumerate(results):
            output += f"测试 {i + 1}:\n"
            output += f"  明文: {result['plaintext']}\n"
            output += f"  密文: {result['ciphertext']}\n"
            output += f"  原始密钥: {result['original_key']}\n"
            output += f"  匹配密钥数量: {result['num_keys']}\n"
            output += f"  匹配密钥: {', '.join(result['matching_keys'][:5])}"
            if len(result['matching_keys']) > 5:
                output += f" ... (共{result['num_keys']}个)"
            output += "\n\n"

            # 填充表格
            self.analysis_table.setItem(i, 0, QTableWidgetItem(result['plaintext']))
            self.analysis_table.setItem(i, 1, QTableWidgetItem(result['ciphertext']))
            self.analysis_table.setItem(i, 2, QTableWidgetItem(str(result['num_keys'])))
            self.analysis_table.setItem(i, 3, QTableWidgetItem(', '.join(result['matching_keys'][:3] + ['...'])))

        self.analysis_table.resizeColumnsToContents()

        output += "结论:\n"
        output += "1. 对于随机选择的明密文对，通常存在多个密钥满足条件\n"
        output += "2. 这是S-DES算法结构性特征：密钥空间 > 明文空间\n"
        output += "3. 实际安全强度低于理论密钥空间大小\n"

        self.analysis_result.setText(output)

    def analyze_encryption_collisions(self):
        """分析加密碰撞"""
        self.analysis_result.append("正在进行加密碰撞分析...")
        QApplication.processEvents()

        collision_analysis, collision_stats = analyze_encryption_collisions()

        output = "=== 加密碰撞分析结果 ===\n\n"
        output += f"测试明文: 01101100\n"
        output += f"不同密文数量: {len(collision_stats)}\n"
        output += f"理论最大碰撞数: {max(collision_stats.values()) if collision_stats else 0}\n"
        output += f"理论最小碰撞数: {min(collision_stats.values()) if collision_stats else 0}\n\n"

        output += "碰撞分布:\n"
        for ciphertext, count in sorted(collision_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            output += f"密文 {ciphertext}: {count} 个密钥\n"

        # 显示最大碰撞的详细信息
        max_collision = max(collision_stats.items(), key=lambda x: x[1]) if collision_stats else (None, 0)
        if max_collision[0]:
            output += f"\n最大碰撞示例:\n"
            output += f"密文: {max_collision[0]}\n"
            output += f"密钥数量: {max_collision[1]}\n"
            output += f"前5个密钥: {', '.join(collision_analysis[max_collision[0]][:5])}\n"

        output += "\n结论:\n"
        output += "1. 对于任意明文分组，存在不同的密钥加密得到相同密文\n"
        output += "2. 这是加密函数多对一映射的必然结果\n"
        output += "3. 这种现象降低了密码系统的实际安全性\n"

        self.analysis_result.setText(output)

    def analyze_comprehensive_collisions(self):
        """全面碰撞分析"""
        self.analysis_result.append("正在进行全面碰撞分析...")
        QApplication.processEvents()

        results = find_key_collisions_for_all_plaintexts()

        output = "=== 全面碰撞分析结果 ===\n\n"

        for plaintext, ciphertext_map in results.items():
            output += f"明文: {plaintext}\n"
            collision_counts = [len(keys) for keys in ciphertext_map.values()]

            output += f"  不同密文数量: {len(ciphertext_map)}\n"
            output += f"  平均每个密文对应的密钥数: {sum(collision_counts) / len(collision_counts):.2f}\n"
            output += f"  最大碰撞数: {max(collision_counts)}\n"
            output += f"  最小碰撞数: {min(collision_counts)}\n\n"

        output += "最终结论:\n"
        output += "1. 对于大多数明密文对，存在多个密钥满足加密关系\n"
        output += "2. 这是S-DES算法密钥空间大于明文空间的必然结果\n"
        output += "3. 在实际应用中，这意味着仅凭一个明密文对无法唯一确定密钥\n"
        output += "4. 需要多个明密文对才能唯一确定正确的密钥\n"
        output += "5. 这种现象解释了为什么现代密码系统使用更大的分组大小\n"

        self.analysis_result.setText(output)

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

    def clear_analysis(self):
        """清空分析结果"""
        self.analysis_result.clear()
        self.analysis_table.setRowCount(0)


def main():
    app = QApplication(sys.argv)
    window = SDESGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()