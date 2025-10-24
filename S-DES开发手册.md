# S-DES 加解密工具开发手册

## 系统架构

### 模块结构

sdes_tool/
├── GUI模块 (PyQt5实现)
│   ├── 主窗口类
│   ├── 二进制加解密标签页
│   ├── ASCII加解密标签页
│   └── 暴力破解标签页
├── 加密算法核心模块
│   ├── 置换函数
│   ├── 密钥生成
│   ├── 轮函数
│   ├── 加密函数
│   ├── 解密函数
│   ├── ASCII转换函数
│   └── 暴力破解函数
└── 主程序入口


## 算法详解

### 1. 初始置换和最终置换
python
初始置换表 (8位)

IP = [2, 6, 3, 1, 4, 8, 5, 7]

最终置换表 (逆初始置换)

IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]


### 2. 密钥生成
python
P10置换表 (10位到10位)

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

P8置换表 (10位到8位)

P8 = [6, 3, 7, 4, 8, 5, 10, 9]

生成两个8位子密钥k1和k2

def generate_keys(key):
    # 实现细节...


### 3. 轮函数结构
python
扩展置换表 (4位到8位)

EP = [4, 1, 2, 3, 2, 3, 4, 1]

P4置换表 (4位到4位)

P4 = [2, 4, 3, 1]

S盒定义

S0 = [[1, 0, 3, 2], ...]
S1 = [[0, 1, 2, 3], ...]

def f_k(bits, key):
    # 实现轮函数操作


## 核心函数说明

### 置换函数
python
def permute(input_bits, table):
    """
    通用置换函数
    :param input_bits: 输入位字符串
    :param table: 置换表
    :return: 置换后的位字符串
    """


### 循环左移函数
python
def left_shift(bits, n):
    """
    循环左移操作
    :param bits: 输入位字符串
    :param n: 左移位数
    :return: 移位后的位字符串
    """


### 密钥生成函数
python
def generate_keys(key):
    """
    生成子密钥k1和k2
    :param key: 10位主密钥
    :return: 元组(k1, k2)
    :raises ValueError: 密钥长度不正确时抛出
    """


### 轮函数
python
def f_k(bits, key):
    """
    轮函数实现
    :param bits: 8位输入数据
    :param key: 8位轮密钥
    :return: 8位输出数据
    """


### 加密函数
python
def encrypt(plaintext, key):
    """
    S-DES加密函数
    :param plaintext: 8位明文
    :param key: 10位密钥
    :return: 8位密文
    :raises ValueError: 输入长度不正确时抛出
    """


### 解密函数
python
def decrypt(ciphertext, key):
    """
    S-DES解密函数
    :param ciphertext: 8位密文
    :param key: 10位密钥
    :return: 8位明文
    :raises ValueError: 输入长度不正确时抛出
    """


### ASCII转换函数
python
def ascii_to_binary(text):
    """
    将ASCII字符串转换为二进制字符串
    :param text: ASCII字符串
    :return: 二进制字符串
    """


python
def binary_to_ascii(binary_text):
    """
    将二进制字符串转换为ASCII字符串
    :param binary_text: 二进制字符串
    :return: ASCII字符串
    """


### ASCII加解密函数
python
def encrypt_ascii(plaintext_ascii, key):
    """
    加密ASCII字符串
    :param plaintext_ascii: ASCII明文
    :param key: 10位密钥
    :return: 元组(ASCII密文, 二进制密文)
    """


python
def decrypt_ascii(ciphertext_ascii, key):
    """
    解密密文ASCII字符串
    :param ciphertext_ascii: ASCII密文
    :param key: 10位密钥
    :return: 元组(ASCII明文, 二进制明文)
    """


### 暴力破解函数
python
def brute_force_attack(known_plaintext, known_ciphertext):
    """
    暴力破解S-DES密钥（二进制模式）
    :param known_plaintext: 已知明文(8位二进制)
    :param known_ciphertext: 已知密文(8位二进制)
    :return: 可能密钥列表
    """


python
def brute_force_attack_ascii(known_plaintext_ascii, known_ciphertext_ascii):
    """
    暴力破解S-DES密钥（ASCII模式）
    :param known_plaintext_ascii: 已知明文(ASCII)
    :param known_ciphertext_ascii: 已知密文(ASCII)
    :return: 可能密钥列表
    """


## GUI模块说明

### 主窗口类
python
class SDESGUI(QMainWindow):
    def __init__(self):
        # 初始化UI组件和布局
        
    def initUI(self):
        # 创建和配置所有UI组件
        
    def create_binary_tab(self):
        # 创建二进制加解密标签页
        
    def create_ascii_tab(self):
        # 创建ASCII加解密标签页
        
    def create_brute_force_tab(self):
        # 创建暴力破解标签页
        
    def execute_binary_operation(self):
        # 处理二进制加解密操作
        
    def execute_ascii_operation(self):
        # 处理ASCII加解密操作
        
    def execute_brute_force(self):
        # 处理暴力破解操作
        
    def append_output(self, output_widget, text):
        # 向输出文本框追加文本
        
    def clear_binary(self):
        # 清空二进制标签页
        
    def clear_ascii(self):
        # 清空ASCII标签页
        
    def clear_brute_force(self):
        # 清空暴力破解标签页


## 扩展和自定义

### 修改置换表
所有置换表定义为全局常量，可直接修改：
python
例如修改初始置换表

IP = [1, 3, 5, 7, 2, 4, 6, 8]


### 修改S盒
S盒数据可自定义：
python
S0 = [
    [新的S盒数据],
    # ...
]


### 添加新功能
1. 在GUI中添加新组件
2. 在相应方法中添加处理逻辑
3. 在算法模块中添加相应的函数实现

## 测试和调试

### 单元测试
可编写测试用例验证算法正确性：
python
def test_encryption():
    plaintext = "10101010"
    key = "1010101010"
    expected = "10010100"
    result = encrypt(plaintext, key)
    assert result == expected


### 调试技巧
- 使用输出语句跟踪算法执行流程
- 验证各置换步骤的正确性
- 检查二进制数据的长度和格式

## 性能优化建议

1. **预计算**：对于固定置换表，可预先计算映射关系
2. **位操作优化**：使用整数位操作替代字符串操作
3. **缓存**：对常用密钥的子密钥进行缓存
4. **并行处理**：暴力破解可使用多线程加速

## 常见问题处理

### 输入验证
- 检查二进制字符串长度和格式
- 处理非二进制字符输入

### 错误处理
- 使用try-except块捕获算法异常
- 提供友好的错误提示信息

## 版本历史
- v1.0: 初始版本，实现基本S-DES加解密功能
- v1.1: 添加输入验证和错误处理
- v1.2: 优化GUI布局和用户体验
- v2.0: 添加ASCII加解密和暴力破解功能

## 后续开发计划
1. 支持文件加解密功能
2. 添加多种工作模式（ECB、CBC等）
3. 实现完整的DES算法
4. 添加性能分析和测试工具
5. 支持更多输入格式（十六进制、Base64等）
6. 添加多线程支持，提高暴力破解速度
7. 增加算法可视化，展示加解密过程
