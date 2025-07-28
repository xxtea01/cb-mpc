#!/usr/bin/env python3
"""
ETH地址生成器
从Threshold ECDSA生成的公钥坐标生成ETH地址
"""

import hashlib
import re
from typing import Tuple

def keccak256(data: bytes) -> bytes:
    """计算Keccak256哈希"""
    return hashlib.sha3_256(data).digest()

def public_key_to_eth_address(x_hex: str, y_hex: str) -> str:
    """
    从公钥坐标生成ETH地址
    
    Args:
        x_hex: 公钥x坐标的十六进制字符串
        y_hex: 公钥y坐标的十六进制字符串
    
    Returns:
        ETH地址字符串（0x开头）
    """
    # 移除可能的0x前缀
    x_hex = x_hex.replace('0x', '')
    y_hex = y_hex.replace('0x', '')
    
    # 确保坐标长度正确（32字节 = 64个十六进制字符）
    if len(x_hex) != 64 or len(y_hex) != 64:
        raise ValueError("公钥坐标必须是64个十六进制字符")
    
    # 创建完整的公钥（未压缩格式：0x04 + x + y）
    public_key = bytes.fromhex('04' + x_hex + y_hex)
    
    # 计算Keccak256哈希（移除0x04前缀）
    hash_bytes = keccak256(public_key[1:])
    
    # 取最后20字节作为地址
    address_bytes = hash_bytes[-20:]
    
    # 转换为十六进制字符串
    address_hex = address_bytes.hex()
    
    return f"0x{address_hex}"

def parse_public_key_from_output(output_text: str) -> Tuple[str, str]:
    """
    从系统输出中解析公钥坐标
    
    Args:
        output_text: 包含公钥信息的文本
    
    Returns:
        (x坐标, y坐标)的元组
    """
    # 匹配Point(x: ..., y: ...)格式
    pattern = r'Point\(x:\s*([a-fA-F0-9]+),\s*y:\s*([a-fA-F0-9]+)\)'
    match = re.search(pattern, output_text)
    
    if not match:
        raise ValueError("无法从输出中解析公钥坐标")
    
    x_coord = match.group(1)
    y_coord = match.group(2)
    
    return x_coord, y_coord

def main():
    """主函数 - 演示如何使用"""
    print("=== ETH地址生成器 ===\n")
    
    # 示例：从DKG输出中解析公钥并生成ETH地址
    sample_output = """
    ✅ DKG completed successfully!
    
    Public Key: Point(x: 3a9bedc74e4ed202c28f8df9bd14df6f0e97c08f380b35b03724d00feceae839, 
                      y: e00475c5827682177a3fa3eec9e95f105f26fdeb17fc66521216bf6de920a74a)
    
    Key Shares:
    - Party 0: x_i = Scalar(6410fce8a3c2dee44febb55faa88ab1ce28b0991e352258dad29c9d39095c438)
    - Party 1: x_i = Scalar(4d834db43e1ece41b18deb10dad8cfdbd7be43bb75473506cbcc3ea1b51aebbd)
    """
    
    try:
        # 解析公钥坐标
        x_coord, y_coord = parse_public_key_from_output(sample_output)
        print(f"解析的公钥坐标:")
        print(f"X: {x_coord}")
        print(f"Y: {y_coord}")
        print()
        
        # 生成ETH地址
        eth_address = public_key_to_eth_address(x_coord, y_coord)
        print(f"生成的ETH地址: {eth_address}")
        
    except Exception as e:
        print(f"错误: {e}")
    
    print("\n=== 使用说明 ===")
    print("1. 运行threshold-ecdsa-web系统")
    print("2. 执行DKG协议")
    print("3. 复制公钥信息到下面的代码中")
    print("4. 运行此脚本生成ETH地址")
    
    print("\n=== 手动输入示例 ===")
    print("如果您有公钥坐标，可以直接调用:")
    print("eth_address = public_key_to_eth_address('your_x_coord', 'your_y_coord')")

if __name__ == "__main__":
    main() 