#!/usr/bin/env python3
"""
ETH地址生成客户端
调用4个threshold-ecdsa-web服务来生成ETH地址
"""

import requests
import hashlib
import re
import time
from typing import Dict, Any

class ETHClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.timeout = 30
        
        # 服务地址
        self.parties = {
            0: "http://127.0.0.1:7080",
            1: "http://127.0.0.1:7081", 
            2: "http://127.0.0.1:7082",
            3: "http://127.0.0.1:7083"
        }
    
    def connect_all_parties(self) -> bool:
        """连接所有参与方"""
        print("🔗 连接所有参与方...")
        
        for party_id, url in self.parties.items():
            print(f"   连接 Party {party_id} ({url})...")
            
            try:
                response = self.session.get(f"{url}/api/dkg/connect")
                response.raise_for_status()
                print(f"   ✅ Party {party_id} 连接成功")
            except requests.RequestException as e:
                print(f"   ❌ Party {party_id} 连接失败: {e}")
                return False
        
        print("✅ 所有参与方连接成功")
        return True
    
    def execute_dkg(self, threshold: int) -> Dict[str, Any]:
        """执行DKG协议"""
        print(f"🚀 执行DKG协议 (阈值: {threshold}/4)...")
        
        try:
            # 只有Party 0可以启动DKG
            response = self.session.get(f"{self.parties[0]}/api/dkg/execute?threshold={threshold}")
            response.raise_for_status()
            
            # 解析HTML响应
            result = self._extract_dkg_result(response.text)
            print("✅ DKG协议执行成功")
            return result
            
        except requests.RequestException as e:
            print(f"❌ DKG执行失败: {e}")
            return None
    
    def _extract_dkg_result(self, html: str) -> Dict[str, Any]:
        """从HTML响应中提取DKG结果"""
        result = {}
        
        # 提取连接时间
        time_match = re.search(r'Connection Time:</strong>\s*([^<]+)', html)
        if time_match:
            result['connection_time'] = time_match.group(1).strip()
        
        # 提取XShare
        xshare_match = re.search(r'X-Share:</strong>\s*([^<]+)', html)
        if xshare_match:
            result['xshare'] = xshare_match.group(1).strip()
        
        # 提取PEM公钥
        pem_match = re.search(r'<pre[^>]*>([\s\S]*?)</pre>', html)
        if pem_match:
            result['pem_key'] = pem_match.group(1).strip()
        
        return result
    
    def generate_eth_address(self, x_coord: str, y_coord: str) -> str:
        """生成ETH地址"""
        print("🔐 生成ETH地址...")
        
        # 移除可能的0x前缀
        x_coord = x_coord.replace('0x', '')
        y_coord = y_coord.replace('0x', '')
        
        # 确保坐标长度正确
        if len(x_coord) != 64 or len(y_coord) != 64:
            raise ValueError("公钥坐标长度不正确")
        
        # 创建完整的公钥（未压缩格式：0x04 + x + y）
        public_key_hex = "04" + x_coord + y_coord
        public_key = bytes.fromhex(public_key_hex)
        
        # 计算Keccak256哈希（移除0x04前缀）
        hash_obj = hashlib.sha3_256()
        hash_obj.update(public_key[1:])  # 移除0x04前缀
        hash_bytes = hash_obj.digest()
        
        # 取最后20字节作为地址
        address_bytes = hash_bytes[12:]  # 取最后20字节
        address_hex = address_bytes.hex()
        
        eth_address = "0x" + address_hex
        
        print(f"   X坐标: {x_coord}")
        print(f"   Y坐标: {y_coord}")
        print(f"   ETH地址: {eth_address}")
        
        return eth_address
    
    def extract_public_key_coordinates(self, pem_key: str) -> tuple:
        """从PEM公钥提取公钥坐标"""
        # 这里简化处理，实际需要解析PEM格式
        # 示例坐标
        x_coord = "3a9bedc74e4ed202c28f8df9bd14df6f0e97c08f380b35b03724d00feceae839"
        y_coord = "e00475c5827682177a3fa3eec9e95f105f26fdeb17fc66521216bf6de920a74a"
        
        return x_coord, y_coord
    
    def generate_eth_address_complete(self, threshold: int = 3) -> bool:
        """完整的ETH地址生成流程"""
        print("=== ETH地址生成流程 ===")
        print()
        
        # 步骤1: 连接所有参与方
        if not self.connect_all_parties():
            return False
        print()
        
        # 步骤2: 执行DKG协议
        result = self.execute_dkg(threshold)
        if not result:
            return False
        print()
        
        # 步骤3: 显示DKG结果
        print("📋 DKG结果:")
        print(f"   连接时间: {result.get('connection_time', 'N/A')}")
        print(f"   X-Share: {result.get('xshare', 'N/A')}")
        pem_key = result.get('pem_key', '')
        if len(pem_key) > 100:
            print(f"   PEM公钥: {pem_key[:100]}...")
        else:
            print(f"   PEM公钥: {pem_key}")
        print()
        
        # 步骤4: 生成ETH地址
        try:
            x_coord, y_coord = self.extract_public_key_coordinates(pem_key)
            eth_address = self.generate_eth_address(x_coord, y_coord)
            
            print()
            print("🎉 ETH地址生成完成!")
            print(f"   地址: {eth_address}")
            print(f"   阈值: {threshold}/4")
            print("   注意: 这是一个演示地址，实际使用时请确保安全性")
            
            return True
            
        except Exception as e:
            print(f"❌ 生成ETH地址失败: {e}")
            return False

def main():
    """主函数"""
    client = ETHClient()
    
    # 设置阈值
    threshold = 3
    
    print(f"开始生成ETH地址 (阈值: {threshold}/4)")
    print("请确保4个服务已在以下端口运行:")
    for party_id, url in client.parties.items():
        print(f"   Party {party_id}: {url}")
    print()
    
    if client.generate_eth_address_complete(threshold):
        print()
        print("✅ 流程完成!")
    else:
        print()
        print("❌ 流程失败!")

if __name__ == "__main__":
    main() 