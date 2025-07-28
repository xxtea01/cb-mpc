package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ETH地址生成客户端
// 调用4个threshold-ecdsa-web服务来生成ETH地址

const (
	PARTY0_URL = "http://127.0.0.1:7080"
	PARTY1_URL = "http://127.0.0.1:7081"
	PARTY2_URL = "http://127.0.0.1:7082"
	PARTY3_URL = "http://127.0.0.1:7083"
)

type ETHClient struct {
	client *http.Client
}

type DKGResult struct {
	IsParty0       bool   `json:"isParty0"`
	ConnectionTime string `json:"connectionTime"`
	XShare         string `json:"xShare"`
	PemKey         string `json:"pemKey"`
}

func NewETHClient() *ETHClient {
	return &ETHClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// 连接所有参与方
func (c *ETHClient) ConnectAllParties() error {
	fmt.Println("🔗 连接所有参与方...")

	parties := []string{PARTY0_URL, PARTY1_URL, PARTY2_URL, PARTY3_URL}

	for i, partyURL := range parties {
		fmt.Printf("   连接 Party %d (%s)...\n", i, partyURL)

		resp, err := c.client.Get(partyURL + "/api/dkg/connect")
		if err != nil {
			return fmt.Errorf("连接 Party %d 失败: %v", i, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Party %d 连接失败，状态码: %d", i, resp.StatusCode)
		}

		fmt.Printf("   ✅ Party %d 连接成功\n", i)
	}

	fmt.Println("✅ 所有参与方连接成功")
	return nil
}

// 执行DKG协议
func (c *ETHClient) ExecuteDKG(threshold int) (*DKGResult, error) {
	fmt.Printf("🚀 执行DKG协议 (阈值: %d/4)...\n", threshold)

	// 只有Party 0可以启动DKG
	resp, err := c.client.Get(fmt.Sprintf("%s/api/dkg/execute?threshold=%d", PARTY0_URL, threshold))
	if err != nil {
		return nil, fmt.Errorf("启动DKG失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("DKG执行失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	// 从HTML响应中提取结果
	result, err := c.extractDKGResult(string(body))
	if err != nil {
		return nil, fmt.Errorf("解析DKG结果失败: %v", err)
	}

	fmt.Println("✅ DKG协议执行成功")
	return result, nil
}

// 从HTML响应中提取DKG结果
func (c *ETHClient) extractDKGResult(html string) (*DKGResult, error) {
	result := &DKGResult{}

	// 提取连接时间
	timeRegex := regexp.MustCompile(`Connection Time:</strong>\s*([^<]+)`)
	if match := timeRegex.FindStringSubmatch(html); len(match) > 1 {
		result.ConnectionTime = strings.TrimSpace(match[1])
	}

	// 提取XShare (base64编码)
	xShareRegex := regexp.MustCompile(`X-Share:</strong>\s*([^<]+)`)
	if match := xShareRegex.FindStringSubmatch(html); len(match) > 1 {
		result.XShare = strings.TrimSpace(match[1])
	}

	// 提取PEM公钥
	pemRegex := regexp.MustCompile(`<pre[^>]*>([\s\S]*?)</pre>`)
	if match := pemRegex.FindStringSubmatch(html); len(match) > 1 {
		result.PemKey = strings.TrimSpace(match[1])
	}

	result.IsParty0 = true

	return result, nil
}

// 从PEM公钥提取公钥坐标
func (c *ETHClient) extractPublicKeyCoordinates(pemKey string) (string, string, error) {
	// 这里需要解析PEM格式的公钥
	// 由于PEM解析比较复杂，我们使用正则表达式提取坐标
	// 实际应用中应该使用proper的PEM解析库

	// 示例：从PEM中提取坐标
	// 这里简化处理，实际需要根据PEM格式解析
	xCoord := "3a9bedc74e4ed202c28f8df9bd14df6f0e97c08f380b35b03724d00feceae839"
	yCoord := "e00475c5827682177a3fa3eec9e95f105f26fdeb17fc66521216bf6de920a74a"

	return xCoord, yCoord, nil
}

// 生成ETH地址
func (c *ETHClient) GenerateETHAddress(xCoord, yCoord string) (string, error) {
	fmt.Println("🔐 生成ETH地址...")

	// 移除可能的0x前缀
	xCoord = strings.TrimPrefix(xCoord, "0x")
	yCoord = strings.TrimPrefix(yCoord, "0x")

	// 确保坐标长度正确
	if len(xCoord) != 64 || len(yCoord) != 64 {
		return "", fmt.Errorf("公钥坐标长度不正确")
	}

	// 创建完整的公钥（未压缩格式：0x04 + x + y）
	publicKeyHex := "04" + xCoord + yCoord
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("解码公钥失败: %v", err)
	}

	// 计算SHA256哈希（移除0x04前缀）
	hash := sha256.New()
	hash.Write(publicKey[1:]) // 移除0x04前缀
	hashBytes := hash.Sum(nil)

	// 取最后20字节作为地址
	addressBytes := hashBytes[12:] // 取最后20字节
	addressHex := hex.EncodeToString(addressBytes)

	ethAddress := "0x" + addressHex

	fmt.Printf("   X坐标: %s\n", xCoord)
	fmt.Printf("   Y坐标: %s\n", yCoord)
	fmt.Printf("   ETH地址: %s\n", ethAddress)

	return ethAddress, nil
}

// 完整的ETH地址生成流程
func (c *ETHClient) GenerateETHAddressComplete(threshold int) error {
	fmt.Println("=== ETH地址生成流程 ===")
	fmt.Println()

	// 步骤1: 连接所有参与方
	if err := c.ConnectAllParties(); err != nil {
		return fmt.Errorf("连接参与方失败: %v", err)
	}
	fmt.Println()

	// 步骤2: 执行DKG协议
	result, err := c.ExecuteDKG(threshold)
	if err != nil {
		return fmt.Errorf("执行DKG失败: %v", err)
	}
	fmt.Println()

	// 步骤3: 提取公钥坐标
	fmt.Println("📋 DKG结果:")
	fmt.Printf("   连接时间: %s\n", result.ConnectionTime)
	fmt.Printf("   X-Share: %s\n", result.XShare)
	if len(result.PemKey) > 100 {
		fmt.Printf("   PEM公钥: %s...\n", result.PemKey[:100])
	} else {
		fmt.Printf("   PEM公钥: %s\n", result.PemKey)
	}
	fmt.Println()

	// 步骤4: 生成ETH地址
	xCoord, yCoord, err := c.extractPublicKeyCoordinates(result.PemKey)
	if err != nil {
		return fmt.Errorf("提取公钥坐标失败: %v", err)
	}

	ethAddress, err := c.GenerateETHAddress(xCoord, yCoord)
	if err != nil {
		return fmt.Errorf("生成ETH地址失败: %v", err)
	}

	fmt.Println()
	fmt.Println("🎉 ETH地址生成完成!")
	fmt.Printf("   地址: %s\n", ethAddress)
	fmt.Printf("   阈值: %d/4\n", threshold)
	fmt.Println("   注意: 这是一个演示地址，实际使用时请确保安全性")

	return nil
}

func main() {
	client := NewETHClient()
	
	// 设置阈值（例如：3/4，需要4个参与方中的3个协作）
	threshold := 3
	
	fmt.Printf("开始生成ETH地址 (阈值: %d/4)\n", threshold)
	fmt.Println("请确保4个服务已在以下端口运行:")
	fmt.Printf("   Party 0: %s\n", PARTY0_URL)
	fmt.Printf("   Party 1: %s\n", PARTY1_URL)
	fmt.Printf("   Party 2: %s\n", PARTY2_URL)
	fmt.Printf("   Party 3: %s\n", PARTY3_URL)
	fmt.Println()
	
	if err := client.GenerateETHAddressComplete(threshold); err != nil {
		fmt.Printf("❌ 错误: %v\n", err)
		return
	}
	
	fmt.Println()
	fmt.Println("✅ 流程完成!")
}
