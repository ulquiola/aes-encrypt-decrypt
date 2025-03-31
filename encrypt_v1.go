package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"golang.org/x/crypto/pbkdf2"
)

var (
	mode        string
	password    string
	dataDir     = "data"
	encryptDir  = "encrypt"
	decryptDir  = "decrypt"
)

type FileMetadata struct {
	OriginalPath string `json:"original_path"`
	Hash         string `json:"hash"`
	Salt         string `json:"salt"`
}

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func PKCS7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("无效的PKCS7填充")
	}
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, errors.New("无效的PKCS7填充")
		}
	}
	return data[:length-padding], nil
}

func generateKey(password string) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	key := deriveKey([]byte(password), salt)
	return key, salt, nil
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2.Key(password, salt, 1000000, 32, sha256.New)
}

func main() {
	flag.StringVar(&mode, "mode", "", "操作模式: encrypt/decrypt")
	flag.StringVar(&password, "key", "", "加密密钥")
	flag.Parse()

	if mode == "" || password == "" {
		fmt.Println("必须指定模式和密钥")
		flag.PrintDefaults()
		return
	}

	if err := ensureDirExists(encryptDir); err != nil {
		fmt.Printf("创建加密目录失败: %v\n", err)
		return
	}
	if err := ensureDirExists(decryptDir); err != nil {
		fmt.Printf("创建解密目录失败: %v\n", err)
		return
	}

	switch mode {
	case "encrypt":
		if err := encryptFiles(); err != nil {
			fmt.Printf("加密失败: %v\n", err)
		}
	case "decrypt":
		if err := decryptFiles(); err != nil {
			fmt.Printf("解密失败: %v\n", err)
		}
	default:
		fmt.Println("模式必须为encrypt或decrypt")
	}
}

func ensureDirExists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

func encryptFiles() error {
	return filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			fmt.Printf("跳过目录或错误路径: %s, 错误: %v\n", path, err)
			return nil
		}
		if filepath.Base(path) == "info.json" {
			return nil
		}

		relPath, err := filepath.Rel(dataDir, path)
		if err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("打开文件失败: %s, 错误: %w", path, err)
		}
		defer file.Close()

		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return fmt.Errorf("计算哈希失败: %s, 错误: %w", path, err)
		}
		fileHash := hex.EncodeToString(hash.Sum(nil))
		if _, err := file.Seek(0, 0); err != nil {
			return err
		}

		// 保留原目录结构
		encSubDir := filepath.Join(encryptDir, filepath.Dir(relPath))
		if err := os.MkdirAll(encSubDir, 0755); err != nil {
			return err
		}
		encPath := filepath.Join(encSubDir, fileHash+".enc")
		infoPath := filepath.Join(encSubDir, fileHash+".info.json")

		// 检查加密文件和元数据是否存在
		_, encErr := os.Stat(encPath)
		_, infoErr := os.Stat(infoPath)
		if !os.IsNotExist(encErr) && !os.IsNotExist(infoErr) {
			fmt.Printf("检测到已加密文件，跳过: %s\n", path)
			return nil
		}

		key, salt, err := generateKey(password)
		if err != nil {
			return err
		}

		blockSize := aes.BlockSize
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		iv := make([]byte, blockSize)
		if _, err := rand.Read(iv); err != nil {
			return err
		}

		encFile, err := os.Create(encPath)
		if err != nil {
			return fmt.Errorf("创建加密文件失败: %s, 错误: %w", encPath, err)
		}
		defer encFile.Close()

		// 写入IV
		if _, err := encFile.Write(iv); err != nil {
			encFile.Close()
			os.Remove(encPath)
			return err
		}

		encrypter := cipher.NewCBCEncrypter(block, iv)
		buffer := make([]byte, 0, 1024*4)

		for {
			readBuf := make([]byte, 1024*4)
			n, readErr := file.Read(readBuf)
			if readErr != nil && readErr != io.EOF {
				encFile.Close()
				os.Remove(encPath)
				return readErr
			}

			buffer = append(buffer, readBuf[:n]...)

			for len(buffer) >= blockSize {
				blockData := buffer[:blockSize]
				buffer = buffer[blockSize:]
				ciphertext := make([]byte, blockSize)
				encrypter.CryptBlocks(ciphertext, blockData)
				if _, err := encFile.Write(ciphertext); err != nil {
					encFile.Close()
					os.Remove(encPath)
					return err
				}
			}

			if readErr == io.EOF {
				break
			}
		}

		// 处理剩余数据
		if len(buffer) > 0 {
			padded := PKCS7Padding(buffer, blockSize)
			ciphertext := make([]byte, len(padded))
			encrypter.CryptBlocks(ciphertext, padded)
			if _, err := encFile.Write(ciphertext); err != nil {
				encFile.Close()
				os.Remove(encPath)
				return err
			}
		}

		// 保存元数据
		info := FileMetadata{
			OriginalPath: relPath,
			Hash:         fileHash,
			Salt:         hex.EncodeToString(salt),
		}
		infoBytes, err := json.Marshal(info)
		if err != nil {
			encFile.Close()
			os.Remove(encPath)
			return err
		}
		if err := ioutil.WriteFile(infoPath, infoBytes, 0644); err != nil {
			encFile.Close()
			os.Remove(encPath)
			os.Remove(infoPath)
			return err
		}

		fmt.Printf("加密成功: %s -> %s\n", path, encPath)
		return nil
	})
}

func decryptFiles() error {
	return filepath.WalkDir(encryptDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".enc") {
			return nil
		}

		baseName := strings.TrimSuffix(d.Name(), ".enc")
		infoPath := filepath.Join(filepath.Dir(path), baseName+".info.json")
		infoData, err := ioutil.ReadFile(infoPath)
		if err != nil {
			return fmt.Errorf("读取元数据失败: %s, 错误: %w", infoPath, err)
		}

		var info FileMetadata
		if err := json.Unmarshal(infoData, &info); err != nil {
			return fmt.Errorf("解析元数据失败: %s, 错误: %w", infoPath, err)
		}

		encFile, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("打开加密文件失败: %s, 错误: %w", path, err)
		}
		defer encFile.Close()

		blockSize := aes.BlockSize
		iv := make([]byte, blockSize)
		if _, err := io.ReadFull(encFile, iv); err != nil {
			return fmt.Errorf("读取IV失败: %s, 错误: %w", path, err)
		}

		salt, err := hex.DecodeString(info.Salt)
		if err != nil {
			return fmt.Errorf("解析Salt失败: %s, 错误: %w", path, err)
		}
		key := deriveKey([]byte(password), salt)
		block, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("创建加密块失败: %s, 错误: %w", path, err)
		}
		decrypter := cipher.NewCBCDecrypter(block, iv)

		// 创建解密目录结构
		dstDir := filepath.Join(decryptDir, filepath.Dir(info.OriginalPath))
		if err := os.MkdirAll(dstDir, 0755); err != nil {
			return err
		}
		dstPath := filepath.Join(dstDir, filepath.Base(info.OriginalPath))

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return fmt.Errorf("创建解密文件失败: %s, 错误: %w", dstPath, err)
		}
		defer dstFile.Close()

		var buffer []byte
		for {
			ciphertext := make([]byte, blockSize)
			n, readErr := encFile.Read(ciphertext)
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return fmt.Errorf("读取加密数据失败: %s, 错误: %w", path, readErr)
			}
			if n < blockSize {
				return fmt.Errorf("加密数据不完整: %s", path)
			}

			decrypter.CryptBlocks(ciphertext, ciphertext)
			buffer = append(buffer, ciphertext[:]...)
		}

		decryptedData, err := PKCS7Unpadding(buffer)
		if err != nil {
			return fmt.Errorf("去除填充失败: %s, 错误: %w", path, err)
		}

		// 验证哈希
		hash := sha256.Sum256(decryptedData)
		if hex.EncodeToString(hash[:]) != info.Hash {
			dstFile.Close()
			os.Remove(dstPath)
			return fmt.Errorf("哈希验证失败: %s", path)
		}

		if _, err := dstFile.Write(decryptedData); err != nil {
			dstFile.Close()
			os.Remove(dstPath)
			return err
		}

		fmt.Printf("解密成功: %s -> %s\n", path, dstPath)
		return nil
	})
}