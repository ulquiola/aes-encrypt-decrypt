package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"flag"
	// "fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const defaultKey = "your_32_byte_key_here_pass@word_" // 32字节密钥
const encryptionMarker = "ENCRYPTED" // 加密标识符

func encryptFile(src, dst string, key []byte) error {
	log.Printf("正在加密文件: %s → %s", src, dst)
	
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// 写入加密标识符
	if _, err := dstFile.Write([]byte(encryptionMarker)); err != nil {
		return err
	}

	// 生成随机IV
	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	// 写入IV到文件头部
	if _, err := dstFile.Write(iv); err != nil {
		return err
	}

	// 创建CTR流加密器
	stream := cipher.NewCTR(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: dstFile}

	// 流式拷贝数据（自动加密）
	if _, err := io.Copy(writer, srcFile); err != nil {
		return err
	}

	log.Printf("加密成功: %s", dst)
	return nil
}

func decryptFile(src, dst string, key []byte) error {
	log.Printf("正在解密文件: %s → %s", src, dst)
	
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// 读取并验证加密标识符
	marker := make([]byte, len(encryptionMarker))
	if _, err := io.ReadFull(srcFile, marker); err != nil {
		return err
	}
	if string(marker) != encryptionMarker {
		log.Printf("文件未加密，跳过: %s", src)
		return nil
	}

	// 读取IV
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(srcFile, iv); err != nil {
		return err
	}

	// 创建CTR流解密器
	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: srcFile}

	// 流式拷贝数据（自动解密）
	if _, err := io.Copy(dstFile, reader); err != nil {
		return err
	}

	log.Printf("解密成功: %s", dst)
	return nil
}

func isFileEncrypted(filepath string) bool {
    file, err := os.Open(filepath)
    if err != nil {
        return false
    }
    defer file.Close()

    marker := make([]byte, len(encryptionMarker))
    if _, err := io.ReadFull(file, marker); err != nil {
        return false
    }
    return string(marker) == encryptionMarker
}

func main() {
	var (
		encryptFlag bool
		decryptFlag bool
		sourceDir   string
		targetDir   string
	)

	flag.BoolVar(&encryptFlag, "encrypt", false, "加密模式")
	flag.BoolVar(&decryptFlag, "decrypt", false, "解密模式")
	flag.StringVar(&sourceDir, "src", "", "源目录路径（加密默认：data，解密默认：encrypt）")
	flag.StringVar(&targetDir, "dst", "", "目标目录路径（加密默认：encrypt，解密默认：decrypt）")
	flag.Parse()
	// 密钥验证
	key := []byte(defaultKey)
	if len(key) != 32 {
		log.Fatalf("密钥长度错误：当前长度 %d（应为32字节）", len(key))
	}

	// 根据模式设置默认路径
	switch {
	case encryptFlag:
		if sourceDir == "" {
			sourceDir = "data"
		}
		if targetDir == "" {
			targetDir = "encrypt"
		}
	case decryptFlag:
		if sourceDir == "" {
			sourceDir = "encrypt"
		}
		if targetDir == "" {
			targetDir = "decrypt"
		}
	default:
		log.Fatal("必须指定加密或解密模式（-encrypt 或 -decrypt）")
	}

	switch {
	case encryptFlag:
		log.Printf("开始加密 %s → %s", sourceDir, targetDir)
		err := filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relPath, err := filepath.Rel(sourceDir, path)
			if err != nil {
				log.Printf("路径解析失败: %s → %v", path, err)
				return err
			}

			if d.IsDir() {
				targetPath := filepath.Join(targetDir, relPath)
				if err := os.MkdirAll(targetPath, 0755); err != nil {
					log.Printf("创建目录 %s 失败: %v", targetPath, err)
					return err
				}
				log.Printf("成功创建目录: %s", targetPath)
				return nil
			}

			targetFile := filepath.Join(targetDir, relPath)
			// 添加检查逻辑
			if _, err := os.Stat(targetFile); err == nil {
				if isFileEncrypted(targetFile) {
					log.Printf("文件已加密，跳过: %s", targetFile)
					return nil
				}
			}
			if err := encryptFile(path, targetFile, key); err != nil {
				log.Printf("加密文件 %s 失败: %v", path, err)
				return err
			}
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("加密完成：目标目录 %s", targetDir)

	case decryptFlag:
		log.Printf("开始解密 %s → %s", sourceDir, targetDir)
		err := filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relPath, err := filepath.Rel(sourceDir, path)
			if err != nil {
				log.Printf("路径解析失败: %s → %v", path, err)
				return err
			}

			if d.IsDir() {
				targetPath := filepath.Join(targetDir, relPath)
				if err := os.MkdirAll(targetPath, 0755); err != nil {
					log.Printf("创建目录 %s 失败: %v", targetPath, err)
					return err
				}
				log.Printf("成功创建目录: %s", targetPath)
				return nil
			}

			targetFile := filepath.Join(targetDir, relPath)
			if err := decryptFile(path, targetFile, key); err != nil {
				log.Printf("解密文件 %s 失败: %v", path, err)
				return err
			}
			return nil
		})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("解密完成：目标目录 %s")
	}
}