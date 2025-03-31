v1 使用说明：

运行加密：

```bash
go run photos_encrypt.go -mode encrypt -key "password"
```

运行解密：

```bash
go run photos_encrypt.go -mode decrypt -key "password"
```

数据文件夹结构：

```
data/               # 原始文件存放目录
encrypt/            # 加密后文件存放目录
decrypt/            # 解密后文件存放目录
```

v2 使用说明：

```
# 使用默认目录加密
go run main.go -encrypt

# 自定义加密目录
go run main.go -encrypt -src "production_data" -dst "encrypted_prod"

# 自定义解密目录
go run main.go -decrypt -src "custom_encrypt" -dst "recovered_files"
```
路径参数化：

源目录和目标目录通过命令行参数完全可控，支持任意路径替换。
智能路径解析：

使用 filepath.Rel 计算相对路径，确保目录结构在目标路径下精确重建。
兼容性保留：

未指定参数时仍保持原有 data → encrypt → decrypt 的默认行为。
错误处理增强：

路径解析失败时会输出详细错误信息，帮助定位问题