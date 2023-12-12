# 参考标准
* 《GB/T 32905-2016 信息安全技术 SM3密码杂凑算法》

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读此标准。

# 概述
SM3密码杂凑算法，或者叫SM3哈希算法，它是一个输出结果为256位（32字节）的哈希算法。在本软件库中，SM3的实现（方法签名）与Go语言中的哈希算法，特别是SHA256保持一致，所以用法也是一样的。具体API文档，包括Example，请参考：[API Document](https://godoc.org/github.com/emmansun/gmsm)。

# 常用用法示例
```go
// 直接使用sm3.Sum方法
func ExampleSum() {
	sum := sm3.Sum([]byte("hello world\n"))
	fmt.Printf("%x", sum)
	// Output: 4cc2036b86431b5d2685a04d289dfe140a36baa854b01cb39fcd6009638e4e7a
}

// 先创建sm3 hash实例，再进行hash计算
func ExampleNew() {
	h := sm3.New()
	h.Write([]byte("hello world\n"))
	fmt.Printf("%x", h.Sum(nil))
	// Output: 4cc2036b86431b5d2685a04d289dfe140a36baa854b01cb39fcd6009638e4e7a
}

// 计算文件内容hash
func ExampleNew_file() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sm3.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x", h.Sum(nil))
}
```

# 性能
请参考[SM3密码杂凑算法性能优化](https://github.com/emmansun/gmsm/wiki/SM3%E6%80%A7%E8%83%BD%E4%BC%98%E5%8C%96)。

