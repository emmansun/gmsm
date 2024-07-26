# PKCS7应用指南
本项目实现 PKCS#7/加密消息语法的子集（[RFC2315](https://www.rfc-editor.org/rfc/rfc2315.html)、[RFC5652](https://www.rfc-editor.org/rfc/rfc5652.html)），以及相应国密支持《GB/T 35275-2017 信息安全技术 SM2密码算法加密签名消息语法规范》。这是 [mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7) 的一个分支，目前[mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7)已经是弃用状态，代码仓库也已经进入存档、只读状态。

## 支持的功能
### 数字信封数据（Enveloped Data）
数字信封数据，使用对称加密算法加密数据，使用非对称加密加密数据密钥。支持的对称加密算法(以及模式)有
* AES128-CBC
* AES192-CBC
* AES256-CBC
* AES128-GCM
* AES192-GCM
* AES256-GCM
* DES-CBC
* 3DES-CBC
* SM4-CBC
* SM4-GCM

支持的非对称加密算法为：
* RSAPKCS1v15，目前尚不支持RSAOAEP
* SM2

#### 主要方法
（是否国密是指OID也使用国密体系）

| 是否国密 | 加密 | 解密（先调用```Parse```） |  
| :--- | :--- | :--- |  
| 否 | Encrypt | Decrypt |  
| 否 | EncryptUsingPSK | DecryptUsingPSK |  
| 是 | EncryptSM | Decrypt |  
| 是 | EncryptCFCA | DecryptCFCA |  
| 是 | EncryptSMUsingPSK | DecryptUsingPSK |  

关于```EncryptSM / EncryptCFCA```的区别，请参考**CFCA互操作性指南**。  
带PSK（Pre-shared key）后缀的方法，其对称加密密钥由调用者提供，而非随机生成。

### 加密数据（Encrypted Data）
加密：对应本项目的```pkcs7.EncryptUsingPSK```和```pkcs7.EncryptSMUsingPSK```方法。  
解密：对应本项目的```pkcs7.DecryptUsingPSK```方法（当然要先调用```pkcs7.Parse```）。

### 签名数据（Signed Data）
签名数据，使用证书对应的私钥进行签名，理论上支持多个签名者，但通常使用场景都是单签。和数字信封数据类似，也分国密和非国密。

#### 创建签名数据
（是否国密是指OID也使用国密体系）

| 是否国密 | 方法 | 默认签名算法 |    
| :--- | :--- | :--- |
| 否 | ```NewSignedData``` | SHA1 |  
| 是 | ```NewSMSignedData``` | SM3 |  

可选步骤：调用```SetDigestAlgorithm```设置想要的签名算法，通常国密不需要修改。    
接着调用```AddSigner```或```AddSignerChain```方法，进行签名；可以通过```SignerInfoConfig.SkipCertificates```指定忽略证书项（最终签名数据中不包含证书项）；  
如果进行Detach签名，则调用```Detach```方法；  
最后调用```Finish```方法，序列化输出结果。  

#### Detach签名
就是外部签名，**被签名数据**不包含在SignedData中（也就是其ContentInfo.Content为空）。

In PKCS#7 SignedData, attached and detached formats are supported… In detached format, data that is signed is not embedded inside the SignedData package instead it is placed at some external location…

可以参考[RFC2315](https://www.rfc-editor.org/rfc/rfc2315.html)的第7章 注3：  
The optional omission of the content field makes it possible to construct "external signatures," for example, without modification to or replication of the content to which the signatures apply. In the case of external signatures, the content being signed would be omitted from the "inner" encapsulated ContentInfo value included in the signed-data content type.

这种外部签名要验签的话，需要先提供**被签名数据**。以下代码片段来自**sign_test.go**中的**testSign**方法：  
```golang
p7, err := Parse(signed)
if err != nil {
	t.Fatalf("test %s/%s/%s: cannot parse signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
}
if testDetach {
  // Detached signature should not contain the content
  // So we should not be able to find the content in the parsed data
  // We should suppliment the content to the parsed data before verifying
	p7.Content = content
}
if !bytes.Equal(content, p7.Content) {
    t.Errorf("test %s/%s/%s: content was not found in the parsed data:\n\tExpected: %s\n\tActual: %s", sigalgroot, sigalginter, sigalgsigner, content, p7.Content)
}
if err := p7.VerifyWithChain(truststore); err != nil {
	t.Errorf("test %s/%s/%s: cannot verify signed data: %s", sigalgroot, sigalginter, sigalgsigner, err)
}
```                    

#### 验证签名
而验证的话，流程如下：
1. 调用```Parse```方法；
2. 如果是Detach签名数据，则手动设置原始数据（参考```testSign```方法）；
3. 如果签名数据中不包含证书项，则手动设置验签证书（参考```TestSkipCertificates```）；
4. 调用```Verify```或```VerifyWithChain```方法。

#### 特殊方法
```DegenerateCertificate```，退化成签名数据中只包含证书，目前没有使用SM2 OID的方法，如果需要可以请求添加。可以参考```TestDegenerateCertificate```和```TestParseSM2CertificateChain```。


### 签名及数字信封数据（Signed and Enveloped Data）
签名和数字信封数据，使用场景较少，有些实现用它来传输私钥（譬如www.gmcert.org）。具体请参考```sign_enveloped_test.go```。

The "signed and enveloped data" content type is a part of the Cryptographic Message Syntax (CMS), which is used in various Internet Standards. However, it's not recommended for use due to several reasons:

1. **Complexity**: The "signed and enveloped data" content type combines two operations - signing and enveloping (encryption). This increases the complexity of the implementation and can lead to potential security vulnerabilities if not handled correctly.

2. **Order of Operations**: The "signed and enveloped data" content type first signs the data and then encrypts it. This means that to verify the signature, the data must first be decrypted. This could potentially expose sensitive data to unauthorized parties before the signature is verified.

3. **Lack of Flexibility**: Combining signing and enveloping into a single operation reduces flexibility. It's often more useful to be able to perform these operations separately, as it allows for more varied use cases.

Instead of using the "signed and enveloped data" content type, it's generally recommended to use separate "signed data" and "enveloped data" content types. This allows the operations to be performed in the order that best suits the application's needs, and also simplifies the implementation.

#### 加密签名流程
1. 调用```NewSignedAndEnvelopedData```或者```NewSMSignedAndEnvelopedData```创建```SignedAndEnvelopedData```数据结构，此过程包含了数据加密过程；
2. 调用```AddSigner```或```AddSignerChain```方法，进行签名；
3. 调用```AddRecipient```方法，用Recipient的公钥加密数据密钥；
4. 最后调用```Finish```方法，序列化输出结果。  

#### 解密验签流程
1. 调用```Parse```方法；
2. 调用```DecryptAndVerify```或者```DecryptAndVerifyOnlyOne```进行解密和验签。
