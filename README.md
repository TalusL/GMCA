# GMCA

SM2 SM3 X.509 Cert 国密 证书 国密算法 国密证书 生成签发 相关代码 

# sm2国密算法密钥生成
# sm3withsm2国密数字签名示例
# sm2 PKCS#12 国密 keystore

纯java示例 基于bouncycastle 1.59

# 注意   
由于美国出口法律的限制，jdk在1.8.151以下版本对DES算法的密码长度有限制，生成keystore的时候会抛出 非法密钥异常，出现此异常请升级jdk版本到1.8.151+ 或者修改对应策略

# Android系统使用国密的问题
由于某些ROM厂商在Android的framework层内置了Bouncycastle Provider，由于版本不兼容会导致出现错误. 
解决方案为：
在Security.addProvider(),前先使用Security.removeProvider("BC");把内置的Bouncycastle Provider先移除
