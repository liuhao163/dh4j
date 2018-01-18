# dh4J 
 Diffie-Hellman 的java实现
（原文作者：http://blog.csdn.net/jianggujin/article/details/50537103）
- 客户端生成公钥、私钥
- 服务端通过客户端的公钥生成公钥、私钥
- 服务端将公钥传给客户端
- 加密：客户端私钥+服务端公钥=生成本地私钥，通过约定算法进行加密
- 解密：服务端私钥+客户端公钥=生成本地私钥，通过约定算法解密

# 实际使用中的场景
1. 客户端生成秘钥，并且保存秘钥
2.  发起交换公钥的请求
    1. 客户端将公钥传递给服务器
    2. 服务端根据公钥生成秘钥传递给客户端
3. 客户端：服务端公钥+客户端私钥生成本地秘钥加密参数，发送请求
4. 服务断：服务端私钥+客户端公钥=生成本地私钥，解密参数，做逻辑相应请求

# 客户端
- DHKeyHelper.getInstance().initPartyAKey(1024);生成公钥、私钥

# 服务端
- DHKeyHelper.getInstance().initPartyBKey(aPari.getPublicKey());根据A的公钥生成自己的私钥

# 加密
- DHKeyHelper.getInstance().encryptString(bPari.getPublicKey(), aPari.getPrivateKey(), "liuhao".getBytes(), HQDHSymmetricalAlgorithm.DES);

# 解密
- DHKeyHelper.getInstance().decryptString(aPari.getPublicKey(), bPari.getPrivateKey(), encryptRes, HQDHSymmetricalAlgorithm.DES);

# 注意
- 加密的data都是byte[]在加密完成后要用 Base64.encodeBase64String转成String否则会出错
- 解密的dataString是Base64.encodeBase64String之后的值，在解密前要Base64.decodeBase64(data)

# ISSUES
由于需要客户端和服务端主动交换公钥，出于性能考虑可以采取如下策略：(via:张鹏)
- 服务端被动接受交换公钥请求，在没有接到请求时候认为客户端公钥一直有效
- 客户端采取一段时间窗口内公钥有效的策略保证请求前公钥一直是合法有效的
- 注意客户端和服务端公钥不一致的异常处理（网络波动情况导致交换失败或者交换成功但是没有响应）
        
