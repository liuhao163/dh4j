package com.ericliu.encrypt.dh4j;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class DHKeyHelper {
    private static DHKeyHelper instance = new DHKeyHelper();

    private final String ALGORITHM = "DH";

    private DHKeyHelper() {
    }

    public static DHKeyHelper getInstance() {
        return instance;
    }

    //初始A的公钥、秘钥
    public DHKeyPari initOriginalKey() throws NoSuchAlgorithmException {
        return initPartyAKey(1024);
    }

    /**
     * 初始化A密钥
     *
     * @param keySize DH key size must be multiple of 64, and can only range from 512 to 2048
     * @return
     * @throws NoSuchAlgorithmException
     */
    public DHKeyPari initPartyAKey(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        return new DHKeyPari(keyPair);
    }

    //根据A的公钥、密钥生成 B公钥 密钥
    public DHKeyPari initPartyBKey(byte[] partyAPublicKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(partyAPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        // 由甲方公钥构建乙方密钥
        DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
        keyPairGenerator.initialize(dhParamSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        return new DHKeyPari(keyPair);
    }

    //根据A公钥+B密钥=本地秘钥 加密
    public byte[] encrypt(byte[] partyAPublicKey, byte[] partyBPrivateKey, byte[] data, HQDHSymmetricalAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secretKey = getSecretKey(partyAPublicKey, partyBPrivateKey, algorithm.getName());

        // 数据加密
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    public String encryptString(byte[] partyAPublicKey, byte[] partyBPrivateKey, byte[] data, HQDHSymmetricalAlgorithm algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        return Base64.encodeBase64String(encrypt(partyAPublicKey, partyBPrivateKey, data, algorithm));
    }


    //根据B公钥+A密钥=本地秘钥 解密
    public byte[] decrypt(byte[] partyBPublicKey, byte[] partyAPrivateKey, byte[] data, HQDHSymmetricalAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secretKey = getSecretKey(partyBPublicKey, partyAPrivateKey, algorithm.getName());

        // 数据加密
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    public String decryptString(byte[] partyBPublicKey, byte[] partyAPrivateKey, String data, HQDHSymmetricalAlgorithm algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        byte[] dataBytes = Base64.decodeBase64(data);
        return new String(decrypt(partyBPublicKey, partyAPrivateKey, dataBytes, algorithm));
    }

    private SecretKey getSecretKey(byte[] publicKey, byte[] privateKey, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);
        Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);

        KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory.getAlgorithm());
        keyAgree.init(priKey);
        keyAgree.doPhase(pubKey, true);

        // 生成本地密钥
        SecretKey secretKey = keyAgree.generateSecret(algorithm);

        return secretKey;
    }

}
