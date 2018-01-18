package com.ericliu.encrypt.dh4j;

import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.util.Arrays;

public class DHKeyPari {
    private byte[] privateKey;
    private String privateKeyString;
    private byte[] publicKey;
    private String publicKeyString;

    public DHKeyPari(KeyPair keyPair) {
        this(keyPair.getPrivate().getEncoded(), keyPair.getPublic().getEncoded());
    }

    public DHKeyPari(byte[] privateKey, byte[] publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.privateKeyString = Base64.encodeBase64String(privateKey);
        this.publicKeyString = Base64.encodeBase64String(publicKey);
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public String getPrivateKeyString() {
        return privateKeyString;
    }

    public String getPublicKeyString() {
        return publicKeyString;
    }

    @Override
    public String toString() {
        return "DHKeyPari{" +
                "privateKeyString='" + privateKeyString + '\'' +
                ", publicKeyString='" + publicKeyString + '\'' +
                '}';
    }
}
