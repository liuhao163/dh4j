package com.ericliu.encrypt.dh4j;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException {
        DHKeyPari aPari = DHKeyHelper.getInstance().initPartyAKey(1024);
        System.out.println(aPari);


        DHKeyPari bPari = DHKeyHelper.getInstance().initPartyBKey(aPari.getPublicKey());

        String encryptRes = DHKeyHelper.getInstance().encryptString(bPari.getPublicKey(), aPari.getPrivateKey(), "liuhao".getBytes(), HQDHSymmetricalAlgorithm.DES);
        System.out.println("encryptRes is :" + encryptRes);

        String decryptRes = DHKeyHelper.getInstance().decryptString(aPari.getPublicKey(), bPari.getPrivateKey(), encryptRes, HQDHSymmetricalAlgorithm.DES);

        System.out.println("decryptRes is :" + new String(decryptRes));
    }
}
