/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.mavenproject1;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author ant
 */
public class P12KeyContainer {

    public Key privateKey;
    public Certificate certificate;

    public void init(FileInputStream stream, String password) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException 
    {
            Security.addProvider(new BouncyCastleProvider());

        PKCS12KeyStoreSpi.BCPKCS12KeyStore keyStore = new PKCS12KeyStoreSpi.BCPKCS12KeyStore();
        keyStore.engineLoad(stream, password.toCharArray());

        String alias = (String) keyStore.engineAliases().nextElement();
        privateKey = keyStore.engineGetKey(alias, password.toCharArray());

        certificate = keyStore.engineGetCertificate(alias);
    }

    public Boolean tryInit(FileInputStream stream, String password) {
        try {
            init(stream, password);

            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}