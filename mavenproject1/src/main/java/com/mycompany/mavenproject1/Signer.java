/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.mycompany.mavenproject1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

/**
 *
 * @author ant
 */
public class Signer {

    private CMSSignedDataGenerator generator;

    public void init(P12KeyContainer keyContainer) throws CertificateEncodingException, OperatorCreationException, CMSException {

        Security.addProvider(new BouncyCastleProvider());

        List certList = new ArrayList();
        X509Certificate cert = (X509Certificate) keyContainer.certificate;
        certList.add(cert);
        Store certsStore = new JcaCertStore(certList);
        generator = new CMSSignedDataGenerator();

        JcaSimpleSignerInfoGeneratorBuilder genInfo = new JcaSimpleSignerInfoGeneratorBuilder();
        genInfo.setProvider("BC");
        genInfo.setDirectSignature(true);

        SignerInfoGenerator signerInfoGenerator = genInfo.
                build("GOST3411withECGOST3410", (PrivateKey) keyContainer.privateKey, cert);

        generator.addSignerInfoGenerator(signerInfoGenerator);
        generator.addCertificates(certsStore);
    }

    private byte[] ConvertToDER(CMSSignedData cmsSignedData) throws IOException {

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(cmsSignedData.toASN1Structure().toASN1Primitive());
        dOut.close();
        return bOut.toByteArray();
    }

    public byte[] sign(byte[] message) throws UnsupportedEncodingException, CMSException, IOException {

        CMSTypedData msg = new CMSProcessableByteArray(message);
        CMSSignedData cmsSignedData = generator.generate(msg, false);

        return ConvertToDER(cmsSignedData);
    }
}
