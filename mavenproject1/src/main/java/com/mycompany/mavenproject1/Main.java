package com.mycompany.mavenproject1;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.HashMap;
import org.bouncycastle.util.encoders.Hex;

/**
 *
 * @author ant
 */
public class Main {

    private static final String paramErrorMessage = "Incorrect parametrs.\n\nMandatory params:\n key: key container file \n password: password to key container \n in: file to sign \n out: file with singnature\n\nExample:\nkey=keyFile.p12 password=12345 in=message.txt out=message.sign.txt";

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

//mvn install:install–file –Dfile=bcprov-jdk15on-150b20.jar     –DgroupId=org.bouncycastle –DartifactId=bcprov-jdk15on –Dversion=1.50 –Dpackaging=jar -e
//mvn install:install-file -Dfile=MyLibWithSomeClasses_orig.jar -DgroupId=art.test.lib     -DartifactId=artlib -Dpackaging=jar -Dversion=0.0 -e        
              args = new String[]{
                  "key=/home/kuznetsov/Documents/p12.pfx",
                  "password=1",
                  "in=/home/kuznetsov/Documents/text.txt",
                  "out=sign.txt",
                  "debug=true"};
        HashMap<String, String> dic = null;

        try {

            if (args.length < 4) {
                System.out.println(paramErrorMessage);
                return;
            }

            dic = CreateParamHashMap(args);

            if (dic == null || !ValidateParams(dic)) {
                System.out.println(paramErrorMessage);
                return;
            }

            if (!new File(dic.get("key")).exists()) {
                System.out.println("key file not found");
                return;
            }

            if (!new File(dic.get("in")).exists()) {
                System.out.println("message file not found");
                return;
            }

            P12KeyContainer keyContainer = new P12KeyContainer();

            try (FileInputStream stream = new FileInputStream(dic.get("key"))) {
            keyContainer.init(stream, dic.get("password"));
               // if (!keyContainer.tryInit(stream, dic.get("password"))) {
               //     System.out.println("Error while loading key from file container");
              //      return;
             //   }
            }

            Signer signer = new Signer();
            signer.init(keyContainer);

            File file = new File(dic.get("in"));

            char[] cbuf = new char[(int) file.length()];
            try (FileReader stream = new FileReader(file)) {
                stream.read(cbuf);
            }

            byte[] singnature = signer.sign(new String(cbuf).getBytes());
            String singnatureStr = Hex.toHexString(singnature).toUpperCase();

            try (FileWriter wrt = new FileWriter(dic.get("out"))) {
                wrt.write(singnatureStr);
            }

            System.out.println("SuccessMastesr");

        } catch (Exception ex) {
            System.out.println("Error while creating singnature");

            if (dic != null) {

                String debugMode = dic.get("debug");

                if (debugMode != null && Boolean.parseBoolean(debugMode)) {
                    System.out.println("debug mode on\nException:\n" + ex);
                }
            }
        }
    }

    private static HashMap<String, String> CreateParamHashMap(String[] args) {
        try {
            HashMap<String, String> dic = new HashMap();
            for (String str : args) {
                if (str != null && !str.isEmpty()) {

                    str = str.trim();
                    int index = str.indexOf('=');

                    if (index != -1) {
                        dic.put(str.substring(0, index), str.substring(index + 1, str.length()));
                    }
                }
            }

            return dic;
        } catch (Exception ex) {
        }

        return null;
    }

    private static boolean ValidateParams(HashMap<String, String> dic) {
        String value = dic.get("key");
        if (value == null || value.isEmpty()) {
            return false;
        }

        value = dic.get("password");
        if (value == null || value.isEmpty()) {
            return false;
        }

        value = dic.get("out");
        if (value == null || value.isEmpty()) {
            return false;
        }

        value = dic.get("in");
        if (value == null || value.isEmpty()) {
            return false;
        }

        return true;
    }

}