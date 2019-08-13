import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.util.Set;

public class GMCA {
    static {
        Security.addProvider(new BouncyCastleProvider());
        BouncyCastleProvider bc = new BouncyCastleProvider();
        Set<Provider.Service> services = bc.getServices();
        for (Provider.Service s:services){
            if (s.toString().toUpperCase().contains("CIPHER")) System.out.println(s.toString());
        }
    }

    public static void main(String[] args) throws Exception {
        genGMCACert();
        genCertWithCaSign();
        testDigitalSign();
        testSM2EcDc();
        testSaveGMKeyStore();

    }

    public static void genGMCACert() throws Exception {
        System.out.println("=============测试生成国密CA根证书=============");
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

        g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

        KeyPair p = g.generateKeyPair();

        PrivateKey privKey = p.getPrivate();
        PublicKey pubKey = p.getPublic();

        System.out.println("CA PrivateKey:" + Base64.toBase64String(privKey.getEncoded()));

        X500Principal iss = new X500Principal("CN=test GM ROOT CA,OU=test,C=CN,S=Guangdong,O=test");

        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(privKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                iss,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - 50000),
                new Date(System.currentTimeMillis() + 50000),
                iss,
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(0xfe))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, "gmca@test.cn"),
                                        new GeneralName(GeneralName.dNSName, "ca.test.cn")
                                }));


        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(pubKey);



        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

        cert = (X509Certificate) fact.generateCertificate(bIn);

        System.out.println("CA Cert:" + Base64.toBase64String(cert.getEncoded()));

        saveFile("CAPrikey", privKey.getEncoded());
        saveFile("CARootCert.cer", cert.getEncoded());
        System.out.println("=============测试生成国密CA根证书=============");
    }


    public static void genCertWithCaSign() throws Exception {
        System.out.println("=============测试国密CA根证书签发国密证书=============");
        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("CAPrikey"));

        
        PrivateKey caPrivateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");

        Certificate caRootCert = certificateFactory.generateCertificate(new FileInputStream("CARootCert.cer"));

        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "BC");

        g.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));

        KeyPair p = g.generateKeyPair();

        PrivateKey privKey = p.getPrivate();
        PublicKey pubKey = p.getPublic();


        ContentSigner sigGen = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(caPrivateKey);
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                (X509Certificate) caRootCert,
                BigInteger.valueOf(new Random().nextInt()),
                new Date(System.currentTimeMillis() - 50000),
                new Date(System.currentTimeMillis() + 50000),
                new X500Principal("CN=TestCert"),
                pubKey).addExtension(new ASN1ObjectIdentifier("2.5.29.15"), true,
                new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.nonRepudiation))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.37"), true,
                        new DERSequence(KeyPurposeId.anyExtendedKeyUsage))
                .addExtension(new ASN1ObjectIdentifier("2.5.29.17"), true,
                        new GeneralNames(new GeneralName[]
                                {
                                        new GeneralName(GeneralName.rfc822Name, "gmca@test.cn"),
                                        new GeneralName(GeneralName.dNSName, "ca.test.cn")
                                }));


        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));

        cert.checkValidity(new Date());

        cert.verify(caRootCert.getPublicKey());

        ByteArrayInputStream bIn = new ByteArrayInputStream(cert.getEncoded());
        CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");

        cert = (X509Certificate) fact.generateCertificate(bIn);

        System.out.println("custCert:" + Base64.toBase64String(cert.getEncoded()));
        System.out.println("custPrivateKey:" + Base64.toBase64String(privKey.getEncoded()));
        saveFile("custCert.cer", cert.getEncoded());
        saveFile("custPrivateKey", privKey.getEncoded());
        System.out.println("=============测试国密CA根证书签发国密证书=============");

    }

    public static void testDigitalSign() throws Exception {
        System.out.println("=============测试国密证书数字签名=============");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("custPrivateKey"));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");

        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("custCert.cer"));

        Signature signature = Signature.getInstance("SM3withSM2", "BC");

        signature.initSign(privateKey);

        String signText = "测试123456test";
        signature.update(signText.getBytes("UTF-8"));

        byte[] digitalsignature = signature.sign();

        System.out.println("signText:" + signText);

        System.out.println("digitalsignature:" + Base64.toBase64String(digitalsignature));

        Signature signature1 = Signature.getInstance("SM3withSM2", "BC");

        signature1.initVerify(certificate.getPublicKey());

        signature1.update(signText.getBytes("UTF-8"));

        boolean result = signature1.verify(digitalsignature);

        System.out.println("verifyResult:" + result);

        Signature signature2 = Signature.getInstance("SM3withSM2", "BC");

        signature2.initVerify(certificate.getPublicKey());

        signature2.update((signText + "exception").getBytes("UTF-8"));

        boolean exceptionResult = signature2.verify(digitalsignature);

        System.out.println("exceptionVerifyResult:" + exceptionResult);

        System.out.println("=============测试国密证书数字签名=============");
    }


    public static void testSM2EcDc() throws Exception {

        System.out.println("=============测试国密SM2加解密=============");

        //从证书获取公钥
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");
        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("custCert.cer"));
        PublicKey publicKey = certificate.getPublicKey();
        //获取加密参数
        BCECPublicKey localECPublicKey = (BCECPublicKey)publicKey;
        ECParameterSpec localECParameterSpec = localECPublicKey.getParameters();
        ECDomainParameters localECDomainParameters = new ECDomainParameters(
                localECParameterSpec.getCurve(), localECParameterSpec.getG(),
                localECParameterSpec.getN());
        ECPublicKeyParameters localECPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(),
                localECDomainParameters);
        //待加密数据
        byte[] ebs = "123sssss测试".getBytes("UTF-8");

        System.out.println("原文:"+new String(ebs));
        //初始化加密引擎
        SM2Engine sm2EncEngine = new SM2Engine();
        sm2EncEngine.init(true, new ParametersWithRandom(localECPublicKeyParameters));
        //加密
        byte[] bs =  sm2EncEngine.processBlock(ebs,0,ebs.length);
        String es = Base64.toBase64String(bs);
        System.out.println("密文:"+es);

        //获取私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("custPrivateKey"));
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //获取解密参数
        BCECPrivateKey sm2PriK = (BCECPrivateKey)privateKey;
        ECParameterSpec ecParameterSpec = sm2PriK.getParameters();
        ECDomainParameters ecDomainParameters = new ECDomainParameters(
                ecParameterSpec.getCurve(), ecParameterSpec.getG(),
                ecParameterSpec.getN());
        ECPrivateKeyParameters localECPrivateKeyParameters = new ECPrivateKeyParameters(
                sm2PriK.getD(), ecDomainParameters);
        //初始化解密引擎
        SM2Engine sm2DcEngine = new SM2Engine();
        sm2EncEngine.init(true, new ParametersWithRandom(localECPublicKeyParameters));
        sm2DcEngine.init(false, localECPrivateKeyParameters);
        bs = Base64.decode(es.getBytes("Utf-8"));
        byte[] b = sm2DcEngine.processBlock(bs,0,bs.length);
        System.out.println("明文:"+new String(b));

        System.out.println("=============测试国密SM2加解密=============");
    }

    public static void testSaveGMKeyStore() throws Exception {
        System.out.println("=============测试国密证书PKCS12 KeyStore存取=============");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(readFile("custPrivateKey"));

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509", "BC");

        Certificate certificate = certificateFactory.generateCertificate(new FileInputStream("custCert.cer"));

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");

        keyStore.load(null, null);

        keyStore.setKeyEntry("test", privateKey, "32145698745632145698745632145698".toCharArray(), new Certificate[]{certificate});

        keyStore.store(new FileOutputStream("cust.pfx"), "32145698745632145698745632145698".toCharArray());

        KeyStore keyStore1 = KeyStore.getInstance("PKCS12", "BC");

        keyStore1.load(new FileInputStream("cust.pfx"), "32145698745632145698745632145698".toCharArray());

        Certificate certificate1 = keyStore1.getCertificate("test");

        PrivateKey privateKey1 = (PrivateKey) keyStore1.getKey("test", "32145698745632145698745632145698".toCharArray());

        System.out.println("公钥证书存取前后对比:" + Arrays.equals(certificate1.getEncoded(), certificate.getEncoded()));

        System.out.println("私钥存取前后对比:" + Arrays.equals(privateKey.getEncoded(), privateKey1.getEncoded()));

        System.out.println("=============测试国密证书PKCS12 KeyStore存取=============");

    }





    public static void saveFile(String path, byte[] data) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(path);
            fileOutputStream.write(data);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    public static byte[] readFile(String path) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(path);
        byte[] bytes = new byte[fileInputStream.available()];
        fileInputStream.read(bytes);
        return bytes;
    }


    public static byte[] getPriKeyByteFromP8(byte[] p8byte) throws Exception {

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(p8byte);

        KeyFactory keyFactory = KeyFactory.getInstance("EC");

        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        ASN1InputStream asn1InputStream = new ASN1InputStream(privateKey.getEncoded());

        ASN1Sequence p8 = (ASN1Sequence) asn1InputStream.readObject();

        ASN1InputStream asn1InputStream1 = new ASN1InputStream(((DEROctetString) p8.getObjectAt(2)).getOctets());

        ASN1Sequence gmPrivateKey =  (ASN1Sequence)asn1InputStream1.readObject();

        byte[] gmPriKeyBytes = ((DEROctetString)gmPrivateKey.getObjectAt(1)).getOctets();

        return gmPriKeyBytes;
    }


}
