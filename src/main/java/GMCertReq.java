import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class GMCertReq {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC","BC");
        keyPairGenerator.initialize(new ECNamedCurveGenParameterSpec("sm2p256v1"));
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SM3withSM2").setProvider("BC").build(keyPair.getPrivate());

        PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=test"),keyPair.getPublic());
        PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner);
        System.out.println("国密证书请求:"+Base64.toBase64String(pkcs10CertificationRequest.getEncoded()));
        //验证证书请求
        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().setProvider("BC").build(pkcs10CertificationRequest.getSubjectPublicKeyInfo());
        boolean isValid = pkcs10CertificationRequest.isSignatureValid(verifier);
        System.out.println(isValid);
    }
}
