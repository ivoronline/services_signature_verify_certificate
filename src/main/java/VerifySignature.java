import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;

public class VerifySignature {

  //KEY STORE
  static String keyStoreName     = "src/main/resources/PublicKeys.jks";
  static String keyStorePassword = "mypassword";
  static String keyStoreType     = "JKS";
  static String keyAlias         = "clientkeys1";

  //XML FILE
  static String xmlInput1        = "src/main/resources/PersonSigned.xml";
  static String xmlInput2        = "src/main/resources/PersonSignedWithKeyInfo.xml";

  //================================================================================
  // MAIN
  //================================================================================
  public static void main(String[] args) throws Exception {

    //GET DOCUMENT (from XML file)
    DocumentBuilderFactory      documentFactory = DocumentBuilderFactory.newInstance();
                                documentFactory.setNamespaceAware(true);
    Document    document =      documentFactory.newDocumentBuilder().parse(new FileInputStream(xmlInput1));

    //GET PUBLIC KEY (from ClientKeyStore.jks)
    char[]                      password  = keyStorePassword.toCharArray();
    KeyStore                    keyStore  = KeyStore.getInstance(keyStoreType);
                                keyStore.load(new FileInputStream(keyStoreName), password);
  //KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(   password);
    KeyStore.TrustedCertificateEntry keyPair   = (KeyStore.TrustedCertificateEntry) keyStore.getEntry(keyAlias, null);
    PublicKey                   publicKey = keyPair.getTrustedCertificate().getPublicKey();

    //GET SIGNATURE
    NodeList                    nodeList      = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
    Node                        signatureNode = nodeList.item(0);

    //VALIDATE SIGNATURE
    DOMValidateContext          valContext    = new DOMValidateContext(publicKey, signatureNode);
    XMLSignatureFactory         factory       = XMLSignatureFactory.getInstance("DOM");
    XMLSignature                signature     = factory.unmarshalXMLSignature(valContext);
    boolean                     valid         = signature.validate(valContext);

    //DISPLAY RESULT
    System.out.println(valid);

  }

}
