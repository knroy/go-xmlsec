import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * A command-line face on Apache Santuario for the go-xmlsec differential
 * tests: sign, verify, encrypt and decrypt, one operation per invocation.
 * Run with -Dorg.apache.xml.security.ignoreLineBreaks=true so that Santuario
 * adds no formatting whitespace inside ds:SignedInfo; the byte-equality test
 * depends on it.
 *
 * Exit status 0 on success, 1 on a verification or processing failure.
 */
public final class Harness {
    static final String WSU =
        "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    static final String SHA256 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;

    public static void main(String[] a) throws Exception {
        Init.init();
        try {
            switch (a[0]) {
                case "verify" -> verify(a[1], a[2]);
                case "sign-enveloped" -> signEnveloped(a[1], a[2], a[3], a[4], a[5], a[6]);
                case "sign-detached" -> signDetached(a[1], a[2], a[3], a[4], java.util.Arrays.copyOfRange(a, 5, a.length));
                case "encrypt" -> encrypt(a[1], a[2], a[3], a[4]);
                case "decrypt" -> decrypt(a[1], a[2], a[3]);
                default -> throw new IllegalArgumentException("unknown command " + a[0]);
            }
        } catch (Exception e) {
            System.err.println("FAILED: " + e);
            System.exit(1);
        }
    }

    static Document parse(String path) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(Files.readAllBytes(Path.of(path))));
        registerIDs(doc.getDocumentElement());
        return doc;
    }

    /** Santuario resolves "#id" only against attributes registered as IDs. */
    static void registerIDs(Element e) {
        NamedNodeMap attrs = e.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
            Attr at = (Attr) attrs.item(i);
            boolean wsu = WSU.equals(at.getNamespaceURI()) && "Id".equals(at.getLocalName());
            boolean xml = "http://www.w3.org/XML/1998/namespace".equals(at.getNamespaceURI()) && "id".equals(at.getLocalName());
            if (wsu || xml) {
                e.setIdAttributeNode(at, true);
            }
        }
        for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element ce) {
                registerIDs(ce);
            }
        }
    }

    static X509Certificate cert(String path) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Path.of(path))));
    }

    static PrivateKey key(String path) throws Exception {
        String pem = Files.readString(Path.of(path)).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    static void write(Document doc, String path) throws Exception {
        try (OutputStream out = new FileOutputStream(path)) {
            XMLUtils.outputDOM(doc, out);
        }
    }

    static Element first(Document doc, String ns, String local) {
        NodeList l = doc.getElementsByTagNameNS(ns, local);
        if (l.getLength() == 0) {
            throw new IllegalStateException("no " + local);
        }
        return (Element) l.item(0);
    }

    /** verify doc.xml cert.pem: checks the first ds:Signature against the certificate. */
    static void verify(String docPath, String certPath) throws Exception {
        Document doc = parse(docPath);
        XMLSignature sig = new XMLSignature(first(doc, Constants.SignatureSpecNS, "Signature"), "", true);
        if (!sig.checkSignatureValue(cert(certPath))) {
            throw new IllegalStateException("signature does not verify");
        }
        System.out.println("OK");
    }

    /** sign-enveloped in.xml key.pem cert.pem c14n sigAlg out.xml */
    static void signEnveloped(String in, String keyPath, String certPath, String c14n, String sigAlg, String out) throws Exception {
        Document doc = parse(in);
        XMLSignature sig = new XMLSignature(doc, "", sigAlg, c14n);
        doc.getDocumentElement().appendChild(sig.getElement());
        Transforms t = new Transforms(doc);
        t.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        t.addTransform(c14n);
        sig.addDocument("", t, SHA256);
        sig.addKeyInfo(cert(certPath));
        sig.sign(key(keyPath));
        write(doc, out);
    }

    /**
     * sign-detached in.xml key.pem sigAlg out.xml id...: exclusive C14N
     * references to each id, the signature appended to wsse:Security.
     */
    static void signDetached(String in, String keyPath, String sigAlg, String out, String[] ids) throws Exception {
        Document doc = parse(in);
        String exc = Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;
        XMLSignature sig = new XMLSignature(doc, "", sigAlg, exc);
        first(doc, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security")
            .appendChild(sig.getElement());
        for (String id : ids) {
            Transforms t = new Transforms(doc);
            t.addTransform(exc);
            sig.addDocument("#" + id, t, SHA256);
        }
        sig.sign(key(keyPath));
        write(doc, out);
    }

    /**
     * encrypt in.xml cert.pem localName out.xml: AES-128-GCM over the first
     * element with that local name, the session key wrapped by RSA-OAEP
     * (XML Encryption 1.1) with SHA-256 digest and MGF, carried in
     * EncryptedData/ds:KeyInfo.
     */
    static void encrypt(String in, String certPath, String local, String out) throws Exception {
        Document doc = parse(in);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        SecretKey sk = kg.generateKey();

        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP_11, null, SHA256);
        keyCipher.init(XMLCipher.WRAP_MODE, cert(certPath).getPublicKey());
        EncryptedKey ek = keyCipher.encryptKey(doc, sk, EncryptionConstants.MGF1_SHA256, null);

        XMLCipher dataCipher = XMLCipher.getInstance(XMLCipher.AES_128_GCM);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, sk);
        EncryptedData ed = dataCipher.getEncryptedData();
        KeyInfo ki = new KeyInfo(doc);
        ki.add(ek);
        ed.setKeyInfo(ki);

        NodeList l = doc.getElementsByTagNameNS("*", local);
        dataCipher.doFinal(doc, (Element) l.item(0), false);
        write(doc, out);
    }

    /** decrypt in.xml key.pem out.xml: the first EncryptedData, key from its KeyInfo. */
    static void decrypt(String in, String keyPath, String out) throws Exception {
        Document doc = parse(in);
        XMLCipher c = XMLCipher.getInstance();
        c.init(XMLCipher.DECRYPT_MODE, null);
        c.setKEK(key(keyPath));
        c.doFinal(doc, first(doc, EncryptionConstants.EncryptionSpecNS, "EncryptedData"));
        write(doc, out);
    }
}
