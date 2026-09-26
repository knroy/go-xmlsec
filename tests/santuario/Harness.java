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
 * A command-line face on Apache Santuario and WSS4J for the go-xmlsec
 * differential tests: sign, verify, encrypt and decrypt with Santuario, and
 * process a WS-Security header with WSS4J, one operation per invocation.
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

    /** Unqualified attribute names registered as IDs besides wsu:Id and xml:id. */
    static final java.util.Set<String> ID_ATTRS = new java.util.HashSet<>();

    /** Leading "--id-attr NAME" options, before the command, add to ID_ATTRS. */
    public static void main(String[] a) throws Exception {
        Init.init();
        int opt = 0;
        while (opt + 1 < a.length && a[opt].equals("--id-attr")) {
            ID_ATTRS.add(a[opt + 1]);
            opt += 2;
        }
        a = java.util.Arrays.copyOfRange(a, opt, a.length);
        try {
            switch (a[0]) {
                case "verify" -> verify(a[1], a[2]);
                case "sign-enveloped" -> signEnveloped(a[1], a[2], a[3], a[4], a[5], a[6], a.length > 7 ? a[7] : "");
                case "verify-insecure" -> verifyInsecure(a[1], a[2]);
                case "sign-transform" -> signTransform(a[1], a[2], a[3], a[4], java.util.Arrays.copyOfRange(a, 5, a.length));
                case "sign-detached" ->signDetached(a[1], a[2], a[3], a[4], java.util.Arrays.copyOfRange(a, 5, a.length));
                case "encrypt" -> encrypt(a[1], a[2], a[3], a[4]);
                case "decrypt" -> decrypt(a[1], a[2], a[3]);
                case "encrypt-ecdh" -> encryptECDH(a[1], a[2], a[3], a[4]);
                case "encrypt-kw" -> encryptKW(a[1], a[2], a[3], a[4]);
                case "decrypt-kw" -> decryptKW(a[1], a[2], a[3]);
                case "encrypt-legacy" -> encryptLegacy(a[1], a[2], a[3], a[4], a[5], a[6]);
                case "wss4j-verify" -> wss4jVerify(a[1], a[2], new Parts(a, 3));
                case "wss4j-decrypt" -> wss4jDecrypt(a[1], a[2], a[3], new Parts(a, 4));
                case "wss4j-process" -> wss4jProcess(a[1], a[2], a[3], a[4]);
                case "wss4j-sign-attachments" -> wss4jSignAttachments(a[1], a[2], a[3], a[4], a[5], new Parts(a, 6));
                case "wss4j-encrypt-attachments" -> wss4jEncryptAttachments(a[1], a[2], a[3], a[4], a[5], new Parts(a, 6));
                case "sign-external" -> signExternal(a[1], a[2], a[3], a[4], a[5], a[6], a.length > 7 ? a[7] : "");
                case "verify-external" -> verifyExternal(a[1], a[2], a[3], a[4]);
                case "pkcs7" -> pkcs7(a[1], a[2], java.util.Arrays.copyOfRange(a, 3, a.length));
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
            boolean extra = at.getNamespaceURI() == null && ID_ATTRS.contains(at.getLocalName());
            if (wsu || xml || extra) {
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

    /**
     * verify-insecure doc.xml cert.pem: as verify, with Santuario's secure
     * validation off, which refuses the XSLT transform outright.
     */
    static void verifyInsecure(String docPath, String certPath) throws Exception {
        Document doc = parse(docPath);
        XMLSignature sig = new XMLSignature(first(doc, Constants.SignatureSpecNS, "Signature"), "", false);
        if (!sig.checkSignatureValue(cert(certPath))) {
            throw new IllegalStateException("signature does not verify");
        }
        System.out.println("OK");
    }

    /**
     * sign-transform in.xml key.pem cert.pem out.xml kind arg...: an
     * enveloped RSA-SHA256 signature over "" whose transforms are
     * enveloped-signature, the named one and exclusive C14N. kind is one of
     * xpath EXPR [prefix uri]..., filter2 FILTER EXPR [prefix uri]..., or
     * xslt stylesheet.xml.
     */
    static void signTransform(String in, String keyPath, String certPath, String out, String[] a) throws Exception {
        Document doc = parse(in);
        String exc = Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, exc);
        doc.getDocumentElement().appendChild(sig.getElement());
        Transforms t = new Transforms(doc);
        t.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        switch (a[0]) {
            case "xpath" -> {
                org.apache.xml.security.transforms.params.XPathContainer x =
                    new org.apache.xml.security.transforms.params.XPathContainer(doc);
                x.setXPath(a[1]);
                for (int i = 2; i + 1 < a.length; i += 2) {
                    x.setXPathNamespaceContext(a[i], a[i + 1]);
                }
                t.addTransform(Transforms.TRANSFORM_XPATH, x.getElement());
            }
            case "filter2" -> {
                org.apache.xml.security.transforms.params.XPath2FilterContainer f = switch (a[1]) {
                    case "intersect" -> org.apache.xml.security.transforms.params.XPath2FilterContainer.newInstanceIntersect(doc, a[2]);
                    case "subtract" -> org.apache.xml.security.transforms.params.XPath2FilterContainer.newInstanceSubtract(doc, a[2]);
                    default -> org.apache.xml.security.transforms.params.XPath2FilterContainer.newInstanceUnion(doc, a[2]);
                };
                for (int i = 3; i + 1 < a.length; i += 2) {
                    f.setXPathNamespaceContext(a[i], a[i + 1]);
                }
                t.addTransform(Transforms.TRANSFORM_XPATH2FILTER, f.getElement());
            }
            case "xslt" -> {
                t.setSecureValidation(false); // which refuses XSLT outright
                t.addTransform(Transforms.TRANSFORM_XSLT, (Element) doc.importNode(parse(a[1]).getDocumentElement(), true));
            }
            default -> throw new IllegalArgumentException("unknown transform " + a[0]);
        }
        t.addTransform(exc);
        sig.addDocument("", t, SHA256);
        sig.addKeyInfo(cert(certPath));
        sig.sign(key(keyPath));
        write(doc, out);
    }

    /**
     * sign-enveloped in.xml key.pem cert.pem c14n sigAlg out.xml [uri]: the
     * reference URI is "" unless given, e.g. "#id" for a SAML assertion.
     */
    static void signEnveloped(String in, String keyPath, String certPath, String c14n, String sigAlg, String out, String uri) throws Exception {
        Document doc = parse(in);
        XMLSignature sig = new XMLSignature(doc, "", sigAlg, c14n);
        doc.getDocumentElement().appendChild(sig.getElement());
        Transforms t = new Transforms(doc);
        t.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        t.addTransform(c14n);
        sig.addDocument(uri, t, SHA256);
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
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_OAEP_11, null, SHA256);
        keyCipher.init(XMLCipher.WRAP_MODE, cert(certPath).getPublicKey());
        encryptWith(doc, local, out, sk -> keyCipher.encryptKey(doc, sk, EncryptionConstants.MGF1_SHA256, null));
    }

    /**
     * encrypt-ecdh in.xml cert.pem localName out.xml: AES-128-GCM over the
     * first element with that local name, the session key wrapped by
     * kw-aes128 under a KEK agreed by ECDH-ES with the certificate's EC key
     * and derived by ConcatKDF with SHA-256, the EncryptedKey carried in
     * EncryptedData/ds:KeyInfo.
     */
    static void encryptECDH(String in, String certPath, String local, String out) throws Exception {
        Document doc = parse(in);
        java.security.PublicKey pub = cert(certPath).getPublicKey();
        org.apache.xml.security.encryption.params.ConcatKDFParams kdf =
            org.apache.xml.security.encryption.params.ConcatKDFParams.createBuilder(128, SHA256)
                .algorithmID("0000").partyUInfo("").partyVInfo("").build();
        org.apache.xml.security.encryption.params.KeyAgreementParameters kap =
            org.apache.xml.security.encryption.XMLCipherUtil.constructAgreementParameters(
                EncryptionConstants.ALGO_ID_KEYAGREEMENT_ECDH_ES,
                org.apache.xml.security.encryption.params.KeyAgreementParameters.ActorType.ORIGINATOR,
                kdf, null, pub);
        XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.AES_128_KeyWrap);
        keyCipher.init(XMLCipher.WRAP_MODE, pub);
        encryptWith(doc, local, out, sk -> keyCipher.encryptKey(doc, sk, kap, null));
    }

    /**
     * encrypt-kw in.xml kek.bin localName out.xml: as encrypt-ecdh, the
     * session key wrapped by kw-aes128 or kw-aes256, by the size of the
     * shared KEK in kek.bin.
     */
    static void encryptKW(String in, String kekPath, String local, String out) throws Exception {
        Document doc = parse(in);
        byte[] kek = Files.readAllBytes(Path.of(kekPath));
        XMLCipher keyCipher = XMLCipher.getInstance(kek.length == 16 ? XMLCipher.AES_128_KeyWrap : XMLCipher.AES_256_KeyWrap);
        keyCipher.init(XMLCipher.WRAP_MODE, new javax.crypto.spec.SecretKeySpec(kek, "AES"));
        encryptWith(doc, local, out, sk -> keyCipher.encryptKey(doc, sk));
    }

    interface KeyEncryptor {
        EncryptedKey encrypt(SecretKey sk) throws Exception;
    }

    /**
     * encrypt-legacy in.xml key localName out.xml dataAlg keyAlg: the legacy
     * algorithms go-xmlsec decrypts only. dataAlg is an AES-CBC or
     * tripledes-cbc URI; keyAlg is rsa-1_5 or rsa-oaep-mgf1p (SHA-1 digest,
     * Santuario's default) with key a certificate, or kw-tripledes with key
     * a 24-octet KEK file.
     */
    static void encryptLegacy(String in, String keyPath, String local, String out, String dataAlg, String keyAlg) throws Exception {
        Document doc = parse(in);
        XMLCipher keyCipher = XMLCipher.getInstance(keyAlg);
        if (keyAlg.equals(XMLCipher.TRIPLEDES_KeyWrap)) {
            keyCipher.init(XMLCipher.WRAP_MODE, new javax.crypto.spec.SecretKeySpec(Files.readAllBytes(Path.of(keyPath)), "DESede"));
        } else {
            keyCipher.init(XMLCipher.WRAP_MODE, cert(keyPath).getPublicKey());
        }
        encryptWith(doc, local, out, sk -> keyCipher.encryptKey(doc, sk), dataAlg);
    }

    /** AES-128-GCM over the first element named local, the EncryptedKey in EncryptedData/ds:KeyInfo. */
    static void encryptWith(Document doc, String local, String out, KeyEncryptor enc) throws Exception {
        encryptWith(doc, local, out, enc, XMLCipher.AES_128_GCM);
    }

    /** As encryptWith, under dataAlg, with a fresh session key of its kind and size. */
    static void encryptWith(Document doc, String local, String out, KeyEncryptor enc, String dataAlg) throws Exception {
        boolean des = dataAlg.equals(XMLCipher.TRIPLEDES);
        KeyGenerator kg = KeyGenerator.getInstance(des ? "DESede" : "AES");
        kg.init(des ? 168 : dataAlg.contains("256") ? 256 : dataAlg.contains("192") ? 192 : 128);
        SecretKey sk = kg.generateKey();
        EncryptedKey ek = enc.encrypt(sk);
        XMLCipher dataCipher = XMLCipher.getInstance(dataAlg);
        dataCipher.init(XMLCipher.ENCRYPT_MODE, sk);
        EncryptedData ed = dataCipher.getEncryptedData();
        KeyInfo ki = new KeyInfo(doc);
        ki.add(ek);
        ed.setKeyInfo(ki);
        NodeList l = doc.getElementsByTagNameNS("*", local);
        dataCipher.doFinal(doc, (Element) l.item(0), false);
        write(doc, out);
    }

    /** decrypt-kw in.xml kek.bin out.xml: the first EncryptedData, its key wrapped under the shared KEK. */
    static void decryptKW(String in, String kekPath, String out) throws Exception {
        Document doc = parse(in);
        XMLCipher c = XMLCipher.getInstance();
        c.init(XMLCipher.DECRYPT_MODE, null);
        c.setKEK(new javax.crypto.spec.SecretKeySpec(Files.readAllBytes(Path.of(kekPath)), "AES"));
        c.doFinal(doc, first(doc, EncryptionConstants.EncryptionSpecNS, "EncryptedData"));
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

    /**
     * wss4j-verify soap.xml cert.pem [part...]: processes the wsse:Security
     * header with WSS4J, the WS-Security engine of phase4 and most Java
     * stacks, with Basic Security Profile enforcement left on and the
     * certificate as the only trusted one. Prints each action performed and
     * the wsu:Id or cid: URI of everything a signature covered. Each part is
     * a MIME part file (see Parts) that cid: references resolve to.
     */
    static void wss4jVerify(String soapPath, String certPath, Parts parts) throws Exception {
        org.apache.wss4j.dom.engine.WSSConfig.init();
        Document doc = parse(soapPath);

        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("sender", cert(certPath));
        org.apache.wss4j.common.crypto.Merlin crypto = new org.apache.wss4j.common.crypto.Merlin();
        crypto.setKeyStore(ks);
        crypto.setTrustStore(ks);

        org.apache.wss4j.dom.handler.RequestData data = new org.apache.wss4j.dom.handler.RequestData();
        data.setWssConfig(org.apache.wss4j.dom.engine.WSSConfig.getNewInstance());
        data.setSigVerCrypto(crypto);
        data.setAttachmentCallbackHandler(parts);

        org.apache.wss4j.dom.handler.WSHandlerResult result =
            new org.apache.wss4j.dom.engine.WSSecurityEngine().processSecurityHeader(doc, data);
        if (result == null || result.getResults().isEmpty()) {
            throw new IllegalStateException("no wsse:Security header processed");
        }
        for (org.apache.wss4j.dom.engine.WSSecurityEngineResult r : result.getResults()) {
            int action = (Integer) r.get(org.apache.wss4j.dom.engine.WSSecurityEngineResult.TAG_ACTION);
            System.out.println("action " + action);
            @SuppressWarnings("unchecked")
            java.util.List<org.apache.wss4j.dom.WSDataRef> refs = (java.util.List<org.apache.wss4j.dom.WSDataRef>)
                r.get(org.apache.wss4j.dom.engine.WSSecurityEngineResult.TAG_DATA_REF_URIS);
            if (refs != null) {
                for (org.apache.wss4j.dom.WSDataRef ref : refs) {
                    System.out.println("signed " + ref.getWsuId());
                }
            }
        }
    }

    /**
     * wss4j-decrypt soap.xml key.pem cert.pem [part...]: processes the
     * wsse:Security header with WSS4J holding the recipient's private key,
     * which decrypts every EncryptedData its EncryptedKey's ReferenceList
     * names, then prints the actions performed, each decrypted attachment
     * (see Parts.print) and the decrypted document.
     */
    static void wss4jDecrypt(String soapPath, String keyPath, String certPath, Parts parts) throws Exception {
        org.apache.wss4j.dom.engine.WSSConfig.init();
        Document doc = parse(soapPath);

        org.apache.wss4j.dom.handler.RequestData data = new org.apache.wss4j.dom.handler.RequestData();
        data.setWssConfig(org.apache.wss4j.dom.engine.WSSConfig.getNewInstance());
        data.setDecCrypto(keyStore(keyPath, certPath));
        data.setCallbackHandler(Harness::password);
        data.setAttachmentCallbackHandler(parts);

        org.apache.wss4j.dom.handler.WSHandlerResult result =
            new org.apache.wss4j.dom.engine.WSSecurityEngine().processSecurityHeader(doc, data);
        if (result == null || result.getResults().isEmpty()) {
            throw new IllegalStateException("no wsse:Security header processed");
        }
        for (org.apache.wss4j.dom.engine.WSSecurityEngineResult r : result.getResults()) {
            System.out.println("action " + r.get(org.apache.wss4j.dom.engine.WSSecurityEngineResult.TAG_ACTION));
        }
        parts.print();
        XMLUtils.outputDOM(doc, System.out);
        System.out.println();
    }

    /**
     * wss4j-process soap.xml key.pem cert.pem signer.pem: processes the
     * wsse:Security header with WSS4J holding both the recipient's private
     * key, for decryption, and the signer's certificate as the only trusted
     * one, for verification, with Basic Security Profile enforcement on.
     * WSS4J processes the header in document order, so a header that is not
     * in processing order fails. Prints each action, "signed #id" for each
     * element a signature covered, "decrypted #id" for each EncryptedData
     * decrypted, then the processed document.
     */
    static void wss4jProcess(String soapPath, String keyPath, String certPath, String signerPath) throws Exception {
        org.apache.wss4j.dom.engine.WSSConfig.init();
        Document doc = parse(soapPath);

        java.security.KeyStore trust = java.security.KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("sender", cert(signerPath));
        org.apache.wss4j.common.crypto.Merlin sigCrypto = new org.apache.wss4j.common.crypto.Merlin();
        sigCrypto.setKeyStore(trust);
        sigCrypto.setTrustStore(trust);

        org.apache.wss4j.dom.handler.RequestData data = new org.apache.wss4j.dom.handler.RequestData();
        data.setWssConfig(org.apache.wss4j.dom.engine.WSSConfig.getNewInstance());
        data.setDecCrypto(keyStore(keyPath, certPath));
        data.setSigVerCrypto(sigCrypto);
        data.setCallbackHandler(Harness::password);

        org.apache.wss4j.dom.handler.WSHandlerResult result =
            new org.apache.wss4j.dom.engine.WSSecurityEngine().processSecurityHeader(doc, data);
        if (result == null || result.getResults().isEmpty()) {
            throw new IllegalStateException("no wsse:Security header processed");
        }
        for (org.apache.wss4j.dom.engine.WSSecurityEngineResult r : result.getResults()) {
            int action = (Integer) r.get(org.apache.wss4j.dom.engine.WSSecurityEngineResult.TAG_ACTION);
            System.out.println("action " + action);
            @SuppressWarnings("unchecked")
            java.util.List<org.apache.wss4j.dom.WSDataRef> refs = (java.util.List<org.apache.wss4j.dom.WSDataRef>)
                r.get(org.apache.wss4j.dom.engine.WSSecurityEngineResult.TAG_DATA_REF_URIS);
            if (refs != null) {
                for (org.apache.wss4j.dom.WSDataRef ref : refs) {
                    System.out.println((action == org.apache.wss4j.dom.WSConstants.SIGN ? "signed " : "decrypted ") + ref.getWsuId());
                }
            }
        }
        XMLUtils.outputDOM(doc, System.out);
        System.out.println();
    }

    /**
     * pkcs7 in.der out.der cert.pem...: the JDK's PKCS#7 codec, since WSS4J
     * 4.0.1 has no PKCS7 token (its DOM processor handles X509v3 and
     * PKIPath only). Prints "subject DN" for each certificate in in.der,
     * then writes the certificates as a certs-only SignedData to out.der.
     */
    static void pkcs7(String in, String out, String[] certs) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        for (java.security.cert.Certificate c : cf.generateCertPath(
                new ByteArrayInputStream(Files.readAllBytes(Path.of(in))), "PKCS7").getCertificates()) {
            System.out.println("subject " + ((X509Certificate) c).getSubjectX500Principal().getName());
        }
        java.util.List<X509Certificate> l = new java.util.ArrayList<>();
        for (String p : certs) {
            l.add(cert(p));
        }
        Files.write(Path.of(out), cf.generateCertPath(l).getEncoded("PKCS7"));
    }

    static final char[] PASS = "changeit".toCharArray();

    /** A WSS4J Crypto holding one private key and its certificate, alias "key". */
    static org.apache.wss4j.common.crypto.Merlin keyStore(String keyPath, String certPath) throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("key", key(keyPath), PASS, new java.security.cert.Certificate[] {cert(certPath)});
        org.apache.wss4j.common.crypto.Merlin crypto = new org.apache.wss4j.common.crypto.Merlin();
        crypto.setKeyStore(ks);
        crypto.setTrustStore(ks);
        return crypto;
    }

    static void password(javax.security.auth.callback.Callback[] callbacks) {
        for (javax.security.auth.callback.Callback c : callbacks) {
            ((org.apache.wss4j.common.ext.WSPasswordCallback) c).setPassword(new String(PASS));
        }
    }

    /**
     * wss4j-sign-attachments soap.xml key.pem cert.pem Element|Content
     * out.xml part...: WSS4J signs every part, and nothing else, with
     * RSA-SHA256, SHA-256 digests and a binary security token. Element
     * selects Attachment-Complete-Signature-Transform, Content
     * Attachment-Content-Signature-Transform.
     */
    static void wss4jSignAttachments(String soapPath, String keyPath, String certPath, String modifier, String out, Parts parts)
            throws Exception {
        org.apache.wss4j.dom.engine.WSSConfig.init();
        Document doc = parse(soapPath);
        org.apache.wss4j.dom.message.WSSecHeader hdr = new org.apache.wss4j.dom.message.WSSecHeader(doc);
        hdr.insertSecurityHeader();
        org.apache.wss4j.dom.message.WSSecSignature b = new org.apache.wss4j.dom.message.WSSecSignature(hdr);
        b.setUserInfo("key", new String(PASS));
        b.setKeyIdentifierType(org.apache.wss4j.dom.WSConstants.BST_DIRECT_REFERENCE);
        b.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        b.setDigestAlgo(SHA256);
        b.getParts().add(new org.apache.wss4j.common.WSEncryptionPart("cid:Attachments", modifier));
        b.setAttachmentCallbackHandler(parts);
        b.build(keyStore(keyPath, certPath));
        write(doc, out);
    }

    /**
     * wss4j-encrypt-attachments soap.xml cert.pem Element|Content out.xml
     * outdir part...: WSS4J encrypts every part for the certificate's key,
     * AES-128-GCM under RSA-OAEP (XML Encryption 1.1) with SHA-256 digest and
     * MGF, the EncryptedKey naming the certificate by issuer and serial.
     * Element selects the Attachment-Complete type, Content
     * Attachment-Content-Only. Each encrypted part is written to outdir as a
     * part file named by its Content-ID.
     */
    static void wss4jEncryptAttachments(String soapPath, String certPath, String modifier, String out, String outDir, Parts parts)
            throws Exception {
        org.apache.wss4j.dom.engine.WSSConfig.init();
        Document doc = parse(soapPath);
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("recipient", cert(certPath));
        org.apache.wss4j.common.crypto.Merlin crypto = new org.apache.wss4j.common.crypto.Merlin();
        crypto.setKeyStore(ks);

        org.apache.wss4j.dom.message.WSSecHeader hdr = new org.apache.wss4j.dom.message.WSSecHeader(doc);
        hdr.insertSecurityHeader();
        org.apache.wss4j.dom.message.WSSecEncrypt b = new org.apache.wss4j.dom.message.WSSecEncrypt(hdr);
        b.setUserInfo("recipient");
        b.setKeyIdentifierType(org.apache.wss4j.dom.WSConstants.ISSUER_SERIAL);
        b.setSymmetricEncAlgorithm(org.apache.wss4j.dom.WSConstants.AES_128_GCM);
        b.setKeyEncAlgo(org.apache.wss4j.dom.WSConstants.KEYTRANSPORT_RSAOAEP_XENC11);
        b.setMGFAlgorithm(org.apache.wss4j.dom.WSConstants.MGF_SHA256);
        b.setDigestAlgorithm(SHA256);
        b.getParts().add(new org.apache.wss4j.common.WSEncryptionPart("cid:Attachments", modifier));
        b.setAttachmentCallbackHandler(parts);
        SecretKey sk = org.apache.wss4j.common.util.KeyUtils.getKeyGenerator(org.apache.wss4j.dom.WSConstants.AES_128_GCM).generateKey();
        b.build(crypto, sk);
        doc.normalizeDocument(); // WSS4J leaves prefixes undeclared; this declares them
        write(doc, out);
        for (org.apache.wss4j.common.ext.Attachment r : parts.results) {
            Files.write(Path.of(outDir, r.getId()), Parts.serialize(r));
        }
    }

    /**
     * sign-external in.xml key.pem cert.pem out.xml uri resource [transform]:
     * an RSA-SHA256, exclusive-C14N signature appended to the document
     * element, over one reference to the external uri, with the transform
     * if given. The uri's octets are served from the local file resource by
     * a ResourceResolver: nothing is fetched.
     */
    static void signExternal(String in, String keyPath, String certPath, String out, String uri, String resource, String transform)
            throws Exception {
        Document doc = parse(in);
        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        doc.getDocumentElement().appendChild(sig.getElement());
        sig.addResourceResolver(serving(uri, resource));
        Transforms t = null;
        if (!transform.isEmpty()) {
            t = new Transforms(doc);
            t.addTransform(transform);
        }
        sig.addDocument(uri, t, SHA256);
        sig.addKeyInfo(cert(certPath));
        sig.sign(key(keyPath));
        write(doc, out);
    }

    /** verify-external doc.xml cert.pem uri resource: verify, serving uri from the local file resource. */
    static void verifyExternal(String docPath, String certPath, String uri, String resource) throws Exception {
        Document doc = parse(docPath);
        XMLSignature sig = new XMLSignature(first(doc, Constants.SignatureSpecNS, "Signature"), "", true);
        sig.addResourceResolver(serving(uri, resource));
        if (!sig.checkSignatureValue(cert(certPath))) {
            throw new IllegalStateException("signature does not verify");
        }
        System.out.println("OK");
    }

    /** A resolver that serves exactly uri from a local file, and nothing else. */
    static org.apache.xml.security.utils.resolver.ResourceResolverSpi serving(String uri, String resource) throws Exception {
        byte[] b = Files.readAllBytes(Path.of(resource));
        return new org.apache.xml.security.utils.resolver.ResourceResolverSpi() {
            @Override
            public boolean engineCanResolveURI(org.apache.xml.security.utils.resolver.ResourceResolverContext c) {
                return uri.equals(c.uriToResolve);
            }

            @Override
            public org.apache.xml.security.signature.XMLSignatureInput engineResolveURI(
                    org.apache.xml.security.utils.resolver.ResourceResolverContext c) {
                org.apache.xml.security.signature.XMLSignatureInput in = new org.apache.xml.security.signature.XMLSignatureByteInput(b);
                in.setSourceURI(uri);
                return in;
            }
        };
    }

    /**
     * The attachments of one invocation, each read from a part file: MIME
     * headers, "Name: value" and CRLF each, an empty line, then the body. The
     * Content-ID, without angle brackets, is the attachment ID and the
     * Content-Type its MIME type, as a SOAP stack such as CXF supplies them to
     * WSS4J. Attachments WSS4J hands back (verified, decrypted or encrypted)
     * are kept in results.
     */
    static final class Parts implements javax.security.auth.callback.CallbackHandler {
        final java.util.List<byte[]> files = new java.util.ArrayList<>();
        final java.util.List<org.apache.wss4j.common.ext.Attachment> results = new java.util.ArrayList<>();

        Parts(String[] a, int from) throws Exception {
            for (int i = from; i < a.length; i++) {
                files.add(Files.readAllBytes(Path.of(a[i])));
            }
        }

        /** A fresh attachment per request, since WSS4J consumes its stream. */
        static org.apache.wss4j.common.ext.Attachment attachment(byte[] f) {
            int end = 0;
            while (!(f[end] == '\r' && f[end + 1] == '\n' && f[end + 2] == '\r' && f[end + 3] == '\n')) {
                end++;
            }
            org.apache.wss4j.common.ext.Attachment att = new org.apache.wss4j.common.ext.Attachment();
            for (String line : new String(f, 0, end, java.nio.charset.StandardCharsets.UTF_8).split("\r\n")) {
                int c = line.indexOf(':');
                String name = line.substring(0, c), value = line.substring(c + 1).trim();
                att.addHeader(name, value);
                if (name.equalsIgnoreCase("Content-ID")) {
                    att.setId(value.replaceAll("^<|>$", ""));
                } else if (name.equalsIgnoreCase("Content-Type")) {
                    att.setMimeType(value);
                }
            }
            att.setSourceStream(new ByteArrayInputStream(java.util.Arrays.copyOfRange(f, end + 4, f.length)));
            return att;
        }

        @Override
        public void handle(javax.security.auth.callback.Callback[] callbacks)
                throws javax.security.auth.callback.UnsupportedCallbackException {
            for (javax.security.auth.callback.Callback c : callbacks) {
                if (c instanceof org.apache.wss4j.common.ext.AttachmentRequestCallback r) {
                    java.util.List<org.apache.wss4j.common.ext.Attachment> l = new java.util.ArrayList<>();
                    for (byte[] f : files) {
                        org.apache.wss4j.common.ext.Attachment att = attachment(f);
                        if ("Attachments".equals(r.getAttachmentId()) || att.getId().equals(r.getAttachmentId())) {
                            l.add(att);
                        }
                    }
                    r.setAttachments(l);
                } else if (c instanceof org.apache.wss4j.common.ext.AttachmentResultCallback r) {
                    results.add(r.getAttachment());
                } else {
                    throw new javax.security.auth.callback.UnsupportedCallbackException(c);
                }
            }
        }

        /** Headers in name order, "Name: value" and CRLF each, an empty line, then the body. */
        static byte[] serialize(org.apache.wss4j.common.ext.Attachment att) throws Exception {
            java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
            for (java.util.Map.Entry<String, String> h : new java.util.TreeMap<>(att.getHeaders()).entrySet()) {
                b.write((h.getKey() + ": " + h.getValue().trim() + "\r\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            b.write("\r\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            b.write(att.getSourceStream().readAllBytes());
            return b.toByteArray();
        }

        /** Prints each result as "attachment <id> <base64 of its part file> <mimeType>". */
        void print() throws Exception {
            for (org.apache.wss4j.common.ext.Attachment r : results) {
                System.out.println("attachment " + r.getId() + " "
                    + Base64.getEncoder().encodeToString(serialize(r)) + " " + r.getMimeType());
            }
        }
    }
}
