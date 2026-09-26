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
                case "sign-detached" -> signDetached(a[1], a[2], a[3], a[4], java.util.Arrays.copyOfRange(a, 5, a.length));
                case "encrypt" -> encrypt(a[1], a[2], a[3], a[4]);
                case "decrypt" -> decrypt(a[1], a[2], a[3]);
                case "wss4j-verify" -> wss4jVerify(a[1], a[2], new Parts(a, 3));
                case "wss4j-decrypt" -> wss4jDecrypt(a[1], a[2], a[3], new Parts(a, 4));
                case "wss4j-sign-attachments" -> wss4jSignAttachments(a[1], a[2], a[3], a[4], a[5], new Parts(a, 6));
                case "wss4j-encrypt-attachments" -> wss4jEncryptAttachments(a[1], a[2], a[3], a[4], a[5], new Parts(a, 6));
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
