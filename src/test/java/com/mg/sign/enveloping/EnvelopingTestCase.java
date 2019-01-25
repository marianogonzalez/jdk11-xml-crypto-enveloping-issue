/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package com.mg.sign.enveloping;

import static java.lang.String.format;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLObject;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.Test;
import org.w3c.dom.Document;

public class EnvelopingTestCase {


  private static final String ALIAS = "test1";
  private static final String JCE_PASSWORD = "test1234";
  private static String XML_PAYLOAD = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      + "<PurchaseOrder>\n"
      + " <Item number=\"130046593231\">\n"
      + "  <Description>Video Game</Description>\n"
      + "  <Price>10.29</Price>\n"
      + " </Item>\n"
      + " <Buyer id=\"8492340\">\n"
      + "  <Name>My Name</Name>\n"
      + "  <Address>\n"
      + "   <Street>One Network Drive</Street>\n"
      + "   <Town>Burlington</Town>\n"
      + "   <State>MA</State>\n"
      + "   <Country>United States</Country>\n"
      + "   <PostalCode>01803</PostalCode>\n"
      + "  </Address>\n"
      + " </Buyer>\n"
      + "</PurchaseOrder>";

  public static XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

  @Test
  public void enveloping() throws Exception {
    Document document = documentBasedOnThe(XML_PAYLOAD.getBytes());
    document.setStrictErrorChecking(false);

    DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);
    Reference reference = fac.newReference("#data", digestMethod);

    KeyStore keystore = KeyStore.getInstance("JCEKS");
    InputStream keystoreIn = getClass().getResourceAsStream("/jce/keystore.jks");
    assert keystoreIn != null;
    keystore.load(keystoreIn, "mule1234".toCharArray());
    Key key = getPrivateKey(keystore, ALIAS, JCE_PASSWORD);
    KeyStore.Entry keyEntry = getKeyEntry(keystore, ALIAS, JCE_PASSWORD);

    XMLSignature signature = fac.newXMLSignature(getSignedInfo(reference, key),
                                                 getKeyInfo((KeyStore.PrivateKeyEntry) keyEntry),
                                                 getReferencedObjects(document), null, null);

    DOMSignContext signContext = new DOMSignContext(key, document);
    signContext.setDefaultNamespacePrefix("dsig");
    signature.sign(signContext);

    String signed = new String(createXmlUsing(document));
    System.out.println(signed);
  }

  private List<XMLObject> getReferencedObjects(Document document) {
    List<XMLObject> objects = new ArrayList<>();
    XMLStructure structure = new DOMStructure(document.getDocumentElement());
    objects.add(fac.newXMLObject(Collections.singletonList(structure), "data", null, "UTF-8"));
    return objects;
  }

  private javax.xml.crypto.dsig.keyinfo.KeyInfo getKeyInfo(KeyStore.PrivateKeyEntry keyEntry) {
    X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

    KeyInfoFactory kif = fac.getKeyInfoFactory();
    List x509Content = new ArrayList();
    x509Content.add(cert.getSubjectX500Principal().getName());
    x509Content.add(cert);
    X509Data xd = kif.newX509Data(x509Content);
    return kif.newKeyInfo(Collections.singletonList(xd));
  }

  private SignedInfo getSignedInfo(Reference ref, Key key) throws Exception {
    String algorithm;
    if (key.getAlgorithm().toUpperCase().equals("RSA")) {
      algorithm = SignatureMethod.RSA_SHA1;
    } else if (key.getAlgorithm().toUpperCase().equals("DSA")) {
      algorithm = SignatureMethod.DSA_SHA1;
    } else {
      throw new RuntimeException("Supported keys are RSA and DSA, but found " + key.getAlgorithm());
    }

    CanonicalizationMethod canonicalizationMethod =
        fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
    SignatureMethod signatureMethod = fac.newSignatureMethod(algorithm, null);
    return fac.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(ref));
  }

  private KeyStore.Entry getKeyEntry(KeyStore keystore, String alias, String password) {
    try {
      KeyStore.Entry key = keystore.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
      if (key != null) {
        return key;
      } else {
        throw new RuntimeException(format("Key for alias '%s' not found", alias));
      }
    } catch (KeyStoreException | NoSuchAlgorithmException e) {
      throw new RuntimeException(format("Error obtaining Key for alias '%s'", alias));
    } catch (UnrecoverableEntryException e) {
      throw new RuntimeException(format("Wrong password for key '%s'", alias));
    }
  }

  private Key getPrivateKey(KeyStore keystore, String alias, String password) {
    try {
      Key key = keystore.getKey(alias, password.toCharArray());
      if (key != null) {
        return key;
      } else {
        throw new RuntimeException(format("Private key for alias '%s' not found", alias));
      }
    } catch (KeyStoreException | NoSuchAlgorithmException e) {
      throw new RuntimeException(format("Error obtaining private key for alias '%s'", alias));
    } catch (UnrecoverableKeyException e) {
      throw new RuntimeException(format("Wrong password for key '%s'", alias));
    }
  }

  private Document documentBasedOnThe(byte[] xml) {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.parse(new ByteArrayInputStream(xml));
      document.normalize();
      return document;

    } catch (Exception e) {
      throw new RuntimeException("Could not create signed Document", e);
    }
  }

  private byte[] createXmlUsing(Document doc) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      StreamResult result = new StreamResult(bos);
      TransformerFactory transformerFactory = TransformerFactory.newInstance();
      Transformer trans = transformerFactory.newTransformer();
      DOMSource source = new DOMSource(doc);
      trans.setOutputProperty(OutputKeys.INDENT, "no");

      trans.transform(source, result);
      return bos.toByteArray();

    } catch (Exception e) {
      throw new RuntimeException("Could not build signed org.mule.security.encryption.xml", e);
    }
  }

}
