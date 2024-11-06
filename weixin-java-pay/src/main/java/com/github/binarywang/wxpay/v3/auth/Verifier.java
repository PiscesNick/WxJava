package com.github.binarywang.wxpay.v3.auth;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface Verifier {
  boolean verify(String serialNumber, byte[] message, String signature);


  X509Certificate getValidCertificate();

  PublicKey getPublicKey();
  String getSerialNumber();
}
