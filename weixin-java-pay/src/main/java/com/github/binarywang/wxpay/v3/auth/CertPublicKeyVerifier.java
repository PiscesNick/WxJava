package com.github.binarywang.wxpay.v3.auth;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import me.chanjar.weixin.common.error.WxRuntimeException;

import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * @author: LHQ
 * @date: 2024/11/1 15:35
 * @desc: 替换原平台证书
 */
@Slf4j
@Data
public class CertPublicKeyVerifier implements Verifier{

  private String publicKeyId;
  private PublicKey publicKey;



  public CertPublicKeyVerifier(String publicKeyId, PublicKey publicKey) {
    this.publicKeyId = publicKeyId;
    this.publicKey = publicKey;
  }

  @Override
  public boolean verify(String serialNumber, byte[] message, String signature) {
      if (serialNumber.equals(publicKeyId)) {
        try {
          Signature sign = Signature.getInstance("SHA256withRSA");
          sign.initVerify(publicKey);
          sign.update(message);
          return sign.verify(Base64.getDecoder().decode(signature));
        } catch (NoSuchAlgorithmException e) {
          throw new WxRuntimeException("当前Java环境不支持SHA256withRSA", e);
        } catch (SignatureException e) {
          throw new WxRuntimeException("签名验证过程发生了错误", e);
        } catch (InvalidKeyException e) {
          throw new WxRuntimeException("无效的证书", e);
        }
      }else {
        log.error("证书公钥ID不匹配,serialNumber:{},publicKeyId:{}",serialNumber,publicKeyId);
        return false;
      }
  }

  @Override
  public X509Certificate getValidCertificate() {
    return null;
  }

  @Override
  public String getSerialNumber() {
    return this.publicKeyId;
  }
}
