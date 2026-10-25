import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';
import 'package:proxypin/network/util/cert/cert_data.dart';
import 'package:proxypin/network/util/cert/emudhra.dart';
import 'package:proxypin/network/util/cert/x509.dart';
import 'package:proxypin/network/util/crypto.dart';

void main() async {
  testEmudhraCaParse();
  testLeafCertificate();
  testChainOrderAndOldMode();
  testSecurityContext();
  await rsaRegression();
  print('emudhra tests passed');
}

/// 证书链解析: 3张证书 + P-384 弱私钥(d<256)
void testEmudhraCaParse() {
  var em = EmudhraCA.instance;
  assert(em.caCert.subject.isNotEmpty);

  //受影响的密钥生成缺陷: d < 256 (全部零字节 + 一个字节)
  var d = _emudhraD();
  assert(d < BigInt.from(256), 'eMudhra private key should be tiny, got $d');
}

BigInt _emudhraD() {
  var keyPem = RegExp('-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----', dotAll: true)
      .firstMatch(EmudhraCA.chainPem)!
      .group(0)!;
  var bytes = base64.decode(keyPem.replaceAll(RegExp(r'-----(BEGIN|END) PRIVATE KEY-----|\s'), ''));
  var pkcs8 = ASN1Parser(Uint8List.fromList(bytes)).nextObject() as ASN1Sequence;
  var sec1 = ASN1Parser((pkcs8.elements![2] as ASN1OctetString).valueBytes).nextObject() as ASN1Sequence;
  var dBytes = (sec1.elements![1] as ASN1OctetString).valueBytes!;
  var d = BigInt.zero;
  for (var b in dBytes) {
    d = (d << 8) | BigInt.from(b);
  }
  return d;
}

/// 叶子证书: 由 eMudhra CA 签发, issuer/公钥正确, ECDSA 签名可用 CA 公钥验证
void testLeafCertificate() {
  var em = EmudhraCA.instance;
  var leafPem = em.leafCertificatePem('example.com');
  var leaf = X509Utils.x509CertificateFromPem(leafPem);

  //SAN
  assert(leaf.subjectAlternativNames!.contains('example.com'), 'sans: ${leaf.subjectAlternativNames}');
  //issuer 与 eMudhra CA subject 完全一致
  var issuer = leaf.issuer;
  var caSubject = em.caCert.subject;
  assert(issuer.length == caSubject.length);
  for (var key in caSubject.keys) {
    assert(issuer[key] == caSubject[key], 'issuer mismatch: $key ${issuer[key]} != ${caSubject[key]}');
  }

  //签名验证: 使用 eMudhra CA 公钥
  assert(_verifyLeafSignature(em, leafPem, _leafSignature(leafPem)));
}

bool _verifyLeafSignature(EmudhraCA em, String leafPem, (BigInt, BigInt) rs) {
  var tbs = _tbsBytes(leafPem);
  var pub = _caPublicKey(em.caCert);
  var signer = ECDSASigner(SHA384Digest());
  signer.init(false, PublicKeyParameter<ECPublicKey>(pub));
  return signer.verifySignature(Uint8List.fromList(tbs), ECSignature(rs.$1, rs.$2));
}

/// 解析出叶子证书的三方签名 DER(r, s)
(BigInt, BigInt) _leafSignature(String pem) {
  var topSeq = _certTopSeq(pem);
  var sigBit = topSeq.elements![2] as ASN1BitString;
  var sigSeq = ASN1Parser(sigBit.stringValues as Uint8List).nextObject() as ASN1Sequence;
  var r = (sigSeq.elements![0] as ASN1Integer).integer!;
  var s = (sigSeq.elements![1] as ASN1Integer).integer!;
  return (r, s);
}

/// 从 EM OV TLS CA - G3C 证书中提取 EC 公钥
ECPublicKey _caPublicKey(X509CertificateData caCert) {
  var certPem = RegExp('-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', dotAll: true)
      .allMatches(EmudhraCA.chainPem)
      .first
      .group(0)!;
  assert(X509Utils.x509CertificateFromPem(certPem).subject['2.5.4.3'] == caCert.subject['2.5.4.3']);
  var topSeq = _certTopSeq(certPem);
  var tbs = topSeq.elements![0] as ASN1Sequence;
  var spki = tbs.elements![6] as ASN1Sequence;
  var bitString = spki.elements![1] as ASN1BitString;
  var pointBytes = bitString.stringValues as Uint8List; //0x04 || X || Y
  var params = ECDomainParameters('secp384r1');
  var point = params.curve.decodePoint(pointBytes)!;
  return ECPublicKey(point, params);
}

ASN1Sequence _certTopSeq(String pem) {
  var bytes = base64.decode(pem.replaceAll(RegExp(r'-----(BEGIN|END) CERTIFICATE-----|\s'), ''));
  return ASN1Parser(Uint8List.fromList(bytes)).nextObject() as ASN1Sequence;
}

Uint8List _tbsBytes(String pem) {
  return (_certTopSeq(pem).elements![0] as ASN1Sequence).encodedBytes!;
}

/// 链顺序: 默认 emSign 链在前, old 模式把 AAA 交叉签名提前
void testChainOrderAndOldMode() {
  var em = EmudhraCA.instance;
  var leafPem = em.leafCertificatePem('example.org');

  var chain = em.chainCertificatesPem(leafPem);
  assert(chain.length == 4);
  var ca = X509Utils.x509CertificateFromPem(chain[1]);
  var root = X509Utils.x509CertificateFromPem(chain[2]);
  var aaa = X509Utils.x509CertificateFromPem(chain[3]);
  assert(ca.subject['2.5.4.3'] == 'EM OV TLS CA - G3C', 'found ${ca.subject['2.5.4.3']}');
  assert(ca.issuer['2.5.4.3'] == 'emSign Root TLS CA - G3', 'found ${ca.issuer['2.5.4.3']}');
  assert(root.subject['2.5.4.3'] == 'emSign Root TLS CA - G3');
  assert(root.issuer['2.5.4.3'] == 'emSign ECC Root CA - G3');
  assert(aaa.issuer['2.5.4.3'] == 'AAA Certificate Services');

  var oldChain = em.chainCertificatesPem(leafPem, oldFirst: true);
  var oldCa = X509Utils.x509CertificateFromPem(oldChain[1]);
  assert(oldCa.issuer['2.5.4.3'] == 'AAA Certificate Services');
  assert(oldChain.length == 4);
  var oldTail1 = X509Utils.x509CertificateFromPem(oldChain[2]);
  assert(oldTail1.issuer['2.5.4.3'] == 'emSign Root TLS CA - G3');
  var oldTail2 = X509Utils.x509CertificateFromPem(oldChain[3]);
  assert(oldTail2.subject['2.5.4.3'] == 'emSign Root TLS CA - G3');
}

/// 完整的 SecurityContext 构建(等价 CertificateManager _createSecurityContext 的 eMudhra 分支)
void testSecurityContext() {
  var em = EmudhraCA.instance;
  var leafPem = EmudhraCA.instance.leafCertificatePem('www.example.com');
  var chainPem = em.chainCertificatesPem(leafPem).join('\r\n');

  var securityContext = SecurityContext(withTrustedRoots: true)
    ..useCertificateChainBytes(chainPem.codeUnits)
    ..usePrivateKeyBytes(em.privateKeyPem.codeUnits);
  securityContext.allowLegacyUnsafeRenegotiation = true;
}

/// RSA 签发路径回归: 类型泛化不影响原有 ProxyPin CA 签发
Future<void> rsaRegression() async {
  var caPem = await File('assets/certs/ca.crt').readAsString();
  var caRoot = X509Utils.x509CertificateFromPem(caPem);
  var pair = CryptoUtils.generateRSAKeyPair();

  var certPem = X509Utils.generateSelfSignedCertificate(caRoot, pair.publicKey as RSAPublicKey,
      pair.privateKey as RSAPrivateKey, 36,
      sans: ['test.proxypin.com'], serialNumber: '10086', subject: {'CN': 'test.proxypin.com'});
  var cert = X509Utils.x509CertificateFromPem(certPem);
  assert(cert.subjectAlternativNames!.contains('test.proxyxin.com'));
  assert(cert.signatureAlgorithm == caRoot.signatureAlgorithm, 'found ${cert.signatureAlgorithm}');
}
