/*
 * Copyright 2026 ProxyPincontributors. All rights reserved.
 * (PEM material originally disclosed by hops around the eMudhra intermediate CA compromise,
 * integrated per the approach of mitmproxy's `--emudhra` option, MIT licensed.)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';
import 'package:proxypin/network/util/cert/cert_data.dart';
import 'package:proxypin/network/util/cert/x509.dart';

/// eMudhra 中间 CA 密钥泄露模式(mitmproxy `--emudhra` 的同款能力)。
/// 受影响私钥已吊销, 仅用于测试仍信任该 CA 的客户端(未更新信任库、不做吊销检查/CT 强制的 TLS 实现),
/// 已更新信任库的客户端会直接拒绝由其签发的证书。
/// https://emudhra.we-have-a-problem.com/
class EmudhraCA {
  /// 与 mitmproxy --emudhra 相同的证书链, 依次包含:
  /// 1. EM OV TLS CA - G3C 的私钥(P-384, d=4, 因密钥生成缺陷而可被任何人恢复);
  /// 2. EM OV TLS CA - G3C(emSign Root TLS CA - G3 签发);
  /// 3. emSign Root TLS CA - G3(emSign ECC Root CA - G3 交叉签发);
  /// 4. EM OV TLS CA - G3C(Sectigo AAA Certificate Services 交叉签发)。
  static const String chainPem = '''
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAShZANiAAQTglHNUqyS
mMHIqtl3Mh3rl+cJvQtMoKylXcitUdz8nRWJoVl+OlEg4e/WMcY+GDXKyuKYaaYu
FjHoooGBq1ZhbcRdkYq8CfOrDmPPeSqk3O1zh743u6VpVJ8cArJw7Wc=
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
4rSb9vGqxZzelQth
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv
1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf
HAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0i
KOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6
OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQ
TaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCw
FFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+Yqgdb
uL5ChFWOQU+ErSDnUq7yr+pjBQ==
-----END CERTIFICATE-----
''';

  EmudhraCA._() {
    var keyPem = _pemBlocks(chainPem, 'PRIVATE KEY').single;
    var certPems = _pemBlocks(chainPem, 'CERTIFICATE');
    assert(certPems.length == 3);

    _privateKeyPem = keyPem;
    _chainCertPems = certPems;

    //解析受影响 CA 证书, 用于派生叶子证书的 issuer/SAN 等字段
    _caCert = X509Utils.x509CertificateFromPem(certPems.first);
    _caSubjectDnBytes = X509Utils.subjectDnBytesFromPem(certPems.first);

    //解析 PKCS#8 EC 私钥: SEQUENCE { INTEGER 0, SEQUENCE{OID id-ecPublicKey, OID secp384r1}, OCTET STRING(SEC1) }
    var bytes = base64
        .decode(keyPem.replaceAll(RegExp(r'-----(BEGIN|END) PRIVATE KEY-----|\s'), ''));
    var pkcs8 = ASN1Parser(Uint8List.fromList(bytes)).nextObject() as ASN1Sequence;
    var algorithmSeq = pkcs8.elements![1] as ASN1Sequence;
    var curveOid = algorithmSeq.elements![1] as ASN1ObjectIdentifier;
    //仅支持 secp384r1(受影响密钥全部为 P-384)
    if (curveOid.objectIdentifierAsString != '1.3.132.0.34') {
      throw StateError('unsupported eMudhra curve: ${curveOid.objectIdentifierAsString}');
    }

    var sec1 = ASN1Parser((pkcs8.elements![2] as ASN1OctetString).valueBytes).nextObject() as ASN1Sequence;
    var dBytes = (sec1.elements![1] as ASN1OctetString).valueBytes!;
    BigInt d = BigInt.zero;
    for (var byte in dBytes) {
      d = (d << 8) | BigInt.from(byte);
    }

    var params = ECDomainParameters('secp384r1');
    _signingKey = ECPrivateKey(d, params);
    var point = params.G * d;
    _signingPublicKey = ECPublicKey(point, params);
  }

  static EmudhraCA? _instance;

  static EmudhraCA get instance => _instance ??= EmudhraCA._();

  ///原文私钥 PEM(PKCS#8), TLS 服务端直接使用
  late final String _privateKeyPem;

  String get privateKeyPem => _privateKeyPem;

  ///证书链 PEM(mitmproxy 顺序): [G3C-emSign, RootTLSG3, G3C-AAA]
  late final List<String> _chainCertPems;

  ///受影响 CA(EM OV TLS CA - G3C)
  late final X509CertificateData _caCert;

  ///CA subject DN 原始字节, 签发叶子证书时作为 issuer
  late final Uint8List _caSubjectDnBytes;

  ///受影响 CA 私钥, 用于签发叶子证书
  late final ECPrivateKey _signingKey;

  ///与私钥对应的公钥(叶子证书复用 CA 密钥对, mitmproxy 同款行为)
  late final ECPublicKey _signingPublicKey;

  X509CertificateData get caCert => _caCert;

  /// 生成签发拦截用的叶子证书 PEM(单证书)
  String leafCertificatePem(String host, {X509CertificateData? remoteCert}) {
    Map<String, String>? subject;
    List<String>? sans;
    DateTime? notBefore;
    DateTime? notAfter;
    if (remoteCert != null) {
      subject = remoteCertSubject(remoteCert);
      sans = remoteCertSans(remoteCert);
      notBefore = remoteCert.validity.notBefore;
      notAfter = remoteCert.validity.notAfter;
    }

    return X509Utils.generateSelfSignedCertificate(_caCert, _signingPublicKey, _signingKey, 36,
        sans: sans ?? [host],
        serialNumber: (Random().nextInt(999999) + 1).toString(),
        subject: subject ?? defaultSubject(host),
        issuerRawBytes: _caSubjectDnBytes,
        notBefore: notBefore,
        notAfter: notAfter);
  }

  /// 叶子证书 + 发给客户端的证书链(叶子/中间 CA/根交互签名), 供 SecurityContext 使用
  ///
  /// [oldFirst] 为 true 时把 Sectigo AAA Certificate Services 交叉签名的中间 CA 放到最前,
  /// 适配只信任 AAA 根的旧版 OpenSSL 信任库(OpenSSL 不回溯同 Subject/SKI 的候选链)。
  List<String> chainCertificatesPem(String leafPem, {bool oldFirst = false}) {
    var chain = [leafPem, ..._chainCertPems];
    if (oldFirst) {
      //G3C-emSign(0), RootTLSG3(1), G3C-AAA(2) -> AAA 版本前置
      chain = [leafPem, _chainCertPems[2], _chainCertPems[0], _chainCertPems[1]];
    }
    return chain;
  }

  static Map<String, String> defaultSubject(String host) {
    return {
      'C': 'CN',
      'ST': 'BJ',
      'L': 'Beijing',
      'O': 'Proxy',
      'OU': 'ProxyPin',
      'CN': host,
    };
  }
}

///拆分 PEM 中指定类型的所有块
List<String> _pemBlocks(String blob, String tag) {
  var matches = RegExp('-----BEGIN $tag-----.*?-----END $tag-----', dotAll: true).allMatches(blob);
  return matches.map((e) => e.group(0)!).toList();
}

///提取远程真实证书的 subject(仅含非空字段), 保持叶子证书与真实证书一致, 便于客户端严格校验
Map<String, String>? remoteCertSubject(X509CertificateData remoteCert) {
  Map<String, String> subject = {};
  remoteCert.subject.forEach((key, value) {
    if (value != null && value.isNotEmpty) {
      subject[key] = value;
    }
  });
  return subject.isEmpty ? null : subject;
}

///提取远程真实证书的 DNS 类型 SAN, 过滤 DirName 等非 DNS 条目
List<String>? remoteCertSans(X509CertificateData remoteCert) {
  var sans = remoteCert.subjectAlternativNames?.where((e) => !e.startsWith('DirName:')).toList();
  return (sans == null || sans.isEmpty) ? null : sans;
}
