package com.rgsc.pwcenter.util;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;

/**
 * 修改时间：2010-12-1 下午06:14:38
 */
public class RSAUtil {
	// 非对称加密密钥算法
	private static final String Algorithm = "RSA";

	// 公钥关键字
	private static final String uk = "publicKey";

	// 私钥关键字
	private static final String pk = "privateKey";

	// 密钥长度，用来初始化
	private static final int Key_Size = 1024;

	// 公钥
	private static byte[] publicKey = null;

	// 私钥
	private static byte[] privateKey = null;

	// RSA最大加密明文大小
	private static final int MAX_ENCRYPT_BLOCK = 117;

	// RSA最大解密密文大小
	private static final int MAX_DECRYPT_BLOCK = 128;

	private static Map<String, String> keyPair = new ConcurrentHashMap<>();

	static {
		try {
			// 得到密钥对生成器
			KeyPairGenerator kpg;
			kpg = KeyPairGenerator.getInstance(Algorithm);
			kpg.initialize(Key_Size);
			// 得到密钥对
			KeyPair kp = kpg.generateKeyPair();
			// 得到公钥
			RSAPublicKey keyPublic = (RSAPublicKey) kp.getPublic();
			publicKey = keyPublic.getEncoded();
			// 得到私钥
			RSAPrivateKey keyPrivate = (RSAPrivateKey) kp.getPrivate();
			privateKey = keyPrivate.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public static Map<String, String> getKeyPair() {
		String str_pubicKey = Base64.getEncoder().encodeToString(publicKey);
		String str_privateKey = Base64.getEncoder().encodeToString(privateKey);
		keyPair.put(RSAUtil.uk, str_pubicKey);
		keyPair.put(RSAUtil.pk, str_privateKey);
		return keyPair;
	}

	/**
	 * 用公钥对字符串进行加密
	 * 
	 * 说明：
	 * 
	 * @param originalString
	 * @param publicKeyArray
	 * @return
	 * @throws Exception
	 *             创建时间：2010-12-1 下午06:29:51
	 */
	public static String encode(String publicKey, String encode_info) {
		try {
			byte[] byte_info = encode_info.getBytes();
			byte[] byteArray_publicKey = Base64.getDecoder().decode(publicKey);
			// 得到公钥
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(byteArray_publicKey);
			KeyFactory kf = KeyFactory.getInstance(Algorithm);
			PublicKey keyPublic = kf.generatePublic(keySpec);
			// 加密数据
			Cipher cp = Cipher.getInstance(Algorithm);
			cp.init(Cipher.ENCRYPT_MODE, keyPublic);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int offSet = 0;
			int inputLen = byte_info.length;
			byte[] cache = null;
			int i = 0;
			// 对数据分段解密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
					cache = cp.doFinal(byte_info, offSet, MAX_ENCRYPT_BLOCK);
				} else {
					cache = cp.doFinal(byte_info, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_ENCRYPT_BLOCK;
			}
			return Base64.getEncoder().encodeToString(out.toByteArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * 使用私钥进行解密
	 * 
	 * 说明：
	 * 
	 * @param encryptedDataArray
	 * @return
	 * @throws Exception
	 *             创建时间：2010-12-1 下午06:35:28
	 */
	public static String decode(String privateKey, String decode_info) {
		try {
			byte[] byte_info = Base64.getDecoder().decode(decode_info);
			byte[] byteArray_privateKey = Base64.getDecoder().decode(privateKey);
			// 得到私钥
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(byteArray_privateKey);
			KeyFactory kf = KeyFactory.getInstance(Algorithm);
			PrivateKey keyPrivate = kf.generatePrivate(keySpec);
			// 解密数据
			Cipher cp = Cipher.getInstance(Algorithm);
			cp.init(Cipher.DECRYPT_MODE, keyPrivate);

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int offSet = 0;
			int inputLen = byte_info.length;
			byte[] cache = null;
			int i = 0;
			// 对数据分段解密
			while (inputLen - offSet > 0) {
				if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
					cache = cp.doFinal(byte_info, offSet, MAX_DECRYPT_BLOCK);
				} else {
					cache = cp.doFinal(byte_info, offSet, inputLen - offSet);
				}
				out.write(cache, 0, cache.length);
				i++;
				offSet = i * MAX_DECRYPT_BLOCK;
			}
			// 得到解密后的字符串
			return new String(out.toByteArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
