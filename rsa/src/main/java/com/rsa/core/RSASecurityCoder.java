package com.rsa.core;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
/**
 * RSA加密解密类 说明： 作者：何杨(heyang78@gmail.com) 创建时间：2010-12-1 下午06:14:38
 * 修改时间：2010-12-1 下午06:14:38
 */
@SuppressWarnings("restriction")
public class RSASecurityCoder {
	// 非对称加密密钥算法
	private static final String Algorithm = "RSA";

	// 密钥长度，用来初始化
	private static final int Key_Size = 1024;

	// 公钥
	private final byte[] publicKey;

	// 私钥
	private final byte[] privateKey;

	/**
	 * 构造函数，在其中生成公钥和私钥
	 * 
	 * @throws Exception
	 */
	public RSASecurityCoder() throws Exception {
		// 得到密钥对生成器
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(Algorithm);
		kpg.initialize(Key_Size);
		// 得到密钥对
		KeyPair kp = kpg.generateKeyPair();

		// 得到公钥
		RSAPublicKey keyPublic = (RSAPublicKey) kp.getPublic();
		publicKey = keyPublic.getEncoded();

		// 得到私钥
		RSAPrivateKey keyPrivate = (RSAPrivateKey) kp.getPrivate();
		privateKey = keyPrivate.getEncoded();
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
	public byte[] getEncryptArray(String originalString, byte[] publicKeyArray) throws Exception {
		// 得到公钥
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyArray);
		System.out.println(Base64.encodeBase64String(keySpec.getEncoded()));
		KeyFactory kf = KeyFactory.getInstance(Algorithm);
		PublicKey keyPublic = kf.generatePublic(keySpec);

		// 加密数据
		Cipher cp = Cipher.getInstance(Algorithm);
		cp.init(Cipher.ENCRYPT_MODE, keyPublic);
		return cp.doFinal(originalString.getBytes());
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
	public String getDecryptString(byte[] encryptedDataArray) throws Exception {
		// 得到私钥
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory kf = KeyFactory.getInstance(Algorithm);
		System.out.println(Base64.encodeBase64String(keySpec.getEncoded()));
		PrivateKey keyPrivate = kf.generatePrivate(keySpec);
		// 解密数据
		Cipher cp = Cipher.getInstance(Algorithm);
		cp.init(Cipher.DECRYPT_MODE, keyPrivate);
		byte[] arr = cp.doFinal(encryptedDataArray);

		// 得到解密后的字符串
		return new String(arr);
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	public static void main(String[] arr) throws Exception {
		String str = "你好，世界！ Hello,world!";
		System.out.println("准备用公钥加密的字符串为：" + str);

		// 用公钥加密
		RSASecurityCoder rsaCoder = new RSASecurityCoder();
		byte[] publicKey = rsaCoder.getPublicKey();
		byte[] encryptArray = rsaCoder.getEncryptArray(str, publicKey);

		System.out.print("用公钥加密后的结果为:");
		for (byte b : encryptArray) {
			System.out.print(b);
		}
		System.out.println();

		// 用私钥解密
		String str1 = rsaCoder.getDecryptString(encryptArray);
		System.out.println("用私钥解密后的字符串为：" + str1);
	}
}