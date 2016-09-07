package com.JUtils.encrypt;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * 作者：彭勃
 * 时间：2016年09月07日
 * 作用：RSA加密解密工具类
 *
 */
public class RSAUtil {
	private static final String AU = "RSA";
	private static final int SIZE = 1024;
	private static byte[] publicKey;
	private static byte[] privateKey;

	/**
	 * 获取RSA秘钥对
	 */
	private static void getKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(AU);
			kpg.initialize(SIZE);
			KeyPair kp = kpg.generateKeyPair();
			PublicKey uk = kp.getPublic();
			PrivateKey pk = kp.getPrivate();
			publicKey = uk.getEncoded();
			privateKey = pk.getEncoded();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public static String getUk() {
		getKeyPair();
		return Base64.encodeBase64String(publicKey);
	}

	public static String getPk() {
		return Base64.encodeBase64String(privateKey);
	}

	public static String encode(String msg, String str_uk) {
		try {
			StringBuffer sb = new StringBuffer();
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(str_uk));
			Cipher cp = Cipher.getInstance(AU);
			KeyFactory kf = KeyFactory.getInstance(AU);
			PublicKey uk = kf.generatePublic(keySpec);
			cp.init(Cipher.ENCRYPT_MODE, uk);
			byte[] byte_msg = msg.getBytes();
			for (int i = 0; i < byte_msg.length; i += 100) {
				byte[] msg_password = cp.doFinal(ArrayUtils.subarray(byte_msg, i, i + 100));
				for (byte b : msg_password) {
					sb.append(b);
					sb.append(",");
				}
			}
			String returnStr = sb.toString();
			if (StringUtils.endsWith(returnStr, ",")) {
				returnStr = StringUtils.removeEnd(returnStr.toString(), ",");
			}
			return returnStr;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String encode(byte[] msg, String str_uk) {
		try {
			StringBuffer sb = new StringBuffer();
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decodeBase64(str_uk));
			Cipher cp = Cipher.getInstance(AU);
			KeyFactory kf = KeyFactory.getInstance(AU);
			PublicKey uk = kf.generatePublic(keySpec);
			cp.init(Cipher.ENCRYPT_MODE, uk);
			for (int i = 0; i < msg.length; i += 100) {
				byte[] msg_password = cp.doFinal(ArrayUtils.subarray(msg, i, i + 100));
				for (byte b : msg_password) {
					sb.append(b);
					sb.append(",");
				}
			}
			String returnStr = sb.toString();
			if (StringUtils.endsWith(returnStr, ",")) {
				returnStr = StringUtils.removeEnd(returnStr.toString(), ",");
			}
			return returnStr;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String decode(String msg_password, String pk) {
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(pk));
			Cipher cp = Cipher.getInstance(AU);
			KeyFactory kf = KeyFactory.getInstance(AU);
			cp.init(Cipher.DECRYPT_MODE, kf.generatePrivate(keySpec));
			StringBuffer sb = new StringBuffer();
			String[] str_byte_array = StringUtils.split(msg_password, ",");
			byte[] byte_msg_password = new byte[str_byte_array.length];
			for (int i = 0; i < str_byte_array.length; i++) {
				byte_msg_password[i] = Byte.parseByte(str_byte_array[i]);
			}
			for (int i = 0; i < byte_msg_password.length; i += 128) {
				byte[] msg_byte = cp.doFinal(ArrayUtils.subarray(byte_msg_password, i, i + 128));
				sb.append(new String(msg_byte));
			}
			return sb.toString();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String decode(byte[] msg_password) {
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decodeBase64(getPk()));
			Cipher cp = Cipher.getInstance(AU);
			KeyFactory kf = KeyFactory.getInstance(AU);
			cp.init(Cipher.DECRYPT_MODE, kf.generatePrivate(keySpec));
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < msg_password.length; i += 128) {
				byte[] msg = cp.doFinal(ArrayUtils.subarray(msg_password, i, i + 128));
				sb.append(new String(msg));
			}
			return sb.toString();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] encodeFile(File file, String str_uk) {
		byte[] buffer = null;
		try {
			FileInputStream fis = new FileInputStream(file);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] b = new byte[1024];
			int n;
			while ((n = fis.read(b)) != -1) {
				bos.write(b, 0, n);
			}
			buffer = bos.toByteArray();
			String content = encode(buffer, str_uk);
			File ff = new File("D:\\1m_mssage");
			if (!ff.exists()) {
				ff.createNewFile();
			}
			FileWriter writer = new FileWriter(ff);
			BufferedWriter bufferWritter = new BufferedWriter(writer);
			bufferWritter.write(content);
			bufferWritter.close();
			fis.close();
			bos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return buffer;
	}

	public static byte[] decodeFile(File file, String pk) {
		byte[] buffer = null;
		Reader reader = null;
		try {
			reader = new InputStreamReader(new FileInputStream(file));
			int tempchar;
			StringBuffer sb = new StringBuffer();
			while ((tempchar = reader.read()) != -1) {
				if (((char) tempchar) != '\r') {
					sb.append((char) tempchar);
				}
			}
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			File ff = new File("D:\\1m_ms.txt");
			if (!ff.exists()) {
				ff.createNewFile();
			}
			String content = decode(sb.toString(), pk);
			FileWriter writer = new FileWriter(ff);
			BufferedWriter bufferWritter = new BufferedWriter(writer);
			bufferWritter.write(content);
			bufferWritter.close();
			reader.close();
			bos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return buffer;
	}

	public static void main(String[] args) {
		String uk = RSAUtil.getUk();
		String pk = RSAUtil.getPk();
//		System.out.println(pk);
//		File file = new File("D:\\1m.txt");
//		RESUtil.encodeFile(file, uk);
//		String pk="MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIj0GdbpG6JPVjBYW6uSFfA5pI6OhKAX6yafZGR/huWR6u04ttb74VNqYvzP9yHoV+x+fEE84Emi4OzDDAuX8+6YwXyw9si09j7O+mPgV8ZmDOslbOJsL0w0n3t1e80hV7BpGy00MpdB+8NnhPA6RaxksGtib6+41eZAe7LEMa7lAgMBAAECgYA77LMxuiYBSz2nQcI6vF0lE9PRHMMjWdPmvm+rGbHo2YQ18E7wmp3pZe+SN10nVQbD0ESGNyDcl4xbjKzEleSBqd+24AqftCcJb0AY4sU5hE9QZ+iv/TCWmekERqxw/j7bd4b51+/1ygk+SETVKfhZ4MQDMNs84SRj54neAKjDMQJBAMdEoS4eMNWKt+g9oFi4q+abzezYc38ItnYnaFUFE/lF7PpXXbJEVk6rf1ywKbd9v9ioPQP+/bdOJND8Redqi1sCQQCv8cNWjZsiGb0NSivh6Vcwn759vS20VQJHKuxQRalifbupl430eFOAX7memqnh9+suGYAirUdNnZCM1cGvZwK/AkAI3ogiClv4FT2MS7noWQflsseepB+35sZgSe694gT6kl8y4VKdTaddxwpbMMgaj7FLTmmw1NesIgFHgAMIgtiDAkEAnrpJM6iEr/rwZzDm7eQI2MEEpYMp3Gpkp7e9gZ2W9lfgGVu0oTx8eG/jkYaOhGGZNfmjc6VHkmn3olalaYxRGQJAXlSmnVYBl+EolhYi574L9l3JOevvVD0y3X2YVGiGrgubEEOYQwSa9OPbIqqYhReSmejoEfMb1fYLQxt7TZ4B/A==";
//		File file = new File("D:\\1m_mssage");
//		RESUtil.decodeFile(file,pk);
		 System.out.println("加密前数据为：helloworld");
		 System.out.println("公钥为:" + uk);
		 String msg_password = RSAUtil.encode("helloworld",uk);
		 System.out.println("加密后数据为："+msg_password);
		 System.out.println("解密后数据为："+RSAUtil.decode(msg_password,pk));
	}
}
