package com.zzlh.auth.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;

/**
 * @Description sha算法
 * @author liulei
 * @date 2018年10月15日 下午12:49:12
 */
public class ShaMessageDigest {

	private static String algorithm = "SHA-1";

	public static String encode(String password, String salt) {
		byte[] digest = null;
		try {
			String saltedPass = mergePasswordAndSalt(password, salt, false);
			MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
			digest = messageDigest.digest(Utf8.encode(saltedPass));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return Utf8.decode(Base64.encode(digest));
	}

	protected static String mergePasswordAndSalt(String password, Object salt, boolean strict) {
		if (password == null) {
			password = "";
		}
		if (strict && (salt != null)) {
			if ((salt.toString().lastIndexOf("{") != -1) || (salt.toString().lastIndexOf("}") != -1)) {
				throw new IllegalArgumentException("Cannot use { or } in salt.toString()");
			}
		}
		if ((salt == null) || "".equals(salt)) {
			return password;
		} else {
			return password + "{" + salt.toString() + "}";
		}
	}
}
