package com.KirisakiKen;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.util.Locale;

public class Main
{
    private Main() {}

    private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text)
    {
        try
        {
            Mac hmac;
            hmac = Mac.getInstance(crypto);

            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");

            hmac.init(macKey);

            return hmac.doFinal(text);
        }
        catch (GeneralSecurityException gse)
        {
            throw new UndeclaredThrowableException(gse);
        }
    }

    private static byte[] hexStr2Bytes(String hex)
    {
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();
        byte[] ret = new byte[bArray.length - 1];

        for (int i = 0; i < ret.length; i++)
        {
            ret[i] = bArray[i + 1];
        }

        return ret;
    }

    private static String asciiToHex(String string)
    {
        char[] ch = string.toCharArray();

        StringBuilder builder = new StringBuilder();

        for (char c : ch)
        {
            int i = (int) c;
            builder.append(Integer.toHexString(i).toUpperCase());
        }

        return builder.toString();
    }

    private static final long[] DIGITS_POWER = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
                                                10000000000L};

    public static String generateTOTP(String key, String time, String returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA1");
    }
    public static String generateTOTP256(String key, String time, String returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA256");
    }
    public static String generateTOTP512(String key, String time, String returnDigits)
    {
        return generateTOTP(key, time, returnDigits, "HmacSHA512");
    }

    public static String generateTOTP(String key, String time, String returnDigits, String crypto)
    {
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;

        while (time.length() < 16) time = "0" + time;

        byte[] msg = hexStr2Bytes(time);
        byte[] k = hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);

        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) |
                     ((hash[offset + 1] & 0xff) << 16) |
                     ((hash[offset + 2] & 0xff) << 8) |
                     (hash[offset + 3] & 0xff);

        long otp = binary % DIGITS_POWER[codeDigits];
        result = Long.toString(otp);

        while (result.length() < codeDigits) result = "0" + result;

        return result;
    }

    private static String GetCurrentTime()
    {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
        LocalDateTime currentTime = LocalDateTime.now();

        return dtf.format(currentTime);
    }


    public static void main(String[] args)
    {
        String rawKey = "InsertYourKeyHere!"; // Insert your secret key here.
        String key = asciiToHex(rawKey);
        String digits = "6"; // Digits of your TOTP. (1-10 Digits available)
        String hashAlgorithm = "HmacSHA512"; // Hash algorithm. (Hmac1, Hmac256, Hmac512 available)

        long T0 = 0;
        long X = 30;
        long currentUnix = new Date().getTime() / 1000L;
        String steps = "0";

        long T = (currentUnix - T0) / X;
        steps = Long.toHexString(T).toUpperCase();

        while (steps.length() < 16) steps = "0" + steps;

        try
        {
            System.out.println("Your key: " + rawKey + " | " +
                               "Your TOTP : " + generateTOTP(key, steps, digits, hashAlgorithm) + " | " +
                               "Current Time : " + GetCurrentTime() + " | " +
                               "Current Unix Time : " + currentUnix);
        }
        catch (final Exception e)
        {
            System.out.println("Error : " + e);
        }
    }
}
