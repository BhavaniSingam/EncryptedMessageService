package zipping;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.Assert.assertTrue;

/**
 * <h1>ZIP Test</h1>
 * Contains tests for functionality of the ZIP class
 * @author Michael Kyeyune
 * @since 2016-03-29
 */
public class ZIPTest
{
    @Test
    public void testZipping() throws UnsupportedEncodingException
    {
        String text = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, " +
                "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
                "Ut enim ad minim veniam, quis nostrud exercitation ullamco " +
                "laboris nisi ut aliquip ex ea commodo consequat. " +
                "Duis aute irure dolor in reprehenderit in voluptate velit esse " +
                "cillum dolore eu fugiat nulla pariatur. " +
                "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui " +
                "officia deserunt mollit anim id est laborum.";

        byte[] textData = text.getBytes("UTF8");

        //compress and check that compression took place
        byte[] compressedData = ZIP.compress(textData);
        assertTrue(compressedData.length < textData.length);

        byte[] uncompressedData = ZIP.decompress(compressedData);
        assertTrue(textData.length == uncompressedData.length);

        //check that text generated from decompression is still the same as the original
        String uncompressedDataText = new String(uncompressedData, "UTF8");
        assertTrue(text.equals(uncompressedDataText));
    }

    @Test
    public void testZippingRandom()
    {
        byte[] data = new byte[277];

        SecureRandom prng = new SecureRandom();
        prng.nextBytes(data);

        byte[] compressedData = ZIP.compress(data);
        assertTrue(compressedData.length < data.length);

        byte[] uncompressedData = ZIP.decompress(compressedData);
        assertTrue(data.length == uncompressedData.length);
    }

    @Test
    public void testZippingRandomText() throws UnsupportedEncodingException
    {
        byte[] data = new byte[277];

        SecureRandom prng = new SecureRandom();
        prng.nextBytes(data);

        String sampleText = new String(data, "UTF8");
        byte[] sampleTextData = sampleText.getBytes("UTF8");

        byte[] compressedData = ZIP.compress(sampleTextData);
        assertTrue(compressedData.length < sampleTextData.length);

        byte[] uncompressedData = ZIP.decompress(compressedData);
        assertTrue(sampleTextData.length == uncompressedData.length);
    }

    @Test
    public void testZippingRandomTextBase64()
    {
        byte[] data = new byte[277];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(data);

        byte[] encodedBytes = Base64.getEncoder().encode(data);

        byte[] compressedData = ZIP.compress(encodedBytes);
        assertTrue(compressedData.length < encodedBytes.length);
    }

    @Test
    public void testZippingRandomTextBase64ToString() throws UnsupportedEncodingException
    {
        byte[] data = new byte[277];
        SecureRandom prng = new SecureRandom();
        prng.nextBytes(data);

        String encodedString = Base64.getEncoder().encodeToString(data);
        System.out.println(encodedString);
        byte[] encodedStringBytes = encodedString.getBytes("UTF8");

        byte[] compressedData = ZIP.compress(encodedStringBytes);
        assertTrue(compressedData.length < encodedStringBytes.length);

    }
}
