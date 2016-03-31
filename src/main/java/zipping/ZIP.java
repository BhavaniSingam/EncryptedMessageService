package zipping;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.*;

/**
 * <h1>ZIP</h1>
 * Contains methods to compress and decompress byte arrays
 * @author Michael Kyeyune
 * @since 2016-03-28
 */
public class ZIP
{
    /**
     * A method to compress provided byte array
     * @param data The data to be compressed
     * @return byte[] The compressed data
     */
    public static byte[] compress(byte[] data)
    {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        Deflater compresser = new Deflater(Deflater.BEST_COMPRESSION, true);
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(stream, compresser);

        try {
            deflaterOutputStream.write(data);
            deflaterOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return stream.toByteArray();
    }

    /**
     * A method to decompress provided byte array
     * @param compressedData The data to be uncompressed
     * @return byte[] The decompressed data
     */
    public static byte[] decompress(byte[] compressedData)
    {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        Inflater decompresser = new Inflater(true);
        InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(stream, decompresser);
        try {
            inflaterOutputStream.write(compressedData);
            inflaterOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return stream.toByteArray();
    }
}
