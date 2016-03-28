package zipping;

import java.io.ByteArrayOutputStream;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

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
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);

        Deflater deflater = new Deflater();
        deflater.setInput(data);
        deflater.finish();

        byte[] buffer = new byte[1024];

        while(!deflater.finished())
        {
            out.write(buffer, 0, deflater.deflate(buffer));
        }

        return out.toByteArray();
    }

    /**
     * A method to decompress provided byte array
     * @param compressedData The data to be uncompressed
     * @return byte[] The decompressed data
     */
    public static byte[] decompress(byte[] compressedData)
    {
        Inflater inflater = new Inflater();
        inflater.setInput(compressedData);

        ByteArrayOutputStream out = new ByteArrayOutputStream(compressedData.length);
        byte[] buffer = new byte[1024];

        try
        {
            while(!inflater.finished())
            {
                out.write(buffer, 0, inflater.inflate(buffer));
            }
            return out.toByteArray();
        }
        catch(DataFormatException ex)
        {
            ex.printStackTrace();
            //return data uncompressed
            return compressedData;
        }
    }
}
