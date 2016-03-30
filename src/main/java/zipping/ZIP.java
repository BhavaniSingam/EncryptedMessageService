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
        ByteArrayInputStream bais = new ByteArrayInputStream(data);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        ZipEntry entry = new ZipEntry("temp.zip");
        entry.setSize(data.length);

        try {
            zos.putNextEntry(entry);

            byte[] buffer = new byte[1024];

            int len;

            while((len = bais.read(buffer)) > 0)
            {
                zos.write(buffer, 0, len);
            }

            zos.closeEntry();
            bais.close();
            zos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally
        {
            return baos.toByteArray();
        }


    }

    /**
     * A method to decompress provided byte array
     * @param compressedData The data to be uncompressed
     * @return byte[] The decompressed data
     */
    public static byte[] decompress(byte[] compressedData)
    {
        ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
        ZipInputStream zis = new ZipInputStream(bais);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            zis.getNextEntry();
            byte[] buffer = new byte[1024];

            int len;
            while((len = zis.read(buffer)) > 0)
            {
                baos.write(buffer, 0, len);
            }
            baos.close();
            zis.getNextEntry();
            zis.closeEntry();
            zis.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        finally
        {
            return baos.toByteArray();
        }

    }
}
