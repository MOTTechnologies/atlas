package com.github.manevolent.atlas.model.crypto;

import com.github.manevolent.atlas.model.Calibration;
import com.github.manevolent.atlas.model.KeySet;
import com.github.manevolent.atlas.model.MemorySource;
import com.github.manevolent.atlas.model.Project;

import java.io.IOException;

public interface MemoryEncryption {

    default void encrypt(Calibration calibration, byte[] data) throws IOException {
        encrypt(calibration, data, 0, data.length);
    }

    void encrypt(Calibration calibration, byte[] data, int offs, int len) throws IOException;

    default void decrypt(Calibration calibration, byte[] data) throws IOException {
        decrypt(calibration, data, 0, data.length);
    }

    void decrypt(Calibration calibration, byte[] data, int offs, int len) throws IOException;

    boolean isKeySetRequired();

    int getBlockSize();

    int getKeySize();

    default int read(Calibration calibration, long flashOffs, byte[] dst, int offs, int len) throws IOException {
        int blockStart = (int) Math.floor((double)flashOffs / (double)getBlockSize());
        int blockEnd = (int) Math.ceil((double)(flashOffs+len) / (double)getBlockSize());
        int dataStart = blockStart * getBlockSize();
        int dataEnd = blockEnd * getBlockSize();
        byte[] cipherText = new byte[dataEnd - dataStart];
        int read = calibration.getSource().read(cipherText, dataStart, 0, cipherText.length);
        if (read != cipherText.length) {
            throw new IOException("Unexpected read size: " + read + " != " + cipherText.length);
        }
        decrypt(calibration, cipherText, 0, cipherText.length);
        System.arraycopy(cipherText, (int) (flashOffs - dataStart), dst, offs, len);
        return len;
    }

    default void write(Calibration calibration, long flashOffs, byte[] src, int offs, int len) throws IOException {
        int blockStart = (int) Math.floor((double)flashOffs / (double)getBlockSize());
        int blockEnd = (int) Math.ceil((double)(flashOffs+len) / (double)getBlockSize());
        int dataStart = blockStart * getBlockSize();
        int dataEnd = blockEnd * getBlockSize();
        byte[] data = new byte[dataEnd - dataStart];

        // Read the cleartext at this region
        calibration.getSource().read(data, dataStart, 0, data.length);
        decrypt(calibration, data, 0, data.length);

        // Update the cleartext
        System.arraycopy(src, offs, data, (int) (flashOffs - dataStart), len);

        // Encrypt the cleartext
        encrypt(calibration, data, 0, data.length);

        // Write the cleartext back
        calibration.getSource().write(data, dataStart, 0, data.length);
    }
}
