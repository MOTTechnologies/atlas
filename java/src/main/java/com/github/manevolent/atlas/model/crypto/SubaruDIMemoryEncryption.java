package com.github.manevolent.atlas.model.crypto;

import com.github.manevolent.atlas.model.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class SubaruDIMemoryEncryption implements MemoryEncryption {
    public static final String keyProperty = "subaru.dit.flashkey";

    public SubaruDIMemoryEncryption() {

    }

    @Override
    public boolean isKeySetRequired() {
        return true;
    }

    private KeyProperty getKeyProperty(Calibration calibration) {
        KeyProperty property = calibration.getKeySet().getProperty(keyProperty, KeyProperty.class);
        if (property == null) {
            throw new IllegalArgumentException("Missing key (" + keyProperty + ")");
        } else if (property.getKey().length != 8) {
            throw new IllegalArgumentException("Invalid key length: " + (property.getKey().length != 8));
        }

        return property;
    }

    private byte[] getKey(Calibration calibration) {
        return getKeyProperty(calibration).getKey();
    }

    public short[] getEncryptionKey(Calibration calibration) {
        byte[] key = getKey(calibration);
        ByteBuffer buffer = ByteBuffer.wrap(key);
        short[] encryptKey = new short[4];
        encryptKey[0] = buffer.getShort();
        encryptKey[1] = buffer.getShort();
        encryptKey[2] = buffer.getShort();
        encryptKey[3] = buffer.getShort();
        return encryptKey;
    }

    public short[] getDecryptionKey(Calibration calibration) {
        byte[] key = getKey(calibration);
        ByteBuffer buffer = ByteBuffer.wrap(key);
        short[] decryptKey = new short[4];
        decryptKey[3] = buffer.getShort();
        decryptKey[2] = buffer.getShort();
        decryptKey[1] = buffer.getShort();
        decryptKey[0] = buffer.getShort();
        return decryptKey;
    }

    @Override
    public void encrypt(Calibration calibration, byte[] data, int offs, int len) throws IOException {
        short[] encryptKey = getEncryptionKey(calibration);

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(data, offs, len);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            com.github.manevolent.atlas.ssm4.SubaruDITFlashEncryption.feistel_encrypt(inputStream, outputStream,
                    encryptKey);

            System.arraycopy(outputStream.toByteArray(), 0, data, 0, len);
        }
    }

    @Override
    public void decrypt(Calibration calibration, byte[] data, int offs, int len) throws IOException {
        short[] decryptKey = getDecryptionKey(calibration);

        try (ByteArrayInputStream inputStream = new ByteArrayInputStream(data, offs, len);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            com.github.manevolent.atlas.ssm4.SubaruDITFlashEncryption.feistel_decrypt(inputStream, outputStream,
                    decryptKey);

            byte[] decrypted = outputStream.toByteArray();
            System.arraycopy(decrypted, 0, data, 0, Math.min(decrypted.length, len));
        }
    }

    @Override
    public int getBlockSize() {
        return 32 / 8; // 32 bits
    }

    @Override
    public int getKeySize() {
        return 64 / 8; // 64 bits
    }

    public static class Factory implements MemoryEncryptionFactory {
        @Override
        public List<PropertyDefinition> getPropertyDefinitions() {
            return Arrays.asList(new PropertyDefinition(true, keyProperty,
                            "Feistel Key",
                            "The feistel algorithm encryption key",
                            KeyProperty.class));
        }

        @Override
        public MemoryEncryption create() {
            return new SubaruDIMemoryEncryption();
        }
    }
}
