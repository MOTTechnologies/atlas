package com.github.manevolent.atlas.protocol.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSDownloadResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

// See: https://piembsystech.com/request-download-0x34-service-uds-protocol/
public class UDSDownloadRequest extends UDSRequest<UDSDownloadResponse> {
    private int dataEncryption;
    private int dataCompression;
    private int memoryIdentifier;

    private int memorySizeBytes;
    private int memoryAddressBytes;

    private long memoryAddress;
    private long memorySize;

    public UDSDownloadRequest() {

    }

    public UDSDownloadRequest(int dataCompression, int dataEncryption, int memoryIdentifier,
                              int memoryAddressBytes, long memoryAddress, int memorySizeBytes, long memorySize) {
        this.dataEncryption = dataEncryption;

        this.dataCompression = dataCompression;

        this.memoryIdentifier = memoryIdentifier;

        this.memoryAddressBytes = memoryAddressBytes;
        this.memoryAddress = memoryAddress;

        this.memorySizeBytes = memorySizeBytes;
        this.memorySize = memorySize;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        this.dataCompression = (int) reader.read(4);
        this.dataEncryption = (int) reader.read(4);

        this.memorySizeBytes = (int) reader.read(4);
        this.memoryAddressBytes = (int) reader.read(4);

        this.memoryAddress = reader.read(memoryAddressBytes * 8);
        this.memorySize = reader.read(memorySizeBytes * 8);
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        writer.writeNibble((byte) (this.dataCompression & 0xF));
        writer.writeNibble((byte) (this.dataEncryption & 0xF));

        writer.writeNibble((byte) (this.memorySizeBytes & 0xF));
        writer.writeNibble((byte) (this.memoryAddressBytes & 0xF));

        if (memoryAddressBytes == 4) {
            writer.writeInt((int) (this.memoryAddress & 0xFFFFFFFFL));
        } else {
            throw new IOException("Can't write address length: " + memoryAddressBytes);
        }

        if (memorySizeBytes == 4) {
            writer.writeInt((int) (this.memorySize & 0xFFFFFFFFL));
        } else {
            throw new IOException("Can't write size length: " + memoryAddressBytes);
        }
    }

    public int getDataCompression() {
        return dataCompression;
    }

    public int getDataEncryption() {
        return dataEncryption;
    }

    public long getMemoryAddress() {
        return memoryAddress;
    }

    public int getMemoryAddressBytes() {
        return memoryAddressBytes;
    }

    public int getMemorySizeBytes() {
        return memorySizeBytes;
    }

    public long getMemorySize() {
        return memorySize;
    }

    public int getMemoryIdentifier() {
        return memoryIdentifier;
    }

    @Override
    public String toString() {
        return "comp=" + dataCompression + " crypto=" + dataEncryption
                + " memid=" + memoryIdentifier
                + " addr=" + (memoryAddress & 0xFFFFFFFFL) + " sz=" + memorySize;
    }
}
