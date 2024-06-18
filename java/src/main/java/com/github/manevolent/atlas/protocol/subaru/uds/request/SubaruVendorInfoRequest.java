package com.github.manevolent.atlas.protocol.subaru.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.subaru.uds.SubaruVendorInfoRecord;

import com.github.manevolent.atlas.protocol.subaru.uds.response.SubaruVendorInfoResponse;
import com.github.manevolent.atlas.protocol.uds.UDSRequest;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

public class SubaruVendorInfoRequest extends UDSRequest<SubaruVendorInfoResponse> {
    private int[] codes;

    public SubaruVendorInfoRequest() {

    }

    public SubaruVendorInfoRequest(int code) {
        this.codes = new int[] { code };
    }

    public SubaruVendorInfoRequest(int[] codes) {
        this.codes = codes;
    }

    public SubaruVendorInfoRequest(SubaruVendorInfoRecord record) {
        this(record.getCode());
    }

    public SubaruVendorInfoRequest(SubaruVendorInfoRecord[] records) {
        this(Arrays.stream(records).mapToInt(SubaruVendorInfoRecord::getCode).toArray());
    }

    public int[] getCodes() {
        return codes;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        byte[] codes = reader.readRemaining();
        this.codes = new int[codes.length];
        for (int i = 0; i < codes.length; i ++) {
            this.codes[i] = codes[i] & 0xFF;
        }
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        for (int code : codes) {
            writer.write(code & 0xFF);
        }
    }

    @Override
    public String toString() {
        return "codes=" + Arrays.stream(codes).mapToObj(c -> String.format("0x%02X", c))
                .collect(Collectors.joining(","));
    }

}
