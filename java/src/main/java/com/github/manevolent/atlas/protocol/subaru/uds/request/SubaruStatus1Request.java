package com.github.manevolent.atlas.protocol.subaru.uds.request;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.protocol.subaru.uds.response.SubaruStatus1Response;

import com.github.manevolent.atlas.protocol.uds.UDSRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class SubaruStatus1Request extends UDSRequest<SubaruStatus1Response> {

    private int[] codes;

    public SubaruStatus1Request() {

    }

    public SubaruStatus1Request(int code) {
        this.codes = new int[] { code };
    }

    public SubaruStatus1Request(int[] codes) {
        this.codes = codes;
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
