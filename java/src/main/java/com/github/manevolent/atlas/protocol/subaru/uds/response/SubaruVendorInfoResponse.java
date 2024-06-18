package com.github.manevolent.atlas.protocol.subaru.uds.response;

import com.github.manevolent.atlas.BitReader;
import com.github.manevolent.atlas.BitWriter;
import com.github.manevolent.atlas.Frame;
import com.github.manevolent.atlas.protocol.subaru.uds.SubaruVendorInfoRecord;
import com.github.manevolent.atlas.protocol.uds.UDSResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class SubaruVendorInfoResponse extends UDSResponse {
    private final Map<SubaruVendorInfoRecord, byte[]> records;

    public SubaruVendorInfoResponse() {
        records = new LinkedHashMap<>();
    }

    public SubaruVendorInfoResponse(Map<SubaruVendorInfoRecord, byte[]> responses) {
        this.records = responses;
    }

    @Override
    public void read(BitReader reader) throws IOException {
        while (reader.remainingBytes() > 0) {
            int code = reader.readByte() & 0xFF;
            SubaruVendorInfoRecord record = SubaruVendorInfoRecord.find(code);
            byte[] data = reader.readBytes(record.getLength());
            records.put(record, data);
        }
    }

    @Override
    public void write(BitWriter writer) throws IOException {
        for (SubaruVendorInfoRecord record : records.keySet()) {
            writer.write(record.getCode() & 0xFF);
            writer.write(records.get(record));
        }
    }

    public byte[] get(SubaruVendorInfoRecord record) {
        return records.get(record);
    }

    public String getAsString(SubaruVendorInfoRecord record) {
        byte[] data = get(record);
        StringBuilder builder = new StringBuilder();
        for (int i = 1; i < data.length; i ++) {
            char c = (char) data[i];
            if (c == 0x00) { // EOL
                break;
            } else {
                builder.append(c);
            }
        }
        return builder.toString();
    }

    public void set(SubaruVendorInfoRecord record, byte[] data) {
        byte[] extended = new byte[record.getLength()];
        System.arraycopy(data, 0, extended, 0, data.length);
        records.put(record, extended);
    }

    public void set(SubaruVendorInfoRecord record, String string) {
        byte[] data = string.getBytes(StandardCharsets.US_ASCII);
        byte[] extended = new byte[data.length + 1];
        extended[0] = 0x1;
        System.arraycopy(data, 0, extended, 1, data.length);
        set(record, extended);
    }

    @Override
    public String toString() {
        return "records=" + records.entrySet().stream().map(r ->
                String.format("{%s=%s}", r.getKey(), Frame.toHexString(r.getValue())))
                .collect(Collectors.joining(","));
    }

}
