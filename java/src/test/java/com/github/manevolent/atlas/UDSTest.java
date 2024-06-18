package com.github.manevolent.atlas;

import com.github.manevolent.atlas.protocol.uds.AsyncUDSSession;
import com.github.manevolent.atlas.protocol.uds.UDSFrame;
import com.github.manevolent.atlas.protocol.uds.request.UDSReadDataByIDRequest;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class UDSTest {

    @Test
    public void testWrite() throws IOException, TimeoutException, InterruptedException {
        int did = 0x1234;

        TestCANFrameWriter writer = new TestCANFrameWriter();
        TestJ2534Device testDevice = new TestJ2534Device(writer);
        AsyncUDSSession session = new AsyncUDSSession(testDevice.openISOTOP());
        session.request((Address)null, new UDSReadDataByIDRequest(new int[] { did }));

        byte[] written = writer.getWritten();

        TestCanFrameReader reader = new TestCanFrameReader(new ByteArrayInputStream(written));
        testDevice = new TestJ2534Device(reader);
        session = new AsyncUDSSession(testDevice.openISOTOP());
        UDSFrame read = session.reader().read();

        assertEquals(read.getBody().getClass(), UDSReadDataByIDRequest.class);
        assertArrayEquals(((UDSReadDataByIDRequest)read.getBody()).getDids(), new int[] { did });
    }

}
