package com.github.manevolent.atlas.protocol.j2534;

import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.FrameWriter;
import com.github.manevolent.atlas.protocol.can.CANFrame;

import java.io.Closeable;

/**
 * Represents a CAN device that can produce a reader and/or writer for transporting CAN bus frames.
 *
 * This is typically the result of opening a connection with a J2534 device that supports CAN-level
 * communications, and isn't to be confused with an ISO-TP device that communicates frames longer than
 * 8 bytes, which standard CAN is typically limited to.
 */
public interface CANDevice extends Closeable {

    /**
     * Requests a CAN frame reader from this device.
     * @return reader instance.
     * @throws UnsupportedOperationException if, for example, the device is write-only.
     */
    FrameReader<CANFrame> reader() throws UnsupportedOperationException;

    /**
     * Requests a CAN frame writer from this device.
     * @return writer instance.
     * @throws UnsupportedOperationException if, for example, the device is read-only.
     */
    FrameWriter<CANFrame> writer() throws UnsupportedOperationException;

}
