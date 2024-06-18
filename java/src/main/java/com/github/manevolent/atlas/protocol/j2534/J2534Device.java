package com.github.manevolent.atlas.protocol.j2534;

import aQute.lib.io.IO;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.uds.UDSComponent;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public interface J2534Device extends Closeable {

    CANFilter CAN_ALL = new CANFilter(new byte[4], new byte[4]);
    ISOTPFilter ISOTP_ALL = new ISOTPFilter(new byte[4], new byte[4], new byte[4]);



    default CANDevice openCAN() throws IOException {
        return openCAN(new CANFilter[0]);
    }

    CANDevice openCAN(CANFilter... filters) throws IOException;

    default ISOTPDevice openISOTOP() throws IOException {
        return openISOTOP(new ISOTPFilter[0]);
    }

    ISOTPDevice openISOTOP(ISOTPFilter... filters) throws IOException;

    default <T extends UDSComponent> ISOTPDevice openISOTOP(List<T> components) throws IOException {
        return openISOTOP(components.stream().map(UDSComponent::toISOTPFilter)
                .toArray(J2534Device.ISOTPFilter[]::new));
    }

    default ISOTPDevice openISOTOP(UDSComponent... components) throws IOException {
        return openISOTOP(Arrays.stream(components).toList());
    }

    void setConfig(int protocol, int parameter, int value) throws IOException;

    default void setConfig(int protocol, J2534Parameter parameter, int value) throws IOException {
        setConfig(protocol, parameter.getCode(), value);
    }

    default void setConfig(J2534Protocol protocol, J2534Parameter parameter, int value) throws IOException {
        setConfig(protocol.getCode(), parameter.getCode(), value);
    }

    int getConfig(int protocol, int parameter) throws IOException;

    default int getConfig(int protocol, J2534Parameter parameter) throws IOException {
        return getConfig(protocol, parameter.getCode());
    }

    default int getConfig(J2534Protocol protocol, J2534Parameter parameter) throws IOException {
        return getConfig(protocol.getCode(), parameter.getCode());
    }

    class CANFilter {
        private final byte[] mask;
        private final byte[] pattern;

        public CANFilter(byte[] mask, byte[] pattern) {
            this.mask = mask;
            this.pattern = pattern;
        }

        public CANFilter(CANArbitrationId mask, CANArbitrationId pattern) {
            this.mask = mask.getData();
            this.pattern = pattern.getData();
        }

        public byte[] getMask() {
            return mask;
        }

        public byte[] getPattern() {
            return pattern;
        }
    }

    class ISOTPFilter extends CANFilter {
        private final byte[] flow;

        public ISOTPFilter(byte[] mask, byte[] pattern, byte[] flow) {
            super(mask, pattern);
            this.flow = flow;
        }

        public ISOTPFilter(CANArbitrationId mask, CANArbitrationId pattern, CANArbitrationId flow) {
            super(mask, pattern);
            this.flow = flow.getData();
        }

        public byte[] getFlow() {
            return flow;
        }

        public boolean testPattern(CANArbitrationId id) {
            byte[] data = id.getData();
            byte[] mask = getMask();
            byte[] maskResult = new byte[getMask().length];
            for (int i = 0; i < maskResult.length; i ++) {
                maskResult[i] = (byte) ((data[i] & 0xFF) & (mask[i] & 0xFF));
            }

            byte[] pattern = getPattern();
            for (int i = 0; i < pattern.length; i ++) {
                if (pattern[i] != maskResult[i])
                    return false;
            }

            return true;
        }

        public boolean testFlow(CANArbitrationId id) {
            byte[] data = id.getData();
            byte[] mask = getMask();
            byte[] maskResult = new byte[getMask().length];
            for (int i = 0; i < maskResult.length; i ++) {
                maskResult[i] = (byte) ((data[i] & 0xFF) & (mask[i] & 0xFF));
            }

            byte[] flow = getFlow();
            for (int i = 0; i < flow.length; i ++) {
                if (flow[i] != maskResult[i])
                    return false;
            }

            return true;
        }
    }

}
