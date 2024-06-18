package com.github.manevolent.atlas.protocol.subaru;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.protocol.subaru.uds.request.SubaruReadDTCRequest;
import com.github.manevolent.atlas.protocol.subaru.uds.response.SubaruReadDTCResponse;
import com.github.manevolent.atlas.ssm4.Crypto;
import com.github.manevolent.atlas.protocol.uds.UDSComponent;
import com.github.manevolent.atlas.protocol.uds.command.UDSDataByIdSupplier;
import com.github.manevolent.atlas.protocol.uds.command.UDSSecurityAccessCommand;
import com.github.manevolent.atlas.protocol.uds.command.UDSSupplier;

import java.util.Set;

import static com.github.manevolent.atlas.protocol.subaru.SubaruDITComponent.ENGINE_1;

public final class SubaruDITCommands {

    public static final UDSDataByIdSupplier<Boolean> IGNITION_ON =
            new UDSDataByIdSupplier<>(ENGINE_1, 0x11C8) {
                @Override
                public Boolean handle(byte[] data) {
                    return data.length == 1 && data[0] == (byte) 0xFF;
                }
            };

    public static final UDSSupplier<SubaruReadDTCRequest, SubaruReadDTCResponse, Set<Short>>
            READ_DTC = new UDSSupplier<>() {
        @Override
        public UDSComponent getComponent() {
            return SubaruDITComponent.ENGINE_2;
        }

        @Override
        public Address getSendAddress() {
            return SubaruDITComponent.ENGINE_2.getSendAddress(); // Broadcast
        }

        @Override
        public SubaruReadDTCRequest newRequest() {
            return new SubaruReadDTCRequest();
        }

        @Override
        public Set<Short> handle(SubaruReadDTCResponse response) {
            return response.getDtcs();
        }
    };

}
