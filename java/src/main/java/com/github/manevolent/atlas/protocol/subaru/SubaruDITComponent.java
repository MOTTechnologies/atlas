package com.github.manevolent.atlas.protocol.subaru;

import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.uds.UDSComponent;

import static com.github.manevolent.atlas.protocol.can.CANArbitrationId.id;

public enum SubaruDITComponent implements UDSComponent {
    FRONT_RELAY_CONTROL(4601, id(0x744), id(0x74C)),
    POWER_STEERING(1201, id(0x746), id(0x74E)),
    HEADLIGHT(0, id(0x747), id(0x74F)),
    IMMOBILIZER(1301, id(0x750), id(0x758)),
    KEYLESS_ACCESS_1(1301, id(0x751), id(0x759)), // and push start
    BODY_CONTROL(501, id(0x752), id(0x75A)),
    TIRE_PRESSURE_MONITOR(0, id(0x753), id(0x75B)),
    CENTRAL_GATEWAY(4301, id(0x763), id(0x76B)),
    TELEMATICS(0, id(0x776), id(0x77E)),
    COMBINATION_METER(0, id(0x783),  id(0x78B)),
    AIRBAG(0, id(0x780), id(0x788)),
    ENGINE_1(102, id(0x7A2), id(0x7AA)),
    BRAKE_CONTROL(0, id(0x7B0), id(0x7B8)), // ABS?
    KEYLESS_ACCESS_3(1303, id(0x7B4), id(0x7BC)),
    KEYLESS_ACCESS_2(1302, id(0x7C1), id(0x7C9)),
    AIR_CONDITIONER(0, id(0x7C4), id(0x7CC)),
    INFOTAINMENT(0, id(0x7D0), id(0x7D8)),
    BROADCAST(-1, id(0x7DF), null),
    ENGINE_2(103, id(0x7E0),  id(0x7E8)),
    TRANSMISSION(201, id(0x7E1), id(0x7E9)),
    UNKNOWN_1(0, id(0x7E2), id(0x7EA)),
    UNKNOWN_2(0, id(0x7E3), id(0x7EB)),
    UNKNOWN_3(0, id(0x7E4), id(0x7EC)),
    UNKNOWN_4(0, id(0x7E5), id(0x7ED)),
    UNKNOWN_5(0, id(0x7E6), id(0x7EE)),
    UNKNOWN_6(0, id(0x7E7), id(0x7EF));

    private final int id;

    private final CANArbitrationId sendAddress;
    private final CANArbitrationId replyAddress;

    SubaruDITComponent(int id,
                       CANArbitrationId sendAddress) {
        this.id = id;
        this.sendAddress = sendAddress;
        this.replyAddress = id(sendAddress.getArbitrationId() + 8);
    }

    SubaruDITComponent(int id,
                       CANArbitrationId sendAddress,
                       CANArbitrationId replyAddress) {
        this.id = id;
        this.sendAddress = sendAddress;
        this.replyAddress = replyAddress;
    }

    public int getId() {
        return id;
    }

    @Override
    public CANArbitrationId getSendAddress() {
        return sendAddress;
    }

    @Override
    public CANArbitrationId getReplyAddress() {
        return replyAddress;
    }

}
