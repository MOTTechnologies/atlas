package com.github.manevolent.atlas.protocol.subaru;

import com.github.manevolent.atlas.protocol.j2534.J2534Device;
import com.github.manevolent.atlas.protocol.subaru.uds.request.*;
import com.github.manevolent.atlas.protocol.uds.BasicUDSProtocol;
import com.github.manevolent.atlas.protocol.uds.UDSProtocol;
import com.github.manevolent.atlas.protocol.uds.UDSQuery;

public final class SubaruProtocols {

    /**
     * This doesn't seem to work, as flow control filter appears to be an exact match
     */
    public static final J2534Device.ISOTPFilter DIT_FILTER = new J2534Device.ISOTPFilter(
            new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x08},
            new byte[] { (byte)0x00, (byte)0x00, (byte)0x07, (byte)0x08},
            new byte[] { (byte)0x00, (byte)0x00, (byte)0x07, (byte)0x00}
    );

    public static final UDSProtocol DIT = new BasicUDSProtocol(
            UDSQuery.from("Subaru Status 0x1", 0x1, SubaruStatus1Request.class),
            UDSQuery.from("Subaru Read DTC", 0x3, SubaruReadDTCRequest.class),
            UDSQuery.from("Subaru Unknown 4", 0x4, Subaru4Request.class),
            UDSQuery.from("Subaru Read DTC 2", 0x7, SubaruStatus7Request.class), // seen sent to transmission
            UDSQuery.from("Vendor Info", 0x9, SubaruVendorInfoRequest.class)
    ).layer(UDSProtocol.STANDARD);

}
