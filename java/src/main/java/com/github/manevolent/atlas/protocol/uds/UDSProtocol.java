package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.protocol.uds.request.*;
import com.github.manevolent.atlas.protocol.uds.response.*;

public interface UDSProtocol {

    BasicUDSProtocol STANDARD = new BasicUDSProtocol(
            UDSQuery.from("Diagnostic Session Control", 0x10, UDSDiagSessionControlRequest.class),
            UDSQuery.from("ECU Reset", 0x11, UDSECUResetRequest.class),
            UDSQuery.from("Read DTC", 0x19, UDSReadDTCRequest.class),
            UDSQuery.from("Security Access", 0x27, UDSSecurityAccessRequest.class),
            UDSQuery.from("Communication Control", 0x28, UDSCommunicationControlRequest.class),
            UDSQuery.from("Authentication", 0x29, UDSAuthenticationRequest.class),
            UDSQuery.from("Write Data by Identifier", 0x2E, UDSWriteDataByIDRequest.class),
            UDSQuery.from("Tester Present", 0x3E, UDSTesterPresentRequest.class),
            UDSQuery.from("Access Timing Parameters", 0x83, UDSAccessTimingParametersRequest.class),
            UDSQuery.from("Read Data by ID", 0x22, UDSReadDataByIDRequest.class),
            UDSQuery.from("Read Memory by Address", 0x23, UDSReadMemoryByAddressRequest.class),
            UDSQuery.from("Dynamically Define Data Identifier", 0x2C, UDSDefineDataIdentifierRequest.class),
            UDSQuery.from("Routine Control", 0x31, UDSRoutineControlRequest.class),
            UDSQuery.from("Control DTC Settings", 0x85, UDSControlDTCSettingsRequest.class),
            UDSQuery.from("Reset DTC Information", 0x14, UDSClearDTCInformationRequest.class),
            UDSQuery.from("Download", 0x34, UDSDownloadRequest.class),
            UDSQuery.from("Upload", 0x35, UDSUploadRequest.class),
            UDSQuery.from("Transfer", 0x36, UDSTransferRequest.class),
            UDSQuery.from("Transfer Exit", 0x37, UDSTransferExitRequest.class),
            UDSQuery.from("Negative", UDSSide.RESPONSE, 0x7F, UDSNegativeResponse.class)
    );

    UDSQuery getBySid(int sid) throws IllegalArgumentException;

    default Class<? extends UDSBody> getClassBySid(int sid) throws IllegalArgumentException, IllegalStateException {
        UDSQuery query = getBySid(sid);
        UDSMapping<?> mapping = query.getMapping(sid);
        if (mapping == null) {
            throw new IllegalArgumentException("unknown SID " + sid);
        }

        return mapping.getBodyClass();
    }

    /**
     * Layers the given protocol over another protocol
     * @param lower lower layer protocol
     * @return layered UDS protocol
     */
    default LayeredUDSProtocol layer(UDSProtocol lower) {
        return new LayeredUDSProtocol(this, lower);
    }

    int getSid(Class<? extends UDSBody> clazz);

}
