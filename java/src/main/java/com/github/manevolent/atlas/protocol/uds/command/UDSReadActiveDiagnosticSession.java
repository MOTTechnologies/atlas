package com.github.manevolent.atlas.protocol.uds.command;

import com.github.manevolent.atlas.protocol.uds.flag.DataIdentifier;
import com.github.manevolent.atlas.protocol.uds.flag.DiagnosticSessionType;
import com.github.manevolent.atlas.protocol.uds.UDSComponent;
import com.github.manevolent.atlas.protocol.uds.flag.Flag;

public class UDSReadActiveDiagnosticSession extends UDSDataByIdSupplier<DiagnosticSessionType> {
    public UDSReadActiveDiagnosticSession(UDSComponent component) {
        super(component, DataIdentifier.DIAG_SESSION_DATA_ID.collapse());
    }

    @Override
    protected DiagnosticSessionType handle(byte[] data) {
        return Flag.find(DiagnosticSessionType.class, (int) data[0] & 0xFF).orElse(null);
    }
}
