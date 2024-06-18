package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.protocol.uds.response.UDSNegativeResponse;

import java.io.IOException;

public class UDSNegativeResponseException extends IOException {
    private final Address address;
    private final UDSNegativeResponse response;

    public UDSNegativeResponseException(Address address, UDSNegativeResponse response) {
        super(response.toString());

        this.address = address;
        this.response = response;
    }

    public UDSNegativeResponseException(UDSNegativeResponseException exception) {
        super(exception);

        this.address = exception.getAddress();
        this.response = exception.getResponse();
    }

    public Address getAddress() {
        return address;
    }

    public UDSNegativeResponse getResponse() {
        return response;
    }
}
