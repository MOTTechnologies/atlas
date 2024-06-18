package com.github.manevolent.atlas.protocol.uds.command;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.protocol.uds.*;


import java.io.IOException;
import java.util.concurrent.TimeoutException;

public interface UDSSupplier<R extends UDSRequest<S>, S extends UDSResponse, T> {

    UDSComponent getComponent();

    default Address getSendAddress() {
        return getComponent().getSendAddress();
    }

    R newRequest();

    T handle(S response);

    default T execute(UDSSession session) throws IOException, TimeoutException, InterruptedException {
        UDSComponent component = getComponent();
        R request = newRequest();
        S response;
        try (UDSTransaction<R, S> transaction = session.request(getSendAddress(), request)) {
            response = transaction.get();
        }
        return handle(response);
    }

}
