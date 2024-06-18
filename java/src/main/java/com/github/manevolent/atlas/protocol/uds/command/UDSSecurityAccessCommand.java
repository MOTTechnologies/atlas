package com.github.manevolent.atlas.protocol.uds.command;

import com.github.manevolent.atlas.protocol.uds.UDSComponent;
import com.github.manevolent.atlas.protocol.uds.UDSSession;
import com.github.manevolent.atlas.protocol.uds.UDSTransaction;
import com.github.manevolent.atlas.protocol.uds.request.UDSSecurityAccessRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSSecurityAccessResponse;

import java.io.IOException;


public abstract class UDSSecurityAccessCommand implements UDSCommand<UDSSecurityAccessRequest, UDSSecurityAccessResponse> {
    private final int seed;
    private final UDSComponent component;

    public UDSSecurityAccessCommand(int seed, UDSComponent component) {
        this.seed = seed;
        this.component = component;
    }

    public int getSeed() {
        return seed;
    }

    @Override
    public UDSComponent getComponent() {
        return component;
    }

    @Override
    public UDSSecurityAccessRequest newRequest() {
        return new UDSSecurityAccessRequest(seed, new byte[0]);
    }

    @SuppressWarnings("unchecked")
    @Override
    public void handle(UDSSession session, UDSSecurityAccessResponse response) throws IOException {
        if (response.getSeed().length == 0) {
            return;
        }

        UDSSecurityAccessRequest answer = answer(response);
        try (UDSTransaction<UDSSecurityAccessRequest, UDSSecurityAccessResponse> response2 =
                     session.request(getComponent().getSendAddress(), answer)) {
            handle(response2.get());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected abstract UDSSecurityAccessRequest answer(UDSSecurityAccessResponse challenge);
    protected abstract void handle(UDSSecurityAccessResponse result) throws IOException;
}
