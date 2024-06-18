package com.github.manevolent.atlas.protocol.subaru;

import com.github.manevolent.atlas.ssm4.AES;
import com.github.manevolent.atlas.protocol.uds.UDSComponent;
import com.github.manevolent.atlas.protocol.uds.command.UDSSecurityAccessCommand;
import com.github.manevolent.atlas.protocol.uds.request.UDSSecurityAccessRequest;
import com.github.manevolent.atlas.protocol.uds.response.UDSSecurityAccessResponse;

import java.io.IOException;

public class SubaruSecurityAccessCommandAES extends UDSSecurityAccessCommand {
    private final byte[] aesKey;

    public SubaruSecurityAccessCommandAES(int seed, UDSComponent component, byte[] aesKey) {
        super(seed, component);

        this.aesKey = aesKey;
    }

    @Override
    protected UDSSecurityAccessRequest answer(UDSSecurityAccessResponse challenge) {
        assert challenge.getLevel() == getSeed();
        return new UDSSecurityAccessRequest(getSeed() + 1, AES.answer(aesKey, challenge.getData()));
    }

    @Override
    protected void handle(UDSSecurityAccessResponse result) throws IOException {
       if (result.getData().length != 0) {
           throw new IOException("Unexpected security access response: " + result.toString());
       }
    }
}
