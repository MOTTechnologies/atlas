package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.logging.Log;
import com.github.manevolent.atlas.model.*;

import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;
import com.github.manevolent.atlas.protocol.uds.UDSComponent;
import com.github.manevolent.atlas.protocol.uds.UDSProtocol;
import com.github.manevolent.atlas.protocol.uds.UDSSession;
import com.github.manevolent.atlas.protocol.uds.debug.DebugUDSSession;
import com.github.manevolent.atlas.protocol.uds.request.UDSDefineDataIdentifierRequest;
import com.github.manevolent.atlas.protocol.uds.request.UDSTesterPresentRequest;
import com.github.manevolent.atlas.ui.behavior.ProgressListener;
import com.google.common.collect.Sets;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.logging.Level;

public class DebugConnection extends UDSConnection {
    private final Platform debugPlatform = new DebugPlatform();
    private final Random random = new Random();
    private final Set<MemoryParameter> activeParameters = new LinkedHashSet<>();

    private SessionType sessionType;
    private long start = System.currentTimeMillis();

    public DebugConnection(Supplier<J2534DeviceProvider<?>> deviceProvider) {
        super(deviceProvider);
    }

    @Override
    public List<Platform> getPlatforms() {
        return List.of();
    }

    @Override
    public ConnectionType getType() {
        return ConnectionType.DEBUG;
    }

    @Override
    public SessionType getSessionType() {
        return sessionType;
    }

    @Override
    public Set<ConnectionFeature> getFeatures() {
        return Collections.unmodifiableSet(Sets.newHashSet(ConnectionFeature.values()));
    }

    @Override
    public MemoryFrame readFrame() {
        return new MemoryFrame();
    }

    @Override
    protected UDSProtocol getProtocol() {
        return UDSProtocol.STANDARD;
    }

    @Override
    protected UDSComponent getECUComponent() {
        return DebugUDSSession.COMPONENT;
    }

    @Override
    protected UDSSession newSession(SessionType type) {
        Log.can().log(Level.FINE, "Creating new session (" + type + ")");
        DebugUDSSession session = new DebugUDSSession();
        session.start();
        return session;
    }

    @Override
    public byte[] readMemory(MemoryAddress address, Variant variant, int length) throws IOException {
        Log.can().log(Level.FINE, "Read memory " + address + " (len=" + length + ")");

        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            throw new IOException(e);
        }

        return new byte[length];
    }

    @Override
    public Platform identify() {
        return null;
    }

    @Override
    public FlashResult writeCalibration(Platform platform, Calibration calibration, ProgressListener progressListener) throws FlashException {
        Log.can().log(Level.INFO, "Wrote calibration " + calibration);
        return new FlashResult(FlashResult.State.SUCCESS, 0);
    }

    @Override
    public Calibration readCalibration(Platform platform, ProgressListener progressListener) throws IOException, TimeoutException, InterruptedException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void change(ConnectionMode newMode) throws IOException, TimeoutException {
        // Sure thing, bud!
        sessionType = SessionType.NORMAL;
        setConnectionMode(newMode);
        Log.can().log(Level.INFO, "Debug session changed to " + newMode);

    }

    @Override
    protected int getNextDataIdentifierSize(List<MemoryParameter> parameters) {
        return 0;
    }

    @Override
    protected boolean keepAlive() throws IOException, TimeoutException, InterruptedException {
        Log.can().log(Level.FINE, "Sending keep-alive");

        getSession().request(getECUComponent().getSendAddress(), new UDSTesterPresentRequest(
                new byte[] { (byte) 0xBE, (byte) 0xEE, (byte) 0xEF }));
        return false;
    }

    public static class Factory implements ConnectionFactory {
        @Override
        public Connection createConnection(Supplier<J2534DeviceProvider<?>> provider) {
            return new DebugConnection(provider);
        }

        @Override
        public Set<ConnectionFeature> getSupportedFeatures() {
            return Collections.unmodifiableSet(Sets.newHashSet(ConnectionFeature.values()));
        }
    }

    private class DebugPlatform implements Platform {
        private final Vehicle vehicle;

        private DebugPlatform() {
            this.vehicle = Vehicle.builder().withMake("TestCo").withMarket("VDM").withModel("TestMachine")
                    .withTransmission("MT").withTrim("TestTrim").withYear("1990").build();
        }

        @Override
        public Vehicle getVehicle() {
            return vehicle;
        }

        @Override
        public Checksum getChecksum(Calibration calibration) {
            return new Checksum() {
                @Override
                public boolean validate(Calibration calibration) throws IOException {
                    return true;
                }

                @Override
                public void correct(Calibration calibration) throws IOException {

                }
            };
        }
    }
}
