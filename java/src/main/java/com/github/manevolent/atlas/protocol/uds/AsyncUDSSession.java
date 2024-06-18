package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.FrameWriter;

import com.github.manevolent.atlas.logging.Log;

import com.github.manevolent.atlas.protocol.j2534.ISOTPDevice;
import com.github.manevolent.atlas.protocol.uds.flag.NegativeResponseCode;
import com.github.manevolent.atlas.protocol.uds.response.UDSNegativeResponse;

import java.io.EOFException;
import java.io.IOException;

import java.util.HashMap;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.logging.Level;

public class AsyncUDSSession extends AbstractUDSSession implements UDSSession {
    private final ISOTPDevice device;
    private final UDSProtocol protocol;

    @SuppressWarnings("rawtypes")
    private final Map<Integer, UDSTransaction> activeTransactions = new HashMap<>();

    private final Reader readThread;
    private UDSFrameReader reader;
    private UDSFrameWriter writer;

    private boolean closed;

    private final Object[] writeLocks = new Object[0xFF];

    public AsyncUDSSession(ISOTPDevice device, UDSProtocol protocol) {
        this.device = device;
        this.protocol = protocol;
        this.readThread = new Reader();

        for (int i = 0; i < writeLocks.length; i ++) {
            writeLocks[i] = new Object();
        }
    }

    public AsyncUDSSession(ISOTPDevice device) {
        this(device, UDSProtocol.STANDARD);
    }

    public void start() {
        if (!this.readThread.isAlive()) {
            this.readThread.start();
        }
    }

    protected void ensureInitialized() {
        synchronized (this) {
            if (this.reader == null || this.writer == null) {
                this.reader = new UDSFrameReader(device.reader(), protocol) {
                    @Override
                    protected void onFrameRead(UDSFrame frame) {
                        AsyncUDSSession.this.onUDSFrameRead(frame);
                    }
                };

                this.writer = new UDSFrameWriter(device.writer(), protocol) {
                    @Override
                    protected void onFrameWrite(UDSFrame frame) {
                        AsyncUDSSession.this.onUDSFrameWrite(frame);
                    }
                };
            }
        }
    }

    public FrameReader<UDSFrame> reader() throws IOException {
        ensureInitialized();
        return reader;
    }

    public FrameWriter<UDSBody> writer() throws IOException {
        ensureInitialized();
        return writer;
    }

    protected long handle() throws IOException, TimeoutException {
        long n;
        for (n = 0; !closed;) {
            handleNext();
            n++;
        }
        return n;
    }

    @SuppressWarnings({"unchecked", "rawtypes", "resource"})
    protected UDSResponse handleNext() throws IOException, TimeoutException {
        UDSFrame frame = reader().read();
        if (frame == null) {
            return null;
        }

        if (frame.getBody() instanceof UDSResponse) {
            if (frame.getBody() instanceof UDSNegativeResponse negativeResponse) {
                if (negativeResponse.getResponseCode() == NegativeResponseCode.RESPONSE_PENDING) {
                    return null;
                }

                UDSTransaction transaction = activeTransactions.get(negativeResponse.getRejectedSid() & 0xFF);
                if (transaction != null) {
                    transaction.supplyException(frame.getAddress(), negativeResponse);
                }
            } else {
                int responseSid = frame.getServiceId();
                UDSQuery query = protocol.getBySid(responseSid);
                int serviceId = query.getMapping(UDSSide.REQUEST).getSid();
                UDSTransaction transaction = activeTransactions.get(serviceId & 0xFF);
                if (transaction != null) {
                    transaction.supply(frame);
                }
            }

            return (UDSResponse) frame.getBody();
        } else {
            // We're not expecting requests/etc.
            return null;
        }
    }

    //TODO this isn't really async
    public <T extends UDSResponse> void requestAsync(UDSComponent component, UDSRequest<T> request,
                                                     Consumer<T> callback) throws IOException {
        AtomicReference<Throwable> error = new AtomicReference<>();
        requestAsync(component.getSendAddress(), request, callback, error::set);
        Throwable throwable = error.getAcquire();
        if (throwable != null) {
            throw new IOException(throwable);
        }
    }

    //TODO this isn't really async
    public <T extends UDSResponse> void requestAsync(UDSComponent component, UDSRequest<T> request,
                                                Consumer<T> callback, Consumer<Exception> error) {
        requestAsync(component.getSendAddress(), request, callback, error);
    }

    //TODO this isn't really async
    public <Q extends UDSRequest<T>, T extends UDSResponse> void requestAsync(Address destination, Q request,
                                                             Consumer<T> callback, Consumer<Exception> error) {
        try (UDSTransaction<Q, T> transaction = request(destination, request)) {
            callback.accept(transaction.get());
        } catch (Exception e) {
            error.accept(e);
        }
    }

    @SuppressWarnings("unchecked")
    public <Q extends UDSRequest<T>, T extends UDSResponse>
    UDSTransaction<Q, T> request(Address destination, Q request)
            throws IOException, TimeoutException, InterruptedException {
        final int serviceId = protocol.getSid(request.getClass()) & 0xFF;
        Class<T> responseClass = (Class<T>) protocol.getBySid(serviceId).getMapping(UDSSide.RESPONSE).getBodyClass();

        synchronized (writeLocks[serviceId]) {
            UDSTransaction<Q, T> transaction;
            while ((transaction = activeTransactions.get(serviceId)) != null) {
                // Wait for any other transactions to complete before submitting another
                transaction.join(1, TimeUnit.SECONDS); // It would be unexpected, but this is so we don't block forever
            }

            // Construct the new transaction
            transaction = new UDSTransaction<>(
                    (Class<Q>) request.getClass(),
                    responseClass,
                    request.isResponseExpected()
            ) {
                @Override
                public void close() {
                    if (request.isResponseExpected() &&
                            !AsyncUDSSession.this.activeTransactions.remove(serviceId, this)) {
                        throw new IllegalStateException("transaction for sid 0x" + Integer.toHexString(serviceId)
                                + " not active");
                    }

                    super.close();
                }
            };

            if (request.isResponseExpected()) {
                activeTransactions.put(serviceId, transaction);
            }

            // Write to the bus
            try {
                writer().write(destination, request);
            } catch (IOException ex) {
                // If there is a failure, remove the transaction, otherwise we 'brick' this SID
                try {
                    transaction.close();
                } catch (Exception e) {
                    ex.addSuppressed(e);
                }

                throw ex;
            }

            // Return the transaction and release the lock
            return transaction;
        }
    }

    @Override
    public void close() throws IOException {
        if (!closed) {
            try {
                if (device != null) {
                    device.close();
                }

                if (readThread != null && readThread.isAlive()) {
                    readThread.interrupt();
                }

                if (reader != null) {
                    reader.close();
                }

                activeTransactions.clear();
            } finally {
                closed = true;
                onDisconnected(this);
            }
        }
    }

    private class Reader extends Thread {
        Reader() {
            this.setName("UDSSession/" + device.toString() + "/" + protocol.toString());
            this.setDaemon(true);
        }

        @Override
        public void run() {
            while (!interrupted() && !closed) {
                try {
                    handle();
                } catch (TimeoutException ex) {
                    continue;
                } catch (EOFException ex) {
                    break;
                } catch (Exception ex) {
                    Log.can().log(Level.WARNING, "Problem reading UDS frame", ex);
                }
            }

            try {
                close();
            } catch (IOException ex) {
                Log.can().log(Level.WARNING, "Problem closing UDS session", ex);
            }
        }
    }
}
