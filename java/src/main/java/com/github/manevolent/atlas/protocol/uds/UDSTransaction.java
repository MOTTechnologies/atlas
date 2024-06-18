package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.Addressed;
import com.github.manevolent.atlas.protocol.can.CANArbitrationId;
import com.github.manevolent.atlas.protocol.uds.response.UDSNegativeResponse;
import com.google.common.collect.Streams;
import org.checkerframework.checker.units.qual.A;

import java.io.Closeable;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;

public abstract class UDSTransaction<Q extends UDSRequest<T>, T extends UDSResponse> implements Closeable {
    public static final int DEFAULT_TIMEOUT_MILLIS = 2_000;

    private final Class<Q> requestClass;
    private final Class<T> responseClass;
    private final boolean responseExpected;
    private final List<UDSFrame> responses = new ArrayList<>();
    private final List<IOException> exceptions = new ArrayList<>();

    private boolean closed = false;

    public UDSTransaction(Class<Q> requestClass, Class<T> responseClass, boolean responseExpected) {
        this.requestClass = requestClass;
        this.responseClass = responseClass;
        this.responseExpected = responseExpected;

    }

    /**
     * Finds if the transaction has been closed.
     * @return true if an invocation to close() was completed, false otherwise.
     */
    public boolean isClosed() {
        return closed;
    }

    /**
     * Finds if a response is expected from this transaction
     * @return true if a response is expected, false otherwise.
     */
    public boolean isResponseExpected() {
        return responseExpected;
    }

    /**
     * Peeks at the oldest, or first received response, if available.
     * @return oldest, or first received response.
     */
    @SuppressWarnings("unchecked")
    public T peekFirst() {
        synchronized (this) {
            return responses.isEmpty() ? null : (T) responses.getFirst().getBody();
        }
    }

    /**
     * Peeks at the newest, or last received response, if available.
     * @return newest, or last received response.
     */
    @SuppressWarnings("unchecked")
    public T peekLast() {
        synchronized (this) {
            return responses.isEmpty() ? null : (T) responses.getLast().getBody();
        }
    }

    /**
     * Peeks at all responses received.
     * @return all immediately available, queued responses.
     */
    @SuppressWarnings("unchecked")
    public List<T> peekAll() {
        synchronized (this) {
            return Collections.unmodifiableList(responses).stream().map(f -> (T) f.getBody()).toList();
        }
    }

    /**
     * Gets the first exception encountered, if one exists.
     * @return exception
     */
    public IOException peekException() {
        synchronized (this) {
            return exceptions.stream().findFirst().orElse(null);
        }
    }

    /**
     * Gets the first negative response object, if one exists.
     * @return negative response
     */
    public UDSNegativeResponse peekNegativeResponse() {
        IOException exception = peekException();
        return exception instanceof UDSNegativeResponseException nre ? nre.getResponse() : null;
    }

    /**
     * From the perspective of the supplier (receiver), supply a response frame to the transaction invoker.
     * @param frame response frame to immediately supply.
     */
    public void supply(UDSFrame frame) {
        if (closed) {
            throw new IllegalStateException("transaction was closed");
        }

        if (!responseClass.isAssignableFrom(frame.getBody().getClass())) {
            throw new ClassCastException(frame.getBody().getClass().toString());
        }

        synchronized (this) {
            this.responses.add(frame);
            this.notify();
        }
    }

    /**
     * From the perspective of the supplier (receiver), supply an exception to the transaction invoker. This is
     * non-blocking.
     *
     * @param exception exception to immediately supply.
     */
    public void supplyException(Address address, UDSNegativeResponse exception) {
        supplyException(new UDSNegativeResponseException(address, exception));
    }

    /**
     * From the perspective of the supplier (receiver), supply an exception to the transaction invoker.
     * @param exception exception to immediately supply.
     */
    public void supplyException(IOException exception) {
        synchronized (this) {
            this.exceptions.add(exception);
            this.notifyAll();
        }
    }

    /**
     * Gets the next reply to the transaction.
     *
     * @param timeUnit time unit.
     * @param duration duration to receive the first response message, of the prior time unit.
     * @return transaction result.
     * @throws IOException if there was a problem with the transaction.
     * @throws InterruptedException if waiting for a transaction response was interrupted.
     * @throws TimeoutException if a timeout was encountered while waiting for the transaction to receive a response.
     */
    public T get(long duration, TimeUnit timeUnit) throws InterruptedException, IOException, TimeoutException {
        return get(timeUnit.toMillis(duration));
    }

    /**
     * Gets the next reply to the transaction.
     *
     * @param timeoutMillis timeout to receive the first response message, in milliseconds.
     * @return transaction result, or null if no response is expected.
     * @throws IOException if there was a problem with the transaction.
     * @throws InterruptedException if waiting for a transaction response was interrupted.
     * @throws TimeoutException if a timeout was encountered while waiting for the transaction to receive a response.
     */
    public T get(long timeoutMillis) throws IOException, InterruptedException, TimeoutException {
        if (!responseExpected) {
            return null;
        }

        synchronized (this) {
            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < timeoutMillis
                    && this.responses.isEmpty() && this.exceptions.isEmpty()) {
                if (closed) {
                    throw new IllegalStateException("transaction was closed");
                }

                this.wait(timeoutMillis);
            }

            if (System.currentTimeMillis() - start >= timeoutMillis) {
                throw new TimeoutException("Timeout waiting for response to " + requestClass.getSimpleName());
            }

            IOException exception = peekException();
            if (peekException() != null) {
                // Re-throwing the exception ensures we get both halves of the stack trace
                if (exception instanceof UDSNegativeResponseException nre) {
                    throw new UDSNegativeResponseException(nre);
                } else {
                    throw new IOException(exception);
                }
            }

            //noinspection unchecked
            return (T) this.responses.removeFirst().getBody();
        }
    }

    /**
     * Gets the next result to the message, waiting for a default time of 2 seconds.
     * @return transaction result.
     * @throws IOException if there was a problem with the transaction.
     * @throws InterruptedException if waiting for a transaction response was interrupted.
     * @throws TimeoutException if a timeout was encountered while waiting for the transaction to receive a response.
     */
    public T get() throws IOException, InterruptedException, TimeoutException {
        return get(DEFAULT_TIMEOUT_MILLIS);
    }

    /**
     * Gets the next result to the message from a specific component, waiting for a default time of 2 seconds.
     *
     * @param component component to listen for a response from
     * @return transaction result.
     * @throws IOException if there was a problem with the transaction.
     * @throws InterruptedException if waiting for a transaction response was interrupted.
     * @throws TimeoutException if a timeout was encountered while waiting for the transaction to receive a response.
     */
    public T get(UDSComponent component) throws IOException, InterruptedException, TimeoutException {
        return get(component, DEFAULT_TIMEOUT_MILLIS);
    }

    /**
     * Gets the next reply to the transaction from a specific component, with a specified timeout.
     *
     * @param component component to listen for a response from
     * @param timeoutMillis timeout to receive the first response message, in milliseconds.
     * @return transaction result, or null if no response is expected.
     * @throws IOException if there was a problem with the transaction.
     * @throws InterruptedException if waiting for a transaction response was interrupted.
     * @throws TimeoutException if a timeout was encountered while waiting for the transaction to receive a response.
     */
    public T get(UDSComponent component, long timeoutMillis)
            throws IOException, InterruptedException, TimeoutException {
        CANArbitrationId replyAddress = component.getReplyAddress();

        synchronized (this) {
            long start = System.currentTimeMillis();
            while (System.currentTimeMillis() - start < timeoutMillis) {
                UDSFrame frame = responses.stream()
                        .filter(f -> f instanceof Addressed a && a.getAddress().equals(replyAddress))
                        .findFirst()
                        .orElse(null);

                if (frame != null) {
                    responses.remove(frame);

                    //noinspection unchecked
                    return (T) frame.getBody();
                }

                IOException exception = exceptions.stream().filter(e ->
                        e instanceof UDSNegativeResponseException n && n.getAddress().equals(replyAddress) ||
                                !(e instanceof UDSNegativeResponseException)
                ).findFirst().orElse(null);

                if (exception != null) {
                    if (exception instanceof UDSNegativeResponseException nre) {
                        throw new UDSNegativeResponseException(nre);
                    } else {
                        throw new IOException(exception);
                    }
                }

                if (closed) {
                    throw new IllegalStateException("transaction was closed");
                }

                this.wait(timeoutMillis);
            }

            throw new TimeoutException("Timeout waiting for response to " + requestClass.getSimpleName()
                    + " from 0x" + replyAddress.toString());
        }
    }

    /**
     * Waits for any response in the transaction, but does not throw any exceptions if failures are encountered.
     * Waits indefinitely.
     * @throws TimeoutException if a timeout occurred waiting for any response to the state.
     */
    public void join() throws InterruptedException {
        try {
            join(Integer.MAX_VALUE);
        } catch (TimeoutException e) {
            // This is a bug if this is thrown
            throw new RuntimeException("A timeout was encountered that should never occur", e);
        }
    }

    /**
     * Waits for any response in the transaction, but does not throw any exceptions if failures are encountered.
     * @param timeout if a timeout occurred waiting for any response to the state.
     * @throws TimeoutException if a timeout occurred waiting for any response to the state.
     */
    public void join(long timeout) throws TimeoutException, InterruptedException {
        try {
            get(timeout);
        } catch (IOException e) {
            // Ignored
        }
    }

    /**
     * Waits for any response in the transaction, but does not throw any exceptions if failures are encountered.
     * @throws TimeoutException if a timeout occurred waiting for any response to the state.
     */
    public void join(long duration, TimeUnit unit) throws TimeoutException, InterruptedException {
        try {
            get(duration, unit);
        } catch (IOException e) {
            // Ignored
        }
    }

    /**
     * Streams responses from the receiver, up until any negative responses are received.
     * @param timeout timeout to wait for any single response.
     * @param count expected number of responses to receive.
     * @return stream of responses.
     */
    public Stream<T> stream(long timeout, int count) {
        return Streams.stream(new Iterator<T>() {
            int i = 0;

            @Override
            public boolean hasNext() {
                return i < count;
            }

            @Override
            public T next() {
                try {
                    T response = get(timeout);
                    i ++;
                    return response;
                } catch (InterruptedException | IOException | TimeoutException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    /**
     * Collects any responses received in this transaction, including any negative responses.
     * @param timeout timeout to wait for any single response.
     * @return a list of all collected responses during the method invocation.
     * @throws InterruptedException if waiting for a transaction response was interrupted.
     * @throws IOException if a reception error was encountered while waiting for a response.
     */
    public List<UDSResponse> collect(long timeout) throws InterruptedException, IOException {
        List<UDSResponse> responses = new ArrayList<>();

        while (true) {
            try {
                responses.add(get(timeout));
            } catch (UDSNegativeResponseException e) {
                responses.add(e.getResponse());
            } catch (TimeoutException e) {
                break;
            }
        }

        return Collections.unmodifiableList(responses);
    }

    @Override
    public void close() {
        synchronized (this) {
            supplyException(new IOException("transaction was closed"));
            closed = true;
        }
    }
}
