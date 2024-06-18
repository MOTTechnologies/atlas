package com.github.manevolent.atlas.protocol.uds;

import com.github.manevolent.atlas.Address;
import com.github.manevolent.atlas.connection.SessionType;
import com.github.manevolent.atlas.protocol.subaru.SubaruDITComponent;
import com.github.manevolent.atlas.protocol.uds.request.UDSCommunicationControlRequest;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;

public interface UDSSession extends Closeable {

    <Q extends UDSRequest<T>, T extends UDSResponse> UDSTransaction<Q, T> request(Address destination, Q request)
            throws IOException, TimeoutException, InterruptedException;

    default <Q extends UDSRequest<T>, T extends UDSResponse> List<T> request(UDSComponent component, Q request,
                                                                             UDSComponent... replies)
            throws IOException, TimeoutException, InterruptedException {
        List<T> responses = new ArrayList<>(replies.length);
        try (UDSTransaction<Q, T> transaction = request(component.getSendAddress(), request)) {
            for (UDSComponent reply : replies) {
                responses.add(transaction.get(reply));
            }
        }
        return responses;
    }

    default <Q extends UDSRequest<T>, T extends UDSResponse> T request(UDSComponent component,
                                                                       UDSComponent reply,
                                                                       Q request)
            throws IOException, TimeoutException, InterruptedException {
        try (UDSTransaction<Q, T> transaction = request(component.getSendAddress(), request)) {
            return transaction.get(reply);
        }
    }

    default <Q extends UDSRequest<T>, T extends UDSResponse> T request(UDSComponent component,
                                                                       UDSComponent reply, Q request, long timeout)
            throws IOException, TimeoutException, InterruptedException {
        try (UDSTransaction<Q, T> transaction = request(component.getSendAddress(), request)) {
            return transaction.get(reply, timeout);
        }
    }

    default <Q extends UDSRequest<T>, T extends UDSResponse> T request(UDSComponent component, Q request)
            throws IOException, TimeoutException, InterruptedException {
        try (UDSTransaction<Q, T> transaction = request(component.getSendAddress(), request)) {
            return transaction.get();
        }
    }

    default <Q extends UDSRequest<T>, T extends UDSResponse> T request(UDSComponent component, Q request, long timeout)
            throws IOException, TimeoutException, InterruptedException {
        try (UDSTransaction<Q, T> transaction = request(component.getSendAddress(), request)) {
            return transaction.get(timeout);
        }
    }

    default void send(UDSComponent component, UDSRequest<?> request) throws TimeoutException, InterruptedException {
        try {
            request(component, request);
        } catch (IOException e) {
            // Ignored
        } catch (TimeoutException | InterruptedException e) {
            throw e;
        }
    }

    default void send(UDSComponent component, UDSRequest<?> request, long timeout)
            throws TimeoutException, InterruptedException {
        try {
            request(component, request, timeout);
        } catch (IOException e) {
            // Ignored
        } catch (TimeoutException | InterruptedException e) {
            throw e;
        }
    }

    void addListener(UDSListener listener);

    boolean removeListener(UDSListener listener);

    boolean hasListener(UDSListener listener);
}
