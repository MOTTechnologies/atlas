package com.github.manevolent.atlas.connection;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

public abstract class AbstractConnection<L extends ConnectionListener> implements Connection {
    private final List<L> listeners = new LinkedList<>();

    protected void fireEvent(Consumer<? super L> invoke) {
        listeners.forEach(invoke);
    }

    public void addListener(L listener) {
        listeners.add(listener);
    }

    public boolean removeListener(L listener) {
        return listeners.remove(listener);
    }
}
