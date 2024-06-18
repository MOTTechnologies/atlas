package com.github.manevolent.atlas.checked;

import java.util.function.Consumer;

public interface CheckedConsumer<T, E extends Exception> extends Consumer<T> {

    @Override
    default void accept(T object) {
        try {
            acceptChecked(object);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    void acceptChecked(T object) throws E;

}
