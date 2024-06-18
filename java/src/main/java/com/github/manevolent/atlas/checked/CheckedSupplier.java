package com.github.manevolent.atlas.checked;

import java.util.function.Supplier;

public interface CheckedSupplier<T, E extends Exception> extends Supplier<T> {

    @Override
    default T get() {
        try {
            return getChecked();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    T getChecked() throws E;

}
