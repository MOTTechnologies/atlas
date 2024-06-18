package com.github.manevolent.atlas.checked;

import java.util.function.Function;

public interface CheckedFunction<T, R, E extends Exception> extends Function<T, R> {

    @Override
    default R apply(T object) {
        try {
            return applyChecked(object);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    R applyChecked(T object) throws E;

}
