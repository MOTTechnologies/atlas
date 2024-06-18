package com.github.manevolent.atlas.checked;

import java.util.function.BiFunction;

public interface CheckedBiFunction<S, T, R, E extends Exception> extends BiFunction<S, T, R> {

    @Override
    default R apply(S one, T two) {
        try {
            return applyChecked(one, two);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    R applyChecked(S one, T two) throws E;

}
