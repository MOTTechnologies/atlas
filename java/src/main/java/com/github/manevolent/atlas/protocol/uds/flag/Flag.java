package com.github.manevolent.atlas.protocol.uds.flag;

import java.util.Arrays;
import java.util.Optional;

public interface Flag {

    /**
     * Gets the specific code for this flag. The code should be unique among any others enumerated values of
     * this type.
     * @return unique code
     */
    int getCode();

    /**
     * Finds a constant in a provided enum
     * @param enumClass enumerator class
     * @param code code to search for
     * @return an optional representing the first encountered Flag in the search matching the provided code, if present.
     * @param <F> Flag type
     */
    static <F extends Flag> Optional<F> find(Class<F> enumClass, int code) {
        return find(enumClass.getEnumConstants(), code);
    }

    /**
     * Finds a constant in a provided array
     * @param array array of Flags
     * @param code code to search for
     * @return an optional representing the first encountered Flag in the search matching the provided code, if present.
     * @param <F> Flag type
     */
    static <F extends Flag> Optional<F> find(F[] array, int code) {
        return Arrays.stream(array)
                .filter(f -> f.getCode() == code)
                .findFirst();
    }

}
