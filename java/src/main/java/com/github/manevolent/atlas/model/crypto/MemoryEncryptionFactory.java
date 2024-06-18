package com.github.manevolent.atlas.model.crypto;

import com.github.manevolent.atlas.model.PropertyDefinition;

import java.util.Collections;
import java.util.List;

public interface MemoryEncryptionFactory {

    default List<PropertyDefinition> getPropertyDefinitions() {
        return Collections.emptyList();
    }

    MemoryEncryption create();

}
