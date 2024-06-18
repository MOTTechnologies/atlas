package com.github.manevolent.atlas.connection;

import com.github.manevolent.atlas.model.PropertyDefinition;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

public interface ConnectionFactory {

    /**
     * Creates a connection instance using a given provider
     * @param provider provider that will provide a J2534 device
     * @return connection
     */
    default Connection createConnection(J2534DeviceProvider<?> provider) {
        return createConnection(() -> provider);
    }

    /**
     * Creates a connection instance using a given provider supplier
     * @param provider supplier that will provide a J2534 provider
     * @return connection
     */
    Connection createConnection(Supplier<J2534DeviceProvider<?>> provider);

    /**
     * Gets the parameters for this connection that will be expected on a project.
     * @return list of parameters.
     */
    default List<PropertyDefinition> getPropertyDefinitions() {
        return Collections.emptyList();
    }

    /**
     * Gets the supported features for connections created from this factory.
     * @return supported features
     */
    Set<ConnectionFeature> getSupportedFeatures();

}
