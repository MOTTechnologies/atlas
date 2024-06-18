package com.github.manevolent.atlas.protocol.j2534;

import java.util.List;

public interface J2534DeviceProvider<T extends J2534DeviceDescriptor> {

    /**
     * Gets the default device from this provider, or throws IOException on failure.
     * @return default device.
     */
    T getDefaultDevice() throws DeviceNotFoundException;

    void setDefaultDevice(J2534DeviceDescriptor descriptor);

    List<T> getAllDevices();

    default T autoselectDevice() throws DeviceNotFoundException {
        T device = getDefaultDevice();

        if (device == null) {
            List<T> devices = getAllDevices();

            if (devices == null || devices.isEmpty()) {
                throw new NullPointerException("No J2534 devices were found.");
            }

            device = devices.getFirst();
        }

        return device;
    }

}
