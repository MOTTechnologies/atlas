package com.github.manevolent.atlas.ui.util;

import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceType;
import com.github.manevolent.atlas.settings.Setting;
import com.github.manevolent.atlas.settings.Settings;

public class Devices {

    public static J2534DeviceType getType() {
        return Settings.getOptional(Settings.DEVICE_PROVIDER)
                .map(J2534DeviceType::valueOf)
                .orElse(J2534DeviceType.TACTRIX_SERIAL);
    }

    public static J2534DeviceProvider<?> getProvider() {
        return getType().getProvider();
    }

    public static void setType(J2534DeviceType newDeviceType) {
        Settings.set(Settings.DEVICE_PROVIDER, newDeviceType.name());
    }
}
