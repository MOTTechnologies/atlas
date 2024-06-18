package com.github.manevolent.atlas.protocol.j2534.tactrix;

import com.fazecast.jSerialComm.SerialPort;

import com.github.manevolent.atlas.protocol.j2534.DeviceNotFoundException;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceDescriptor;
import com.github.manevolent.atlas.protocol.j2534.J2534DeviceProvider;

import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.settings.StringSetting;

import java.util.*;

public class SerialTactrixOpenPortProvider implements J2534DeviceProvider<SerialTactrixOpenPort.SerialPortDescriptor> {
    private static final StringSetting deviceSetting = new StringSetting("can.tactrix.serial.serialport.name");

    public SerialTactrixOpenPortProvider() {
    }

    @Override
    public void setDefaultDevice(J2534DeviceDescriptor descriptor) {
        if (descriptor instanceof SerialTactrixOpenPort.SerialPortDescriptor serialPortDescriptor) {
            Settings.set(deviceSetting, serialPortDescriptor.getPort().getSystemPortPath());
        }
    }

    @Override
    public SerialTactrixOpenPort.SerialPortDescriptor getDefaultDevice() throws DeviceNotFoundException {
        List<SerialTactrixOpenPort.SerialPortDescriptor> descriptors = getAllDevices();

        return Settings.getOptional(deviceSetting).map(deviceFile -> {
            Optional<SerialTactrixOpenPort.SerialPortDescriptor> descriptor =
                    descriptors.stream().filter(x -> x.getPort().getSystemPortPath().equals(deviceFile))
                            .findFirst();

            if (descriptor.isPresent()) {
                return descriptor.get();
            } else {
                throw new DeviceNotFoundException(deviceFile);
            }
        }).orElse(null);
    }

    @Override
    public List<SerialTactrixOpenPort.SerialPortDescriptor> getAllDevices() {
        return Arrays.stream(SerialPort.getCommPorts())
                .map(SerialTactrixOpenPort.SerialPortDescriptor::new).toList();
    }
}
