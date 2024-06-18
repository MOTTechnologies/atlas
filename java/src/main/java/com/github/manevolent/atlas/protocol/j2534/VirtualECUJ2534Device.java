package com.github.manevolent.atlas.protocol.j2534;

import com.github.manevolent.atlas.BasicFrame;
import com.github.manevolent.atlas.FrameReader;
import com.github.manevolent.atlas.FrameWriter;
import com.github.manevolent.atlas.connection.subaru.SubaruDIPlatform;
import com.github.manevolent.atlas.connection.subaru.SubaruDIVirtualECU;
import com.github.manevolent.atlas.model.Project;
import com.github.manevolent.atlas.protocol.can.CANFrame;
import com.github.manevolent.atlas.protocol.isotp.ISOTPFrame;
import com.github.manevolent.atlas.settings.Setting;
import com.github.manevolent.atlas.settings.Settings;
import com.github.manevolent.atlas.settings.StringSetting;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class VirtualECUJ2534Device implements J2534Device {
    @Override
    public CANDevice openCAN(CANFilter... filters) throws IOException {
        return new DebugCANDevice();
    }

    @Override
    public DebugISOTPDevice openISOTOP(ISOTPFilter... filters) throws IOException {
        return new DebugISOTPDevice();
    }

    @Override
    public void setConfig(int protocol, int parameter, int value) throws IOException {

    }

    @Override
    public int getConfig(int protocol, int parameter) throws IOException {
        return 0;
    }

    @Override
    public void close() throws IOException {

    }

    public static class DebugCANDevice implements CANDevice {
        @Override
        public FrameReader<CANFrame> reader() {
            throw new UnsupportedOperationException();
        }

        @Override
        public FrameWriter<CANFrame> writer() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() throws IOException {
            // Do nothing
        }
    }

    public static class DebugISOTPDevice implements com.github.manevolent.atlas.protocol.j2534.ISOTPDevice {
        @Override
        public FrameReader<ISOTPFrame> reader() {
            throw new UnsupportedOperationException();
        }

        @Override
        public FrameWriter<BasicFrame> writer() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() throws IOException {
            // Do nothing
        }
    }

    public static class Descriptor implements J2534DeviceDescriptor {
        @Override
        public J2534Device createDevice(Project project) throws IOException {
            return new VirtualECUJ2534Device();
        }

        @Override
        public String toString() {
            return "Generic Debug Device";
        }
    }

    public static class Provider implements J2534DeviceProvider<J2534DeviceDescriptor> {
        private static final StringSetting descriptorSetting =
                Setting.string(VirtualECUJ2534Device.class.getName() + ".descriptor");

        private static final StringSetting subaruDIPlatform =
                Setting.string(VirtualECUJ2534Device.class.getName() + ".subaruDIPlatform");

        public Provider() {

        }

        @Override
        public J2534DeviceDescriptor getDefaultDevice() throws DeviceNotFoundException {
            String descriptorClass = descriptorSetting.get();
            if (descriptorClass == null) {
                return null;
            }

            if (descriptorClass.equals(Descriptor.class.getName())) {
                return new Descriptor();
            } else if (descriptorClass.equals(SubaruDIVirtualECU.DeviceDescriptor.class.getName())) {
                SubaruDIPlatform platform = SubaruDIPlatform.valueOf(Settings.getOptional(subaruDIPlatform).orElseThrow());
                return new SubaruDIVirtualECU(platform).getDescriptor();
            } else {
                throw new DeviceNotFoundException(descriptorClass);
            }
        }

        @Override
        public void setDefaultDevice(J2534DeviceDescriptor descriptor) {
            Settings.set(descriptorSetting, descriptor.getClass().getName());

            if (descriptor instanceof SubaruDIVirtualECU.DeviceDescriptor virtualECU) {
                Settings.set(subaruDIPlatform, virtualECU.getPlatform().name());
            }
        }

        @Override
        public List<J2534DeviceDescriptor> getAllDevices() {
            List<J2534DeviceDescriptor> descriptors = new ArrayList<>();
            descriptors.add(new Descriptor());

            for (SubaruDIPlatform platform : SubaruDIPlatform.values()) {
                descriptors.add(new SubaruDIVirtualECU(platform).getDescriptor());
            }

            return descriptors;
        }
    }
}
