package com.github.manevolent.atlas.protocol.j2534;

public class DeviceNotFoundException extends RuntimeException {
    private final String name;

    public DeviceNotFoundException(String name) {
        this.name = name;
    }

    public DeviceNotFoundException(String name, Throwable e) {
        super(e);

        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String getMessage() {
        return name;
    }
}
