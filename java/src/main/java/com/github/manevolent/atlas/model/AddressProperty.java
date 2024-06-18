package com.github.manevolent.atlas.model;

import java.util.Arrays;

public class AddressProperty extends ProjectProperty {
    private long address;

    public AddressProperty() {

    }

    public AddressProperty(long address) {
        this.address = address;
    }

    public long getAddress() {
        return address;
    }

    public void setAddress(long address) {
        this.address = address;
    }

    @Override
    public AddressProperty copy() {
        return new AddressProperty(address);
    }

    @Override
    public void apply(ProjectProperty other) {
        setAddress(((AddressProperty) other).getAddress());
    }
}
