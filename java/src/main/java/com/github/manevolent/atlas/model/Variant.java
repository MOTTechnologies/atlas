package com.github.manevolent.atlas.model;

public class Variant extends AbstractAnchored implements Editable<Variant> {
    private String name;
    private OSType osType;

    public Variant() {

    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public OSType getOSType() {
        return osType;
    }

    public void setOSType(OSType osType) {
        this.osType = osType;
    }

    public static Variant.Builder builder() {
        return new Builder();
    }

    @Override
    public Variant copy() {
        Variant copy = new Variant();
        copy.name = this.name;
        copy.osType = this.osType;
        return copy;
    }

    @Override
    public void apply(Variant other) {
        this.name = other.name;
        this.osType = other.osType;
    }

    @Override
    public String toString() {
        return name;
    }

    public static class Builder {
        private final Variant variant = new Variant();

        public Builder withName(String name) {
            this.variant.name = name;
            return this;
        }

        public Builder withOSType(OSType type) {
            this.variant.osType = type;
            return this;
        }

        public Variant build() {
            return variant;
        }
    }
}
