package com.github.manevolent.atlas.math;

public enum InterpolationType {
    LINEAR("Linear", new LinearInterpolationFunction()),
    NEAREST_NEIGHBOR("Nearest Neighbor", new NearestNeighborInterpolationFunction());

    private final String name;
    private final InterpolationFunction function;

    InterpolationType(String name, InterpolationFunction function) {
        this.name = name;
        this.function = function;
    }

    public InterpolationFunction getFunction() {
        return function;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return getName();
    }
}
