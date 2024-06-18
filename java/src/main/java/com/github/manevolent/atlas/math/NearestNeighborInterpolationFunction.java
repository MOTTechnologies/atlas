package com.github.manevolent.atlas.math;

public class NearestNeighborInterpolationFunction implements InterpolationFunction {
    @Override
    public float interpolate(float a, float b, float v) {
        return v > 0.5 ? b : a;
    }
}
