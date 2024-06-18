package com.github.manevolent.atlas.math;

public class LinearInterpolationFunction implements InterpolationFunction {
    @Override
    public float interpolate(float a, float b, float v) {
        return a + ((b - a) * v);
    }
}
