package com.github.manevolent.atlas.graphics;

import com.github.manevolent.atlas.model.Color;

public class Point3F {
    private float x, y, z;

    public Point3F(float x, float y, float z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public Point3F(java.awt.Color color) {
        this(color.getRed() / 255f, color.getGreen() / 255f, color.getBlue() / 255f);
    }

    public Point3F(Color color) {
        this(color.getRed() / 255f, color.getGreen() / 255f, color.getBlue() / 255f);
    }

    public float getX() {
        return x;
    }

    public float getY() {
        return y;
    }

    public float getZ() {
        return z;
    }

    public void setX(float x) {
        this.x = x;
    }

    public void setY(float y) {
        this.y = y;
    }

    public void setZ(float z) {
        this.z = z;
    }

    public Point3F add(float x, float y) {
        return new Point3F(this.x + x, this.y + y, this.z);
    }

    public Point3F add(float x, float y, float z) {
        return new Point3F(this.x + x, this.y + y, this.z + z);
    }
}
