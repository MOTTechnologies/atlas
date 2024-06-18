package com.github.manevolent.atlas.model;

import org.checkerframework.checker.units.qual.C;

public class Color extends AbstractAnchored implements Editable<Color> {
    private int red, green, blue;

    public Color(int red, int green, int blue) {
        this.red = red;
        this.green = green;
        this.blue = blue;
    }

    public Color() {

    }

    public int getRed() {
        return red;
    }

    public int getGreen() {
        return green;
    }

    public int getBlue() {
        return blue;
    }

    public void setRed(int red) {
        this.red = red;
    }

    public void setGreen(int green) {
        this.green = green;
    }

    public void setBlue(int blue) {
        this.blue = blue;
    }

    public static Color fromAwtColor(java.awt.Color color) {
        return new Color(color.getRed(), color.getGreen(), color.getBlue());
    }

    public java.awt.Color toAwtColor() {
        return new java.awt.Color(red, green, blue);
    }

    public java.awt.Color toAwtColor(int alpha) {
        return new java.awt.Color(red, green, blue, alpha);
    }

    @Override
    public Color copy() {
        Color color = new Color();
        color.red = red;
        color.green = green;
        color.blue = blue;
        return color;
    }

    @Override
    public void apply(Color other) {
        this.red = other.red;
        this.green = other.green;
        this.blue = other.blue;
    }
}

