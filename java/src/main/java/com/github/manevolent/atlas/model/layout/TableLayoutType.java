package com.github.manevolent.atlas.model.layout;

public enum TableLayoutType {
    STANDARD("Standard", new StandardTableLayout.Factory());

    private final TableLayoutFactory factory;
    private final String name;

    TableLayoutType(String name, TableLayoutFactory tableLayout) {
        this.factory = tableLayout;
        this.name = name;
    }

    public TableLayoutFactory getFactory() {
        return factory;
    }

    @Override
    public String toString() {
        return name;
    }
}

