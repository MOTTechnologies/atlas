package com.github.manevolent.atlas.model;

import java.util.UUID;

public abstract class AbstractAnchored implements Anchored {
    private String uniqueId = UUID.randomUUID().toString();

    @Override
    public String get_anchor() {
        return uniqueId;
    }

    @Override
    public void set_anchor(String uuid) {
        if (uuid == null) {
            uuid = UUID.randomUUID().toString();
        }

        this.uniqueId = uuid;
    }
}
