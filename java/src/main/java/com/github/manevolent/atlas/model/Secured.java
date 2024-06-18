package com.github.manevolent.atlas.model;

import java.util.*;

public interface Secured {

    static <T> List<T> asPublic(List<T> list) {
        List<T> confidential = new ArrayList<>();
        list.stream()
                .filter(s -> !(s instanceof Secured secured) || !secured.isConfidential())
                .forEach(confidential::add);
        return confidential;
    }

    static <T> Set<T> asPublic(Set<T> list) {
        Set<T> confidential = new LinkedHashSet<>();
        list.stream()
                .filter(s -> !(s instanceof Secured secured) || !secured.isConfidential())
                .forEach(confidential::add);
        return confidential;
    }

    static <T> List<T> asConfidential(List<T> list) {
        List<T> confidential = new ArrayList<>();
        list.stream()
                .filter(s -> (s instanceof Secured secured) && secured.isConfidential())
                .forEach(confidential::add);
        return confidential;
    }

    static <T> Set<T> asConfidential(Set<T> list) {
        Set<T> confidential = new LinkedHashSet<>();
        list.stream()
                .filter(s -> (s instanceof Secured secured) && secured.isConfidential())
                .forEach(confidential::add);
        return confidential;
    }


    boolean isConfidential();

    void setConfidential(boolean confidential);

}
