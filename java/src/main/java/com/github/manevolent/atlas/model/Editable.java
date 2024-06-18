package com.github.manevolent.atlas.model;

import java.util.*;

public interface Editable<T> {

    T copy();

    void apply(T other);

    @SuppressWarnings("unchecked")
    static <T, E extends Editable<T>> void apply(List<E> target, List<E> other) {
        target.clear();
        other.forEach(item -> target.add((E) item.copy()));
    }

    @SuppressWarnings("unchecked")
    static <K, T, E extends Editable<T>> void apply(Map<K, E> target, Map<K, E> other) {
        other.forEach((key, otherItem) -> {
            E value = target.get(key);
            if (value == null) {
                if (otherItem != null) {
                    target.put(key, (E) otherItem.copy());
                } else {
                    target.put(key, (E) null);
                }
            } else {
                value.apply((T) otherItem);
            }
        });
    }

    @SuppressWarnings("unchecked")
    static <T, E extends Editable<T>> List<E> copy(List<E> list) {
        List<E> copy = new ArrayList<>();
        list.forEach(item -> {
            if (item != null) {
                copy.add((E) item.copy());
            } else {
                copy.add(null);
            }
        });
        return copy;
    }

    @SuppressWarnings("unchecked")
    static <K, T, E extends Editable<T>> Map<K, E> copy(Map<K, E> map) {
        Map<K, E> copy = new LinkedHashMap<>();
        map.forEach((k, v) -> {
            if (v != null) {
                copy.put(k, (E) v.copy());
            } else {
                copy.put(k, null);
            }
        });
        return copy;
    }

}
