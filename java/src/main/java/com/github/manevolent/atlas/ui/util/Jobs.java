package com.github.manevolent.atlas.ui.util;

import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;
import java.util.stream.Stream;

public class Jobs {

    public static Thread fork(Runnable runnable) {
        Thread thread = new Thread(runnable);
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    public static <T> List<T> parallelize(Stream<T> stream) throws ExecutionException, InterruptedException {
        try (ForkJoinPool pool = new ForkJoinPool(Math.max(1, Runtime.getRuntime().availableProcessors() - 1))) {
            return pool.submit(() -> stream.parallel().toList()).get();
        }
    }

}
