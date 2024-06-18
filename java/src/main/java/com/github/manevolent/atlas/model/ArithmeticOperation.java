package com.github.manevolent.atlas.model;

import java.util.function.BiFunction;

public enum ArithmeticOperation {
    ADD("+", (a, x) -> {
        if (a == null) {
            return String.format("x + %f", x);
        } else {
            return String.format("%f + %f", a, x);
        }
    }, (a, x) -> {
        return a + x;
    }, (a, x) -> {
        return a - x;
    }),

    SUBTRACT("-", (a, x) -> {
        if (a == null) {
            return String.format("x - %f", x);
        } else {
            return String.format("%f - %f", a, x);
        }
    }, (a, x) -> {
        return a - x;
    }, (a, x) -> {
        return a + x;
    }),

    EXPONENT("^", (a, x) -> {
        if (a == null) {
            return String.format("x ^ %f", x);
        } else {
            return String.format("%f ^ %f", a, x);
        }
    }, (a, x) -> {
        return (float) Math.pow(a, x);
    },(a, x) -> {
        return (float) Math.pow(a, 1f/x);
    }),

    MULTIPLY("*", (a, x) -> {
        if (a == null) {
            return String.format("x * %f", x);
        } else {
            return String.format("%f * %f", a, x);
        }
    }, (a, x) -> {
        return a * x;
    }, (a, x) -> {
        return a / x;
    }),

    DIVIDE("/", (a, x) -> {
        if (a == null) {
            return String.format("x / %f", x);
        } else {
            return String.format("%f / %f", a, x);
        }
    }, (a, x) -> {
        return a / x;
    }, (a, x) -> {
        return a * x;
    }),

    INVERSE_DIVIDE("/ (inverse)", (a, x) -> {
        if (a == null) {
            return String.format("%f / x", x);
        } else {
            return String.format("%f / %f", x, a);
        }
    }, (a, x) -> {
        return x / a;
    }, (a, x) -> {
        return x / a;
    }),

    RSHIFT(">>", (a, x) -> {
        if (a == null) {
            return String.format("x >> %f", x);
        } else {
            return String.format("%f >> %f", a, x);
        }
    }, (a, x) -> {
        return a / (float)Math.pow(2, x.intValue());
    }, (a, x) -> {
        return a * (float)Math.pow(2, x.intValue());
    }),

    LSHIFT("<<", (a, x) -> {
        if (a == null) {
            return String.format("x << %f", x);
        } else {
            return String.format("%f << %f", a, x);
        }
    }, (a, x) -> {
        return a * (float)Math.pow(2, x.intValue());
    }, (a, x) -> {
        return a / (float)Math.pow(2, x.intValue());
    });

    private final String text;
    private final BiFunction<Float, Float, String> stringConverter;
    private final BiFunction<Float, Float, Float> forwardOperation;
    private final BiFunction<Float, Float, Float> reverseOperation;

    ArithmeticOperation(String text,
                        BiFunction<Float, Float, String> stringConverter,
                        BiFunction<Float, Float, Float> forwardOperation,
                        BiFunction<Float, Float, Float> reverseOperation) {
        this.stringConverter = stringConverter;
        this.forwardOperation = forwardOperation;
        this.reverseOperation = reverseOperation;
        this.text = text;
    }

    public float forward(float a, float x) {
        return forwardOperation.apply(a, x);
    }

    public float reverse(float a, float x) {
        return reverseOperation.apply(a, x);
    }

    @Override
    public String toString() {
        return text;
    }

    public String formatString(float x) {
        return stringConverter.apply(null, x);
    }

    public String formatString(float a, float x) {
        return stringConverter.apply(a, x);
    }
}
