package com.github.manevolent.atlas.model;

import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;

public class Vehicle extends AbstractAnchored {
    private String market;
    private String make;
    private String model;
    private String year;
    private String trim;
    private String transmission;

    public Vehicle() {

    }

    public static Builder builder () {
        return new Builder();
    }

    public static class Builder {
        private final Vehicle vehicle = new Vehicle();

        public Builder withMarket(String market) {
            vehicle.market = market;
            return this;
        }

        public Builder withMake(String make) {
            vehicle.make = make;
            return this;
        }

        public Builder withModel(String value) {
            vehicle.model = value;
            return this;
        }

        public Builder withYear(String value) {
            vehicle.year = value;
            return this;
        }

        public Builder withTrim(String value) {
            vehicle.trim = value;
            return this;
        }

        public Builder withTransmission(String value) {
            vehicle.transmission = value;
            return this;
        }

        public Vehicle build() {
            return vehicle;
        }
    }

    @Override
    public String toString() {
        List<String> parts = Stream.of(market, make, model, year, trim, transmission)
                .filter(Objects::nonNull)
                .toList();

        return String.join(" ", parts);
    }

    public String getMarket() {
        return market;
    }

    public void setMarket(String market) {
        this.market = market;
    }

    public String getMake() {
        return make;
    }

    public void setMake(String make) {
        this.make = make;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getYear() {
        return year;
    }

    public void setYear(String year) {
        this.year = year;
    }

    public String getTrim() {
        return trim;
    }

    public void setTrim(String trim) {
        this.trim = trim;
    }

    public String getTransmission() {
        return transmission;
    }

    public void setTransmission(String transmission) {
        this.transmission = transmission;
    }
}
