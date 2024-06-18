package com.github.manevolent.atlas.logic;

import java.io.IOException;

public interface TableComparer {

    float compareCode(TableExecution a, TableExecution b) throws IOException;

}
