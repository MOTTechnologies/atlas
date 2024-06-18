package com.github.manevolent.atlas.ghidra;

import generic.jar.ResourceFile;
import ghidra.GhidraJarApplicationLayout;
import ghidra.framework.GModule;
import utility.module.ModuleUtilities;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class AtlasGhidraApplicationLayout extends GhidraJarApplicationLayout {
    public AtlasGhidraApplicationLayout() throws FileNotFoundException, IOException {

    }

    @Override
    protected Collection<ResourceFile> findGhidraApplicationRootDirs() {
        Collection<ResourceFile> resourceFiles = super.findGhidraApplicationRootDirs();

        // Add our own extensions
        String appPropPath = "/Ghidra/application.properties";
        URL appPropUrl = AtlasGhidraApplicationLayout.class.getResource(appPropPath);
        String urlString = appPropUrl.toExternalForm();
        urlString = URLDecoder.decode(urlString, StandardCharsets.UTF_8);

        if (urlString.startsWith("file:")) {
            urlString = urlString.substring(5);
        }

        resourceFiles.add(new ResourceFile(urlString).getParentFile());

        return resourceFiles;
    }

    @Override
    protected Map<String, GModule> findGhidraModules() throws IOException {
        Map<String, GModule> modules = new HashMap<>();

        Collection<ResourceFile> moduleRoots = new ArrayList<>();

        for (ResourceFile resourceFile : this.getApplicationRootDirs()) {
            moduleRoots.addAll(ModuleUtilities.findJarModuleRootDirectories(resourceFile, new ArrayList()));
        }

        return ModuleUtilities.findModules(this.getApplicationRootDirs(), moduleRoots);
    }
}
