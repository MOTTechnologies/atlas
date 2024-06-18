package com.github.manevolent.atlas.graphics;

import com.jogamp.opengl.GL2;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.util.Vector;

import static com.jogamp.opengl.GL.GL_FLOAT;

/**
 * See: https://stackoverflow.com/questions/18863915/how-to-use-gldrawarrays-to-display-cube-in-jogl
 */
public class Model {
    private final int drawMode;
    private final int vbo_vertex_name, vbo_color_name;

    private final Vector<Point3F> vertices = new Vector<>();
    private final Vector<Point3F> colors = new Vector<>();

    private boolean disposed = false;

    private Model(int vbo_vertex_name, int vbo_color_name, int drawMode) {
        this.drawMode = drawMode;

        this.vbo_vertex_name = vbo_vertex_name;
        this.vbo_color_name = vbo_color_name;
    }

    public boolean isDisposed() {
        return disposed;
    }

    public void beginVertices() {
        vertices.clear();
        colors.clear();
    }

    public void addVertex(Point3F vertex, Point3F color) {
        vertices.add(vertex);
        colors.add(color);
    }

    public void endVertices(GL2 gl) {
        if (disposed) {
            throw new IllegalStateException();
        }

        gl.glBindBuffer(GL2.GL_ARRAY_BUFFER, vbo_vertex_name);
        gl.glBufferData(GL2.GL_ARRAY_BUFFER, vertices.size() * 3L * 4L, toBuffer(vertices), GL2.GL_DYNAMIC_DRAW);
        gl.glBindBuffer(GL2.GL_ARRAY_BUFFER, 0);

        gl.glBindBuffer(GL2.GL_ARRAY_BUFFER, vbo_color_name);
        gl.glBufferData(GL2.GL_ARRAY_BUFFER, colors.size() * 3L * 4L, toBuffer(colors), GL2.GL_DYNAMIC_DRAW);
        gl.glBindBuffer(GL2.GL_ARRAY_BUFFER, 0);
    }

    public void render(GL2 gl) {
        if (disposed) {
            throw new IllegalStateException();
        }

        gl.glBindBuffer(GL2.GL_ARRAY_BUFFER, vbo_vertex_name);
        gl.glVertexPointer(3, GL_FLOAT, 0, 0L);

        gl.glBindBuffer(GL2.GL_ARRAY_BUFFER, vbo_color_name);
        gl.glColorPointer(3, GL_FLOAT, 0, 0L);

        gl.glEnableClientState(GL2.GL_VERTEX_ARRAY);
        gl.glEnableClientState(GL2.GL_COLOR_ARRAY);

        gl.glDrawArrays(drawMode, 0, vertices.size() * 3);

        gl.glDisableClientState(GL2.GL_COLOR_ARRAY);
        gl.glDisableClientState(GL2.GL_VERTEX_ARRAY);
    }

    public void dispose(GL2 gl) {
        IntBuffer names = IntBuffer.wrap(new int[] { vbo_vertex_name, vbo_color_name });
        gl.glDeleteBuffers(2, names);
        disposed = true;
    }

    public static Model genModel(GL2 gl, int drawMode) {
        IntBuffer names = IntBuffer.allocate(2);
        gl.glGenBuffers(2, names);
        return new Model(names.get(0), names.get(1), drawMode);
    }

    private static ByteBuffer toBuffer(Vector<Point3F> vector) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4 * vector.size() * 3);
        byteBuffer.order(ByteOrder.nativeOrder());
        FloatBuffer buffer = byteBuffer.asFloatBuffer();
        vector.forEach(v -> {
            buffer.put(v.getX());
            buffer.put(v.getY());
            buffer.put(v.getZ());
        });
        buffer.flip();
        return byteBuffer;
    }
}
