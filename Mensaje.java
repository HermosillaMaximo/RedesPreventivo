package virgo;

import java.io.Serializable;

/**
 * Clase que representa un mensaje con su origen y contenido
 */
public class Mensaje implements Serializable {
    private String origen;
    private String contenido;

    public Mensaje(String origen, String contenido) {
        this.origen = origen;
        this.contenido = contenido;
    }

    public String getOrigen() {
        return origen;
    }

    public String getContenido() {
        return contenido;
    }

    @Override
    public String toString() {
        return origen + ": " + contenido;
    }
}