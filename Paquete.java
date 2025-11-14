package virgo;

import java.io.Serializable;

/**
 * Clase que representa un paquete con mensaje encriptado y firma digital
 * Ambos campos son arrays de bytes para trabajar directamente con datos binarios
 */
public class Paquete implements Serializable {
    private byte[] mensajeCifrado;
    private byte[] firma;

    /**
     * Constructor del paquete
     * @param mensajeCifrado El mensaje cifrado en bytes
     * @param firma La firma digital en bytes
     */
    public Paquete(byte[] mensajeCifrado, byte[] firma) {
        this.mensajeCifrado = mensajeCifrado;
        this.firma = firma;
    }

    /**
     * Obtiene el mensaje cifrado en bytes
     * @return Array de bytes con el mensaje cifrado
     */
    public byte[] getMensajeCifradoBytes() {
        return mensajeCifrado;
    }

    /**
     * Obtiene la firma digital en bytes
     * @return Array de bytes con la firma
     */
    public byte[] getFirmaBytes() {
        return firma;
    }
}