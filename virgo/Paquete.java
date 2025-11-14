package virgo;

import java.io.Serializable;


public class Paquete implements Serializable {
    private byte[] mensajeCifrado;
    private byte[] firma;


    public Paquete(byte[] mensajeCifrado, byte[] firma) {
        this.mensajeCifrado = mensajeCifrado;
        this.firma = firma;
    }


    public byte[] getMensajeCifradoBytes() {
        return mensajeCifrado;
    }

    public byte[] getFirmaBytes() {
        return firma;
    }
}