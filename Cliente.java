package virgo;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;

/**
 * Cliente que se conecta al servidor y envía mensajes cifrados con firma digital
 */
public class Cliente {
    private Socket socket;
    private DataInputStream entradaServidor;
    private DataOutputStream salidaServidor;
    private BufferedReader entradaConsola;
    private SecretKey claveAESCompartida;
    private PublicKey clavePublicaCliente;
    private PrivateKey clavePrivadaCliente;
    private boolean esperandoRespuesta;

    public Cliente(String ipServidor, int puertoServidor) throws IOException {
        this.socket = new Socket(ipServidor, puertoServidor);
        this.entradaServidor = new DataInputStream(socket.getInputStream());
        this.salidaServidor = new DataOutputStream(socket.getOutputStream());
        this.entradaConsola = new BufferedReader(new InputStreamReader(System.in));
        this.esperandoRespuesta = false;

        System.out.println("✅ Conectado al servidor " + ipServidor + ":" + puertoServidor);
    }

    /**
     * Genera el par de claves RSA del cliente para firmas digitales
     */
    public void generarClavesRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        KeyPair parClaves = generador.generateKeyPair();
        this.clavePublicaCliente = parClaves.getPublic();
        this.clavePrivadaCliente = parClaves.getPrivate();
        System.out.println("🔑 Claves RSA del cliente generadas");
    }

    /**
     * Establece la conexión segura con el servidor mediante intercambio de claves
     */
    public void establecerConexionSegura() throws Exception {
        // Recibir clave pública del servidor
        PublicKey clavePublicaServidor = recibirClavePublicaDelServidor();

        // Enviar clave pública del cliente al servidor
        enviarClavePublicaAlServidor();

        // Generar clave AES para comunicación simétrica
        generarClaveAESAleatoria();

        // Cifrar y enviar la clave AES al servidor
        enviarClaveAESCifradaAlServidor(clavePublicaServidor);

        System.out.println("🔐 Conexión segura establecida");
    }

    /**
     * Recibe y reconstruye la clave pública RSA del servidor
     */
    private PublicKey recibirClavePublicaDelServidor() throws Exception {
        int tamaño = entradaServidor.readInt();
        byte[] bytesClavePublica = new byte[tamaño];
        entradaServidor.readFully(bytesClavePublica);

        KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
        return fabricaClaves.generatePublic(new X509EncodedKeySpec(bytesClavePublica));
    }

    /**
     * Envía la clave pública del cliente al servidor
     */
    private void enviarClavePublicaAlServidor() throws IOException {
        byte[] clavePublicaBytes = clavePublicaCliente.getEncoded();
        salidaServidor.writeInt(clavePublicaBytes.length);
        salidaServidor.write(clavePublicaBytes);
        salidaServidor.flush();
    }

    /**
     * Genera una clave AES aleatoria de 128 bits
     */
    private void generarClaveAESAleatoria() throws NoSuchAlgorithmException {
        KeyGenerator generadorClaves = KeyGenerator.getInstance("AES");
        generadorClaves.init(128);
        claveAESCompartida = generadorClaves.generateKey();
    }

    /**
     * Cifra la clave AES con RSA y la envía al servidor
     */
    private void enviarClaveAESCifradaAlServidor(PublicKey clavePublicaServidor) throws Exception {
        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaServidor);
        byte[] claveAESCifrada = cifradorRSA.doFinal(claveAESCompartida.getEncoded());

        salidaServidor.writeInt(claveAESCifrada.length);
        salidaServidor.write(claveAESCifrada);
        salidaServidor.flush();
    }

    /**
     * Solicita y envía el nombre del cliente al servidor
     */
    public void enviarNombreDeUsuario() throws IOException {
        System.out.print("Ingresa tu nombre: ");
        String nombre = entradaConsola.readLine();
        byte[] nombreBytes = nombre.getBytes();
        salidaServidor.writeInt(nombreBytes.length);
        salidaServidor.write(nombreBytes);
        salidaServidor.flush();
        System.out.println("👤 Registrado como: " + nombre);
    }

    /**
     * Inicia el hilo que escucha respuestas del servidor
     */
    public void iniciarHiloEscuchaRespuestas() {
        new Thread(() -> {
            try {
                while (true) {
                    int tamaño = entradaServidor.readInt();
                    byte[] respuestaBytes = new byte[tamaño];
                    entradaServidor.readFully(respuestaBytes);
                    String respuesta = new String(respuestaBytes);

                    procesarRespuestaDelServidor(respuesta);
                }
            } catch (IOException e) {
                System.err.println("❌ Error al recibir respuesta: " + e.getMessage());
            }
        }).start();
    }

    /**
     * Procesa las respuestas del servidor (ENVIADO o RECHAZADO)
     */
    private void procesarRespuestaDelServidor(String respuesta) {
        if ("ENVIADO".equals(respuesta)) {
            System.out.println("✅ Tu mensaje fue enviado");
        } else if ("RECHAZADO".equals(respuesta)) {
            System.out.println("❌ Tu mensaje fue rechazado");
        } else {
            System.out.println("📩 " + respuesta);
        }

        esperandoRespuesta = false;
        System.out.print("\nEscribe tu mensaje: ");
    }

    /**
     * Inicia el bucle principal para enviar mensajes
     */
    public void iniciarBucleMensajes() throws Exception {
        System.out.print("Escribe tu mensaje: ");

        while (true) {
            // Esperar si hay una respuesta pendiente
            while (esperandoRespuesta) {
                Thread.sleep(100);
            }

            String mensaje = entradaConsola.readLine();

            if (mensaje != null && !mensaje.trim().isEmpty()) {
                enviarMensajeCifradoConFirma(mensaje);
                esperandoRespuesta = true;
            }
        }
    }

    /**
     * Cifra un mensaje, lo firma y lo envía al servidor
     */
    private void enviarMensajeCifradoConFirma(String mensaje) throws Exception {
        // 1. Cifrar el mensaje con AES
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.ENCRYPT_MODE, claveAESCompartida);
        byte[] mensajeCifrado = cifradorAES.doFinal(mensaje.getBytes());

        // 2. Firmar el mensaje original con la clave privada del cliente
        byte[] firma = firmarMensaje(mensaje);

        // 3. Crear el paquete con mensaje cifrado + firma
        Paquete paquete = new Paquete(mensajeCifrado, firma);

        // 4. Enviar el paquete
        enviarPaquete(paquete);
    }

    /**
     * Firma un mensaje usando SHA-256 y la clave privada del cliente
     */
    private byte[] firmarMensaje(String mensaje) throws Exception {
        Signature firmador = Signature.getInstance("SHA256withRSA");
        firmador.initSign(clavePrivadaCliente);
        firmador.update(mensaje.getBytes());
        return firmador.sign();
    }

    /**
     * Envía un paquete (mensaje cifrado + firma) al servidor
     */
    private void enviarPaquete(Paquete paquete) throws IOException {
        // Enviar mensaje cifrado
        byte[] mensajeCifrado = paquete.getMensajeCifradoBytes();
        salidaServidor.writeInt(mensajeCifrado.length);
        salidaServidor.write(mensajeCifrado);

        // Enviar firma
        byte[] firma = paquete.getFirmaBytes();
        salidaServidor.writeInt(firma.length);
        salidaServidor.write(firma);

        salidaServidor.flush();
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("❌ Uso: java Cliente <ipServidor> <puerto>");
            System.err.println("   Ejemplo: java Cliente 192.168.1.7 50001");
            System.exit(1);
        }

        try {
            String ipServidor = args[0];
            int puerto = Integer.parseInt(args[1]);

            Cliente cliente = new Cliente(ipServidor, puerto);
            cliente.generarClavesRSA();
            cliente.establecerConexionSegura();
            cliente.enviarNombreDeUsuario();
            cliente.iniciarHiloEscuchaRespuestas();
            cliente.iniciarBucleMensajes();

        } catch (NumberFormatException e) {
            System.err.println("❌ Error: El puerto debe ser un número entero");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("❌ Error en el cliente: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}