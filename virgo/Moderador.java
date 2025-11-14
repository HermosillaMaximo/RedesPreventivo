package virgo;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;


public class Moderador {
    private Socket socket;
    private DataOutputStream salidaServidor;
    private DataInputStream entradaServidor;
    private BufferedReader entradaConsola;
    private SecretKey claveAESCompartida;
    private PublicKey clavePublicaModerador;
    private PrivateKey clavePrivadaModerador;

    public Moderador(String ipServidor, int puertoServidor) throws IOException {
        this.socket = new Socket(ipServidor, puertoServidor);
        this.salidaServidor = new DataOutputStream(socket.getOutputStream());
        this.entradaServidor = new DataInputStream(socket.getInputStream());
        this.entradaConsola = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Moderador conectado al servidor " + ipServidor + ":" + puertoServidor);
    }

    
    // Genera las claves pub y priv del moderador
     
    public void generarClavePriv_y_Pub() throws NoSuchAlgorithmException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        KeyPair parClaves = generador.generateKeyPair();
        this.clavePublicaModerador = parClaves.getPublic();
        this.clavePrivadaModerador = parClaves.getPrivate();
        
    }

    
     // Establece la conexión segura con el servidor mediante intercambio de claves
     
    public void establecerConexionSegura() throws Exception {
        // Recibir clave pública del servidor
        PublicKey clavePublicaServidor = recibirClavePublicaDelServidor();

        // Enviar clave pública del moderador al servidor
        enviarClavePublicaAlServidor();

        // Generar clave AES para comunicación simétrica
        generarClaveAESAleatoria();

        // Cifrar y enviar la clave AES al servidor
        enviarClaveAESCifradaAlServidor(clavePublicaServidor);

        System.out.println("Conexión segura establecida");
        System.out.println("Esperando mensajes para moderar...\n");
    }

    // Recibe y reconstruye la clave pública RSA del servidor
     
    private PublicKey recibirClavePublicaDelServidor() throws Exception {
        int tamaño = entradaServidor.readInt();
        byte[] bytesClavePublica = new byte[tamaño];
        entradaServidor.readFully(bytesClavePublica);

        KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
        return fabricaClaves.generatePublic(new X509EncodedKeySpec(bytesClavePublica));
    }

    // Envía la clave pública del moderador al servidor
     
    private void enviarClavePublicaAlServidor() throws IOException {
        byte[] clavePublicaBytes = clavePublicaModerador.getEncoded();
        salidaServidor.writeInt(clavePublicaBytes.length);
        salidaServidor.write(clavePublicaBytes);
        salidaServidor.flush();
    }

    // Genera una clave AES aleatoria de 128 bits

    private void generarClaveAESAleatoria() throws NoSuchAlgorithmException {
        KeyGenerator generadorClaves = KeyGenerator.getInstance("AES");
        generadorClaves.init(128);
        claveAESCompartida = generadorClaves.generateKey();
    }

    // Comunicacion deseada, Se genero la clave y se envia Asimetricamente 
    private void enviarClaveAESCifradaAlServidor(PublicKey clavePublicaServidor) throws Exception {
        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaServidor);
        byte[] claveAESCifrada = cifradorRSA.doFinal(claveAESCompartida.getEncoded());

        salidaServidor.writeInt(claveAESCifrada.length);
        salidaServidor.write(claveAESCifrada);
        salidaServidor.flush();
    }

    // Inicia la Moderacion
    public void iniciarModeracion() throws Exception {
        while (true) {
            int tamaño = entradaServidor.readInt();
            byte[] mensajeCifrado = new byte[tamaño];
            entradaServidor.readFully(mensajeCifrado);

            // Descifrar el mensaje recibido
            String mensajeDescifrado = descifrarMensajeDelServidor(mensajeCifrado);

            // Mostrar mensaje y solicitar decisión
            System.out.println("Mensaje recibido: " + mensajeDescifrado);
            String decision = solicitarDecisionAlModerador();

            // Cifrar y enviar la decisión al servidor
            enviarDecisionCifrada(decision);
        }
    }

    // Descifra un mensaje del servidor usando la clave AES compartida
     
    private String descifrarMensajeDelServidor(byte[] mensajeCifrado) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.DECRYPT_MODE, claveAESCompartida);

        return new String(cifradorAES.doFinal(mensajeCifrado));
    }

    
    // Solicita al moderador que decida si aprobar o rechazar el mensaje
     
    private String solicitarDecisionAlModerador() throws IOException {
        System.out.print("¿Aprobar mensaje? (si/no): ");
        String respuesta = entradaConsola.readLine();

        if ("si".equalsIgnoreCase(respuesta)) {
            System.out.println("Mensaje aprobado");
            return "APROBADO";
        } else {
            System.out.println("Mensaje rechazado");
            return "RECHAZADO";
        }
    }

    /**
     * Cifra la decisión del moderador y la envía al servidor
     */
    private void enviarDecisionCifrada(String decision) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.ENCRYPT_MODE, claveAESCompartida);
        byte[] decisionCifrada = cifradorAES.doFinal(decision.getBytes());

        salidaServidor.writeInt(decisionCifrada.length);
        salidaServidor.write(decisionCifrada);
        salidaServidor.flush();
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Uso: java Moderador <ipServidor> <puerto>");
            System.err.println("Ejemplo: java Moderador 192.168.1.7 50000");
            System.exit(1);
        }

        try {
            String ipServidor = args[0];
            int puerto = Integer.parseInt(args[1]);

            Moderador moderador = new Moderador(ipServidor, puerto);
            moderador.generarClavePriv_y_Pub();
            moderador.establecerConexionSegura();
            moderador.iniciarModeracion();

        } catch (NumberFormatException e) {
            System.err.println("Error: El puerto debe ser un número entero");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("Error en el moderador: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

}
