import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * Moderador que recibe mensajes del servidor y decide si aprobarlos o rechazarlos
 */
public class Moderador {
    private Socket socket;
    private PrintWriter salidaServidor;
    private BufferedReader entradaServidor;
    private BufferedReader entradaConsola;
    private SecretKey claveAESCompartida;

    public Moderador(String ipServidor, int puertoServidor) throws IOException {
        this.socket = new Socket(ipServidor, puertoServidor);
        this.salidaServidor = new PrintWriter(socket.getOutputStream(), true);
        this.entradaServidor = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.entradaConsola = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("✅ Moderador conectado al servidor " + ipServidor + ":" + puertoServidor);
    }

    /**
     * Establece la conexión segura con el servidor mediante intercambio de claves
     */
    public void establecerConexionSegura() throws Exception {
        // Recibir clave pública del servidor
        PublicKey clavePublicaServidor = recibirClavePublicaDelServidor();

        // Generar clave AES para comunicación simétrica
        generarClaveAESAleatoria();

        // Cifrar y enviar la clave AES al servidor
        enviarClaveAESCifradaAlServidor(clavePublicaServidor);

        System.out.println("🔐 Conexión segura establecida");
        System.out.println("🛡️  Esperando mensajes para moderar...\n");
    }

    /**
     * Recibe y reconstruye la clave pública RSA del servidor
     */
    private PublicKey recibirClavePublicaDelServidor() throws Exception {
        String clavePublicaBase64 = entradaServidor.readLine();
        byte[] bytesClavePublica = Base64.getDecoder().decode(clavePublicaBase64);

        KeyFactory fabricaClaves = KeyFactory.getInstance("RSA");
        return fabricaClaves.generatePublic(new X509EncodedKeySpec(bytesClavePublica));
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
        String claveAESCifradaBase64 = Base64.getEncoder().encodeToString(claveAESCifrada);

        salidaServidor.println(claveAESCifradaBase64);
    }

    /**
     * Inicia el bucle principal de moderación de mensajes
     */
    public void iniciarModeracion() throws Exception {
        String mensajeCifrado;

        while ((mensajeCifrado = entradaServidor.readLine()) != null) {
            // Descifrar el mensaje recibido
            String mensajeDescifrado = descifrarMensajeDelServidor(mensajeCifrado);

            // Mostrar mensaje y solicitar decisión
            System.out.println("\n📩 Mensaje recibido: " + mensajeDescifrado);
            String decision = solicitarDecisionAlModerador();

            // Cifrar y enviar la decisión al servidor
            enviarDecisionCifrada(decision);
        }
    }

    /**
     * Descifra un mensaje del servidor usando la clave AES compartida
     */
    private String descifrarMensajeDelServidor(String mensajeCifrado) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.DECRYPT_MODE, claveAESCompartida);
        byte[] mensajeBytes = Base64.getDecoder().decode(mensajeCifrado);

        return new String(cifradorAES.doFinal(mensajeBytes));
    }

    /**
     * Solicita al moderador que decida si aprobar o rechazar el mensaje
     */
    private String solicitarDecisionAlModerador() throws IOException {
        System.out.print("¿Aprobar mensaje? (si/no): ");
        String respuesta = entradaConsola.readLine();

        if ("si".equalsIgnoreCase(respuesta)) {
            System.out.println("✅ Mensaje aprobado");
            return "APROBADO";
        } else {
            System.out.println("❌ Mensaje rechazado");
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
        String decisionCifradaBase64 = Base64.getEncoder().encodeToString(decisionCifrada);

        salidaServidor.println(decisionCifradaBase64);
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("❌ Uso: java Moderador <ipServidor> <puerto>");
            System.err.println("   Ejemplo: java Moderador 192.168.1.7 50000");
            System.exit(1);
        }

        try {
            String ipServidor = args[0];
            int puerto = Integer.parseInt(args[1]);

            Moderador moderador = new Moderador(ipServidor, puerto);
            moderador.establecerConexionSegura();
            moderador.iniciarModeracion();

        } catch (NumberFormatException e) {
            System.err.println("❌ Error: El puerto debe ser un número entero");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("❌ Error en el moderador: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
