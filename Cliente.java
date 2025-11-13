import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * Cliente que se conecta al servidor y envía mensajes cifrados
 */
public class Cliente {
    private Socket socket;
    private BufferedReader entradaServidor;
    private PrintWriter salidaServidor;
    private BufferedReader entradaConsola;
    private SecretKey claveAESCompartida;
    private boolean esperandoRespuesta;

    public Cliente(String ipServidor, int puertoServidor) throws IOException {
        this.socket = new Socket(ipServidor, puertoServidor);
        this.entradaServidor = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        this.salidaServidor = new PrintWriter(socket.getOutputStream(), true);
        this.entradaConsola = new BufferedReader(new InputStreamReader(System.in));
        this.esperandoRespuesta = false;

        System.out.println("✅ Conectado al servidor " + ipServidor + ":" + puertoServidor);
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
     * Solicita y envía el nombre del cliente al servidor
     */
    public void enviarNombreDeUsuario() throws IOException {
        System.out.print("Ingresa tu nombre: ");
        String nombre = entradaConsola.readLine();
        salidaServidor.println(nombre);
        System.out.println("👤 Registrado como: " + nombre);
    }

    /**
     * Inicia el hilo que escucha respuestas del servidor
     */
    public void iniciarHiloEscuchaRespuestas() {
        new Thread(() -> {
            try {
                String respuesta;
                while ((respuesta = entradaServidor.readLine()) != null) {
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
            System.out.println("❌ Tu mensaje fue rechazado por el moderador");
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
                enviarMensajeCifrado(mensaje);
                esperandoRespuesta = true;
            }
        }
    }

    /**
     * Cifra y envía un mensaje al servidor usando AES
     */
    private void enviarMensajeCifrado(String mensaje) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.ENCRYPT_MODE, claveAESCompartida);
        byte[] mensajeCifrado = cifradorAES.doFinal(mensaje.getBytes());
        String mensajeCifradoBase64 = Base64.getEncoder().encodeToString(mensajeCifrado);

        salidaServidor.println(mensajeCifradoBase64);
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
