package virgo;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class Servidor {
    private ServerSocket serverSocketClientes;
    private ServerSocket serverSocketModerador;
    private Socket moderadorSocket;
    private ArrayList<Socket> clientes;
    private final Object lockModerador;
    private Map<Socket, String> nombresClientes;
    private Map<Socket, PublicKey> clavesPublicasClientes;
    private DataOutputStream salidaModerador;
    private DataInputStream entradaModerador;
    private PublicKey clavePublicaServidor;
    private PrivateKey clavePrivadaServidor;
    private Map<Socket, SecretKey> clavesAESClientes;
    private SecretKey claveAESModerador;
    private PublicKey clavePublicaModerador;

    public Servidor(int puertoModerador, int puertoClientes) throws IOException {
        this.serverSocketModerador = new ServerSocket(puertoModerador);
        this.serverSocketClientes = new ServerSocket(puertoClientes);
        this.clientes = new ArrayList<>();
        this.lockModerador = new Object();
        this.nombresClientes = new HashMap<>();
        this.clavesAESClientes = new HashMap<>();
        this.clavesPublicasClientes = new HashMap<>();

        System.out.println("✅ Servidor iniciado");
        System.out.println("   Puerto moderador: " + puertoModerador);
        System.out.println("   Puerto clientes: " + puertoClientes);
    }

    // Genera el par de claves pública y privada RSA para el servidor
     
    public void generarClavesRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
        generador.initialize(2048);
        KeyPair parClaves = generador.generateKeyPair();
        this.clavePublicaServidor = parClaves.getPublic();
        this.clavePrivadaServidor = parClaves.getPrivate();
        System.out.println("Claves del servidor generadas");
    }

    // Convierte la clave pública del servidor a bytes
     
    private byte[] obtenerClavePublicaEnBytes() {
        return clavePublicaServidor.getEncoded();
    }

    // Espera la conexión del moderador y establece la clave AES compartida
     
    public void esperarConexionModerador() throws Exception {
        System.out.println(" Esperando conexión del moderador...");
        moderadorSocket = serverSocketModerador.accept();
        System.out.println("✅ Moderador conectado desde: " + moderadorSocket.getInetAddress());

        salidaModerador = new DataOutputStream(moderadorSocket.getOutputStream());
        entradaModerador = new DataInputStream(moderadorSocket.getInputStream());

        // Enviar clave pública al moderador
        enviarClavePublicaAlModerador();

        // Recibir clave pública del moderador
        recibirClavePublicaDelModerador();

        // Recibir y descifrar la clave AES del moderador
        recibirYDescifrarClaveAESDelModerador();
    }

    // Envía la clave pública RSA al moderador (en bytes)
     
    private void enviarClavePublicaAlModerador() throws IOException {
        byte[] clavePublicaBytes = obtenerClavePublicaEnBytes();
        salidaModerador.writeInt(clavePublicaBytes.length);
        salidaModerador.write(clavePublicaBytes);
        salidaModerador.flush();
    }

    // Recibe la clave pública del moderador
     
    private void recibirClavePublicaDelModerador() throws Exception {
        int tamaño = entradaModerador.readInt();
        byte[] clavePublicaBytes = new byte[tamaño];
        entradaModerador.readFully(clavePublicaBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        clavePublicaModerador = keyFactory.generatePublic(new X509EncodedKeySpec(clavePublicaBytes));
       
    }

    
     // Recibe la clave AES cifrada del moderador y la descifra con la clave privada RSA
     
    private void recibirYDescifrarClaveAESDelModerador() throws Exception {
        int tamaño = entradaModerador.readInt();
        byte[] claveAESCifrada = new byte[tamaño];
        entradaModerador.readFully(claveAESCifrada);

        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaServidor);
        byte[] claveAESBytes = cifradorRSA.doFinal(claveAESCifrada);

        claveAESModerador = new SecretKeySpec(claveAESBytes, 0, claveAESBytes.length, "AES");
        
    }

    // Inicia el hilo que espera conexiones de múltiples clientes

    public void esperarConexionesClientes() {
        new Thread(() -> {
            System.out.println(" Esperando clientes...");
            while (true) {
                try {
                    Socket cliente = serverSocketClientes.accept();
                    clientes.add(cliente);
                    System.out.println(" Cliente conectado desde: " + cliente.getInetAddress());

                    procesarNuevoCliente(cliente);
                } catch (Exception e) {
                    System.err.println("❌ Error al procesar cliente: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }).start();
    }

    // Procesa la conexión de un nuevo cliente ( intercambio de claves y nombre )

    private void procesarNuevoCliente(Socket cliente) throws Exception {
        DataInputStream entrada = new DataInputStream(cliente.getInputStream());
        DataOutputStream salida = new DataOutputStream(cliente.getOutputStream());

        // Enviar clave pública del servidor al cliente
        enviarClavePublicaAlCliente(salida);

        // Recibir la clave pública del cliente
        PublicKey clavePublicaCliente = recibirClavePublicaDelCliente(entrada);
        clavesPublicasClientes.put(cliente, clavePublicaCliente);

        // Recibir y descifrar la clave AES del cliente
        SecretKey claveAESCliente = recibirYDescifrarClaveAESDelCliente(entrada);
        clavesAESClientes.put(cliente, claveAESCliente);

        // Recibir el nombre del cliente
        int tamañoNombre = entrada.readInt();
        byte[] nombreBytes = new byte[tamañoNombre];
        entrada.readFully(nombreBytes);
        String nombreCliente = new String(nombreBytes);

        nombresClientes.put(cliente, nombreCliente);
        System.out.println(" Cliente identificado como: " + nombreCliente);

        // Iniciar hilo para manejar mensajes de este cliente
        iniciarHiloParaManejarMensajesDelCliente(cliente, entrada, salida, nombreCliente);
    }

    // envia la clave publica
    private void enviarClavePublicaAlCliente(DataOutputStream salida) throws IOException {
        byte[] clavePublicaBytes = obtenerClavePublicaEnBytes();
        salida.writeInt(clavePublicaBytes.length);
        salida.write(clavePublicaBytes);
        salida.flush();
    }

    // recibe la clave publica del cliente
    private PublicKey recibirClavePublicaDelCliente(DataInputStream entrada) throws Exception {
        int tamaño = entrada.readInt();
        byte[] clavePublicaBytes = new byte[tamaño];
        entrada.readFully(clavePublicaBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(clavePublicaBytes));
    }


    // recibe la clave y la descifra
    private SecretKey recibirYDescifrarClaveAESDelCliente(DataInputStream entrada) throws Exception {
        int tamaño = entrada.readInt();
        byte[] claveAESCifrada = new byte[tamaño];
        entrada.readFully(claveAESCifrada);

        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaServidor);
        byte[] claveAESBytes = cifradorRSA.doFinal(claveAESCifrada);

        return new SecretKeySpec(claveAESBytes, 0, claveAESBytes.length, "AES");
    }

    // Hilo para manejar los mensajes de un cliente

    private void iniciarHiloParaManejarMensajesDelCliente(Socket cliente, DataInputStream entrada,
                                                          DataOutputStream salida, String nombreCliente) {
        new Thread(() -> {
            try {
                while (true) {
                    // Recibir el paquete (mensaje cifrado + firma)
                    Paquete paquete = recibirPaquete(entrada);

                    procesarPaqueteDelCliente(cliente, paquete, salida, nombreCliente);
                }
            } catch (Exception e) {
                System.out.println("Cliente " + nombreCliente + " se desconectó.");
                eliminarCliente(cliente);
            }
        }).start();
    }

    // Recibe el paquete

    private Paquete recibirPaquete(DataInputStream entrada) throws IOException {
        // Recibir mensaje cifrado
        int tamañoMensaje = entrada.readInt();
        byte[] mensajeCifrado = new byte[tamañoMensaje];
        entrada.readFully(mensajeCifrado);

        // Recibir firma
        int tamañoFirma = entrada.readInt();
        byte[] firma = new byte[tamañoFirma];
        entrada.readFully(firma);

        return new Paquete(mensajeCifrado, firma);
    }

    // Procesa un paquete de un cliente: verifica firma, descifra, envía al moderador

    private void procesarPaqueteDelCliente(Socket cliente, Paquete paquete,
                                           DataOutputStream salidaCliente, String nombreCliente) throws Exception {
        // Descifrar el mensaje del cliente
        String mensajeDescifrado = descifrarMensajeDelCliente(cliente, paquete.getMensajeCifradoBytes());

        // Verificar la firma digital
        boolean firmaValida = verificarFirma(cliente, mensajeDescifrado, paquete.getFirmaBytes());

        if (!firmaValida) {
            System.out.println("⚠️ FIRMA INVÁLIDA de " + nombreCliente + " - Mensaje rechazado");
            byte[] respuesta = "RECHAZADO".getBytes();
            salidaCliente.writeInt(respuesta.length);
            salidaCliente.write(respuesta);
            salidaCliente.flush();
            return;
        }

        System.out.println("Firma válida de " + nombreCliente);

        // Crear mensaje completo con origen
        Mensaje mensaje = new Mensaje(nombreCliente, mensajeDescifrado);

        // Cifrar y enviar al moderador
        byte[] mensajeCifradoParaModerador = cifrarMensajeParaModerador(mensaje.toString());

        // Enviar al moderador y esperar su decisión
        String decision = enviarAlModeradorYEsperarDecision(mensajeCifradoParaModerador);

        // Procesar la decisión del moderador
        procesarDecisionDelModerador(decision, salidaCliente, mensaje.toString());
    }

    // Verifica la firma digital de un mensaje
    private boolean verificarFirma(Socket cliente, String mensaje, byte[] firma) throws Exception {
        PublicKey clavePublicaCliente = clavesPublicasClientes.get(cliente);

        Signature verificador = Signature.getInstance("SHA256withRSA");
        verificador.initVerify(clavePublicaCliente);
        verificador.update(mensaje.getBytes());

        return verificador.verify(firma);
    }

    // Descifra un mensaje del cliente usando su clave AES

    private String descifrarMensajeDelCliente(Socket cliente, byte[] mensajeCifrado) throws Exception {
        SecretKey claveAESCliente = clavesAESClientes.get(cliente);

        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.DECRYPT_MODE, claveAESCliente);

        return new String(cifradorAES.doFinal(mensajeCifrado));
    }

    //Cifra un mensaje para enviarlo al moderador usando la clave AES compartida

    private byte[] cifrarMensajeParaModerador(String mensaje) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.ENCRYPT_MODE, claveAESModerador);

        return cifradorAES.doFinal(mensaje.getBytes());
    }

    // Envía mensaje al moderador y espera su decisión (sincronizado para evitar colisiones)

    private String enviarAlModeradorYEsperarDecision(byte[] mensajeCifrado) throws Exception {
        synchronized (lockModerador) {
            try {
                salidaModerador.writeInt(mensajeCifrado.length);
                salidaModerador.write(mensajeCifrado);
                salidaModerador.flush();

                int tamaño = entradaModerador.readInt();
                byte[] respuestaCifrada = new byte[tamaño];
                entradaModerador.readFully(respuestaCifrada);

                return descifrarRespuestaDelModerador(respuestaCifrada);

            } catch (IOException ex) {
                System.out.println("❌ El moderador se desconectó.");
                cerrarServidor();
                System.exit(0);
            }
        }
        return "RECHAZADO";
    }

     // Descifra la respuesta del moderador

    private String descifrarRespuestaDelModerador(byte[] respuestaCifrada) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.DECRYPT_MODE, claveAESModerador);

        return new String(cifradorAES.doFinal(respuestaCifrada));
    }

    // Procesa la decisión del moderador y responde al cliente

    private void procesarDecisionDelModerador(String decision, DataOutputStream salidaCliente, String mensajeCompleto) throws IOException {
        if ("APROBADO".equalsIgnoreCase(decision)) {
            System.out.println("✅ " + mensajeCompleto);
            byte[] respuesta = "ENVIADO".getBytes();
            salidaCliente.writeInt(respuesta.length);
            salidaCliente.write(respuesta);
        } else {
            System.out.println("Mensaje rechazado: " + mensajeCompleto);
            byte[] respuesta = "RECHAZADO".getBytes();
            salidaCliente.writeInt(respuesta.length);
            salidaCliente.write(respuesta);
        }
        salidaCliente.flush();
    }

     // Elimina completamente un cliente del servidor (cuando se desconecta)

    private void eliminarCliente(Socket cliente) {
        try { cliente.close(); } catch (Exception ignored) {}

        clientes.remove(cliente);
        nombresClientes.remove(cliente);
        clavesAESClientes.remove(cliente);
        clavesPublicasClientes.remove(cliente);

        System.out.println("Cliente desconectado y limpiado correctamente.");
    }


     // Cierra todo si el moderador se desconecta

    private void cerrarServidor() {
        try { moderadorSocket.close(); } catch (Exception ignored) {}
        try { serverSocketClientes.close(); } catch (Exception ignored) {}
        try { serverSocketModerador.close(); } catch (Exception ignored) {}

        for (Socket c : clientes) {
            try { c.close(); } catch (Exception ignored) {}
        }

        System.out.println(" Servidor apagado porque el moderador se desconectó.");
    }




    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println(" Uso: java Servidor <puertoModerador> <puertoClientes>");
            System.err.println("   Ejemplo: java Servidor 50000 50001");
            System.exit(1);
        }

        try {
            int puertoModerador = Integer.parseInt(args[0]);
            int puertoClientes = Integer.parseInt(args[1]);

            Servidor servidor = new Servidor(puertoModerador, puertoClientes);
            servidor.generarClavesRSA();
            servidor.esperarConexionModerador();
            servidor.esperarConexionesClientes();

        } catch (NumberFormatException e) {
            System.err.println(" Error: Los puertos deben ser números enteros");
            System.exit(1);
        } catch (Exception e) {
            System.err.println(" Error en el servidor: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
