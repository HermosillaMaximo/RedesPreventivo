import com.sun.jdi.event.ExceptionEvent;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

public class Servidor
{
    private ServerSocket serverSocketClientes;
    private ServerSocket serverSocketModerador;
    private Socket moderadorSocket;
    private ArrayList<Socket> clientes = new ArrayList<>();
    private final Object lockModerador = new Object();
    private Map<Socket, String> nombresClientes = new HashMap<>();
    private PrintWriter salidaModerador;
    private BufferedReader entradaModerador;
    private PublicKey clavePublicaServidor;
    private PrivateKey clavePrivadaServidor;
    private Map<Socket, SecretKey> clavesAESClientes = new HashMap<>();
    private SecretKey claveAESModerador;



    public Servidor(int puertoModerador, int puertoClientes) throws IOException
    {
        serverSocketModerador = new ServerSocket(puertoModerador);
        serverSocketClientes = new ServerSocket(puertoClientes);
        System.out.println("Servidor iniciado en puerto moderador: " + puertoModerador);
        System.out.println("Servidor iniciado en puerto clientes: " + puertoClientes);
    }


    /*  El servidor aca genera las claves Publicas y Privadas para poder comunicarse
        con los clientes.
    */

    public void generarClaves_Pub_Priv() throws Exception{
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); // Definimos que utilizamos Encriptacion Asimetrica
            generator.initialize(2050);
            KeyPair parClaves = generator.generateKeyPair();
            clavePublicaServidor = parClaves.getPublic();
            clavePrivadaServidor = parClaves.getPrivate();
        }catch (Exception e){
            e.printStackTrace();
        }

    }



    private String getClavePublica() {
        return Base64.getEncoder().encodeToString(clavePublicaServidor.getEncoded());
        /* Es como el ejemplo que puso pruchi, pasa a texto todos los bytes binarios que se generaron
        Ej : 0101010101110101010  ->  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
    * */
    }


    private void enviarClavePublicaAlModerador() {
        salidaModerador.println(getClavePublica());
    }

    private void recibir_y_DescifrarClaveDelModerador() throws Exception {
        String claveAESCifradaBase64 = entradaModerador.readLine();
        byte[] claveAESCifrada = Base64.getDecoder().decode(claveAESCifradaBase64);

        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaServidor);
        byte[] claveAESBytes = cifradorRSA.doFinal(claveAESCifrada);

        claveAESModerador = new SecretKeySpec(claveAESBytes, 0, claveAESBytes.length, "AES");
        System.out.println("🔐 Clave AES del moderador establecida");
    }



    public void esperarModerador() throws Exception {
        System.out.println("Esperando conexión del moderador...");
        moderadorSocket = serverSocketModerador.accept();
        System.out.println("Moderador conectado.");

        salidaModerador = new PrintWriter(moderadorSocket.getOutputStream(), true);
        entradaModerador = new BufferedReader(new InputStreamReader(moderadorSocket.getInputStream()));

        enviarClavePublicaAlModerador();

        recibir_y_DescifrarClaveDelModerador();

    }

    public void esperarClientes()
    {
        new Thread(() ->
        {
            System.out.println("Esperando clientes");
            while (true) {
                try {
                    Socket cliente = serverSocketClientes.accept();
                    clientes.add(cliente);

                    procesarCliente(cliente);

                } catch (Exception e) {
                    System.out.println("Error: No se pudo procesar al cliente" + e.getMessage());
                    e.printStackTrace();
                }

            }
        }).start();
    }



    private void enviarClavePublicaAlCliente(PrintWriter salida) {
        salida.println(getClavePublica());
    }



    private SecretKey recibirYDescifrarClaveAESDelCliente(BufferedReader entrada) throws Exception {
        String claveAESCifradaBase64 = entrada.readLine();
        byte[] claveAESCifrada = Base64.getDecoder().decode(claveAESCifradaBase64);

        Cipher cifradorRSA = Cipher.getInstance("RSA");
        cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaServidor);
        byte[] claveAESBytes = cifradorRSA.doFinal(claveAESCifrada);

        return new SecretKeySpec(claveAESBytes, 0, claveAESBytes.length, "AES");
    }



    private void procesarCliente(Socket cliente) throws Exception {
        BufferedReader entrada = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
        PrintWriter salida = new PrintWriter(cliente.getOutputStream(), true);


        enviarClavePublicaAlCliente(salida);

        // Recibir y descifrar la clave AES del cliente
        SecretKey claveAESCliente = recibirYDescifrarClaveAESDelCliente(entrada);
        clavesAESClientes.put(cliente, claveAESCliente); // Aca guardamos el cliente y la clave que se genero entre ellos

        // Recibir el nombre del cliente
        String nombreCliente = entrada.readLine();
        nombresClientes.put(cliente, nombreCliente);
        System.out.println("Cliente conectado: " + cliente.getInetAddress() + " como " + nombreCliente);

        // Iniciar hilo para manejar mensajes de este cliente
        manejoMensajesDelCliente(cliente, entrada, salida, nombreCliente);
    }

    private void manejoMensajesDelCliente(Socket cliente, BufferedReader entrada,
                                                          PrintWriter salida, String nombreCliente) {
        new Thread(() -> {
            try {
                String mensajeCifrado;
                while ((mensajeCifrado = entrada.readLine()) != null) {
                    procesarMensajeDelCliente(cliente, mensajeCifrado, salida, nombreCliente);
                }
            } catch (Exception e) {
                System.err.println("Error manejando al cliente: " + nombreCliente + ": " + e.getMessage());
            }
        }).start();
    }



    private String descifrarMensajeDelCliente(Socket cliente, String mensajeCifrado) throws Exception {
        SecretKey claveAESCliente = clavesAESClientes.get(cliente);

        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.DECRYPT_MODE, claveAESCliente);
        byte[] mensajeBytes = Base64.getDecoder().decode(mensajeCifrado);

        return new String(cifradorAES.doFinal(mensajeBytes));
    }



    private String cifrarMensajeParaModerador(String mensaje) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.ENCRYPT_MODE, claveAESModerador);
        byte[] mensajeCifrado = cifradorAES.doFinal(mensaje.getBytes());

        return Base64.getEncoder().encodeToString(mensajeCifrado);
    }



    private String descifrarRespuestaDelModerador(String respuestaCifrada) throws Exception {
        Cipher cifradorAES = Cipher.getInstance("AES");
        cifradorAES.init(Cipher.DECRYPT_MODE, claveAESModerador);
        byte[] respuestaBytes = Base64.getDecoder().decode(respuestaCifrada);

        return new String(cifradorAES.doFinal(respuestaBytes));
    }


    private String enviarAlModerador_y_EsperarDecision(String mensajeCifrado) throws Exception {
        synchronized (lockModerador) {
            salidaModerador.println(mensajeCifrado);
            String respuestaCifrada = entradaModerador.readLine();

            // Descifrar la respuesta del moderador
            return descifrarRespuestaDelModerador(respuestaCifrada);
        }
    }


    private void procesarMensajeDelCliente(Socket cliente, String mensajeCifrado,
                                           PrintWriter salidaCliente, String nombreCliente) throws Exception {
        // Descifrar el mensaje del cliente
        String mensajeDescifrado = descifrarMensajeDelCliente(cliente, mensajeCifrado);

        // Crear mensaje completo
        Mensaje mensaje = new Mensaje(nombreCliente, mensajeDescifrado);

        // Cifrar y enviar al moderador
        String mensajeCifradoParaModerador = cifrarMensajeParaModerador(mensaje.toString());

        // Enviar al moderador y esperar su decisión
        String decision = enviarAlModerador_y_EsperarDecision(mensajeCifradoParaModerador);

        // Procesar la decisión del moderador
        procesarDecisionDelModerador(decision, salidaCliente, mensaje.toString());
    }


    private void procesarDecisionDelModerador(String decision, PrintWriter salidaCliente, String mensajeCompleto) {
        if ("APROBADO".equalsIgnoreCase(decision)) {
            System.out.println(mensajeCompleto);
            salidaCliente.println("ENVIADO");
        } else {
            System.out.println("Mensaje rechazado: " + mensajeCompleto);
            salidaCliente.println("RECHAZADO");
        }
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("❌ Uso: java Servidor <puertoModerador> <puertoClientes>");
            System.err.println("   Ejemplo: java Servidor 50000 50001");
            System.exit(1);
        }

        try {
            int puertoModerador = Integer.parseInt(args[0]);
            int puertoClientes = Integer.parseInt(args[1]);

            Servidor servidor = new Servidor(puertoModerador, puertoClientes);
            servidor.generarClaves_Pub_Priv();
            servidor.esperarModerador();
            servidor.esperarClientes();

        } catch (NumberFormatException e) {
            System.err.println("❌ Error: Los puertos deben ser números enteros");
            System.exit(1);
        } catch (Exception e) {
            System.err.println("❌ Error en el servidor: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}