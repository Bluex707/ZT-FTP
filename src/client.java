import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class client {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 4444;

    public static void main(String[] args) {

        startClient();
    }


    public static void startClient() {
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT)) {
            System.out.println("Connecting to Secure Vault...");

            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            // Authenticate the Server (Handshake)
            PublicKey serverPubKey = performHandshake(in);
            if (serverPubKey == null) return;

            // Establish Secure Tunnel (AES)
            SecretKey secretKey = establishAesTunnel(serverPubKey, out);

            // Login to get Session Key
            String response = performLogin(in, out, secretKey);
            if(response!=null) {
                String[] parts = response.split(":");
                String sessionKey = parts[1];
                String userRole = parts[2];
                String userUUID = parts[3];


                if (sessionKey != null) {
                    runCommandLoop(in, out, secretKey, sessionKey, userRole, userUUID);
                }
            }else {
                System.out.println("Login Error!");
            }

        } catch (Exception e) {
            System.out.println("Client Error: " + e.getMessage());
        }
    }


    private static PublicKey performHandshake(DataInputStream in) throws Exception {
        int pubKeyLength = in.readInt();
        byte[] receivedPubKeyBytes = new byte[pubKeyLength];
        in.readFully(receivedPubKeyBytes);

        int sigLength = in.readInt();
        byte[] signature = new byte[sigLength];
        in.readFully(signature);

        PublicKey trustedKey = KeyLoader.loadPublicKey("keys/server_public.key");  //assuming this is the place that the client saved the trusted key for the server
        if (verifySignature(receivedPubKeyBytes, signature, trustedKey)) {
            System.out.println("[Handshake] Server verified.");
            return trustedKey;
        }
        System.out.println("[Handshake] FAILED: Untrusted Server.");
        return null;
    }


    private static SecretKey establishAesTunnel(PublicKey pubKey, DataOutputStream out) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());

        out.writeInt(encryptedKey.length);
        out.write(encryptedKey);
        out.flush();
        return secretKey;
    }


    private static String performLogin(DataInputStream in, DataOutputStream out, SecretKey secretKey) throws Exception {
        Scanner scanner = new Scanner(System.in);
        for (int i = 0; i < 3; i++) {
            System.out.print("Username: ");
            String user = scanner.nextLine();
            System.out.print("Password: ");
            String pass = scanner.nextLine();


            String msg = user + ":" + hash(pass);
            byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
            sendEncryptedBytes(msgBytes, secretKey, out);
            byte[] responseBytes = receiveEncryptedBytes(secretKey, in);
            String response = new String(responseBytes, StandardCharsets.UTF_8);


            if (response.startsWith("SUCCESS")) {

                System.out.println("Logged in successfully!");

                return response;
            }
            System.out.println("Invalid credentials. Attempts left: " + (2 - i));
        }
        return null;
    }


    private static void runCommandLoop(DataInputStream in, DataOutputStream out, SecretKey secretKey, String sessionKey,String userRole, String userUUID) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.println("\n--- Logged In Successfully ---");

        while (true) {
            System.out.println("Commands: [1] List  [2] Upload  [3] Download  [4] Delete  [0] Exit");
            System.out.print("My Files> ");
            String cmd = scanner.nextLine().trim();
            if (cmd.equals("0")) break;

            if (!cmd.equals("1") && !cmd.equals("2") && !cmd.equals("3") && !cmd.equals("4") && !cmd.equals("5")) {
                System.out.println("Invalid command!");
                continue;
            }


            String status = sendCommandAndGetStatus(cmd, sessionKey, secretKey, out, in);

            if (status.contains("TERMINATE")) {
                if (status.contains("expired")) {
                    System.out.println("SESSION EXPIRED: Your window has closed.");
                    System.out.println("Please log in again.");
                }
                else if (status.contains("session")) {
                    System.out.println("SECURITY ALERT: Invalid Session Key detected.");
                }
                else {
                    System.out.println("Server disconnected: " + status);
                }

                break; // Kill connection
            }

            if (status.startsWith("ERROR")) {
                System.out.println("Server: " + status);
                continue; // Back to menu
            }

            switch (cmd) {
                case "1":
                    handleList(scanner,secretKey,in,out,userRole,userUUID);
                    break;
                case "2":
                    handleUpload(scanner, secretKey, out, in,userRole,userUUID);
                    break;
                case "3":
                    handleDownload(scanner, secretKey, out, in,userRole,userUUID);
                    break;
                case "4":
                    handleDelete(scanner, secretKey, in, out,userUUID,userRole);
                    break;
                case "5":
                    handleListUsers(secretKey, in);
                    break;
                default:
                    System.out.println("Critical Error");
                    break;
            }
        }
    }


    private static String sendCommandAndGetStatus(String cmd, String sessionKey, SecretKey secretKey, DataOutputStream out, DataInputStream in) throws Exception {

        String payload = sessionKey + ":" + cmd;
        sendEncryptedBytes(payload.getBytes(StandardCharsets.UTF_8), secretKey, out);

        // Receive the status (PROCEED, ERROR, or TERMINATE)
        byte[] resultBytes = receiveEncryptedBytes(secretKey, in);
        return new String(resultBytes, StandardCharsets.UTF_8);
    }

    private static void sendEncryptedBytes(byte[] data, SecretKey key, DataOutputStream out) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] cipherText = c.doFinal(data);

        out.writeInt(iv.length);
        out.write(iv);
        out.writeInt(cipherText.length);
        out.write(cipherText);
        out.flush();
    }

    private static byte[] receiveEncryptedBytes(SecretKey key, DataInputStream in) throws Exception {
        int ivLen = in.readInt();
        byte[] iv = new byte[ivLen];
        in.readFully(iv);
        int dataLen = in.readInt();
        byte[] cipherText = new byte[dataLen];
        in.readFully(cipherText);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(cipherText);
    }

    private static boolean verifySignature(byte[] d, byte[] s, PublicKey k) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(k);
        sig.update(d);
        return sig.verify(s);
    }

    private static void handleList(Scanner scanner,SecretKey secretKey,DataInputStream in,DataOutputStream out,String userRole,String userUUID) throws Exception{
        String targetToRequest = userUUID;
        if(userRole.equalsIgnoreCase("admin")){
            System.out.println("Enter the uuid for the user you want to check or (click Enter to list YOURS):");
            String input =scanner.nextLine();
            if(!input.isEmpty()){
                targetToRequest = input;
            }
        }

        byte[] sendUUID = targetToRequest.getBytes(StandardCharsets.UTF_8);
        sendEncryptedBytes(sendUUID,secretKey,out);

        //receive the list for that specific uuid
        byte[] resultBytes = receiveEncryptedBytes(secretKey, in);
        String result = new String(resultBytes,StandardCharsets.UTF_8);
        System.out.println("Server: " + result);

    }
    private static void handleUpload(Scanner scanner, SecretKey secretKey, DataOutputStream out, DataInputStream in,String userRole,String userUUID) throws Exception {


        String targetToRequest = userUUID; // Default to self
        if (userRole.equalsIgnoreCase("admin")) {
            System.out.println("Enter target User UUID to upload to (or press Enter for your own folder):");
            String input = scanner.nextLine().trim();
            if (!input.isEmpty()) {
                targetToRequest = input;
            }
        }
        // Send the target folder
        sendEncryptedBytes(targetToRequest.getBytes(StandardCharsets.UTF_8), secretKey, out);


        System.out.println("Enter file path!");
        String filePath = scanner.nextLine();

        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.out.println("Error: File not found or is a directory.");
            sendEncryptedBytes("ABORT".getBytes(), secretKey, out);
            return;
        }

        // Send the filename
        String fileName = file.getName();
        System.out.println("Sending filename: " + fileName);
        byte[] fileNameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        sendEncryptedBytes(fileNameBytes, secretKey, out);

        //  Read file into bytes
        byte[] fileContent = java.nio.file.Files.readAllBytes(file.toPath());

        // Send the raw bytes
        System.out.println("Uploading data (" + fileContent.length + " bytes)...");
        sendEncryptedBytes(fileContent, secretKey, out);

        //  Wait for server confirmation
        byte[] serverResponseBytes = receiveEncryptedBytes(secretKey, in);
        String serverResponse = new String(serverResponseBytes,StandardCharsets.UTF_8);
        System.out.println("Server: " + serverResponse);

    }

    private static void handleDownload(Scanner scanner, SecretKey secretKey, DataOutputStream out, DataInputStream in,String userRole, String userUUID) throws Exception {

        String targetToRequest = userUUID; // Default to self
        if (userRole.equalsIgnoreCase("admin")) {
            System.out.println("Enter target User UUID to upload to (or press Enter for your own folder):");
            String input = scanner.nextLine().trim();
            if (!input.isEmpty()) {
                targetToRequest = input;
            }
        }
        // Send the Target UUID packet first
        sendEncryptedBytes(targetToRequest.getBytes(StandardCharsets.UTF_8), secretKey, out);

        System.out.print("Enter filename to download: ");
        String fileName = scanner.nextLine();

        byte[] nameBytes = fileName.getBytes(StandardCharsets.UTF_8);
        sendEncryptedBytes(nameBytes, secretKey, out);

        byte[] fileData = receiveEncryptedBytes(secretKey, in);

        // Check if the server sent an error instead of file data
        String possibleError = new String(fileData, StandardCharsets.UTF_8);
        if (possibleError.startsWith("ERROR:")) {
            System.out.println("Server " + possibleError);
            return;
        }

        // Save the file locally (e.g., in a 'downloads' folder)
        File downloadDir = new File("downloads");
        if (!downloadDir.exists()) downloadDir.mkdir();

        File targetFile = new File(downloadDir, fileName);
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(fileData);
            fos.flush();
        }
        System.out.println("Successfully downloaded to: " + targetFile.getAbsolutePath());
    }

    private static void handleDelete(Scanner scanner,SecretKey secretKey,DataInputStream in,DataOutputStream out,String userUUID,String userRole) throws Exception{
        String targetToRequest = userUUID;
        if (userRole.equalsIgnoreCase("admin")) {
            System.out.println("Enter target User UUID to upload to (or press Enter for your own folder):");
            String input = scanner.nextLine().trim();
            if (!input.isEmpty()) {
                targetToRequest = input;
            }
        }

        sendEncryptedBytes(targetToRequest.getBytes(StandardCharsets.UTF_8), secretKey, out);

        System.out.print("Enter filename to delete: ");
        String fileName = scanner.nextLine();


        sendEncryptedBytes(fileName.getBytes(StandardCharsets.UTF_8), secretKey, out);

        byte[] ServerResposneBytes = receiveEncryptedBytes(secretKey, in);
        String stringRespnse = new String(ServerResposneBytes,StandardCharsets.UTF_8);
        System.out.println("Server: " +stringRespnse);

    }

    private static void handleListUsers(SecretKey secretKey, DataInputStream in) throws Exception {

        //System.out.println("in handleListUsers");

        // Receive the list of folder names (UUIDs) from the server
        byte[] resultBytes = receiveEncryptedBytes(secretKey, in);
        String result = new String(resultBytes, StandardCharsets.UTF_8);

        System.out.println(result);

    }

    private static String hash(String p) throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(p.getBytes(StandardCharsets.UTF_8)));
    }
}