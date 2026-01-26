import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.*;
import java.util.UUID;

public class server {
    private static final int PORT = 4444;
    private static PublicKey PubKey;
    private static PrivateKey PriKey;
    static final Object lock = new Object();


    public static void main(String[] args) throws Exception {
        // Load keys from file
        PubKey = KeyLoader.loadPublicKey("keys/server_public.key");
        PriKey = KeyLoader.loadPrivateKey("keys/server_private.key");

        try (ServerSocket serverSkt = new ServerSocket(PORT)) {
            System.out.println("Zero-Trust Server started on port " + PORT);

            while (true) {
                Socket skt = serverSkt.accept();
                System.out.println("New client connected!");
                ClientThread thread = new ClientThread(skt, PubKey, PriKey);
                thread.start();
                // Pass the keys to the thread
            }
        }
    }


    public static void logAction(String details) {
        String logEntry = String.format("[%s] %s",
                java.time.LocalDateTime.now(), details);

        synchronized (lock) {
            try (FileWriter fw = new FileWriter("server.log", true);
                 PrintWriter out = new PrintWriter(fw)) {

                out.println(logEntry);

            } catch (IOException e) {
                System.err.println("Logging Error: " + e.getMessage());
            }
        }
    }

}

class ClientThread extends Thread {
    private Socket skt;
    private DataInputStream in;
    private DataOutputStream out;
    private String userUUID;
    private String userRole;
    private String currentSessionKey;
    private final PublicKey serverPublicKey;
    private final PrivateKey serverPrivateKey;

    private long sessionExpiryTime;
    private static final long SESSION_DURATION_MS = 1 * 60 * 1000;


    public ClientThread(Socket skt, PublicKey pub, PrivateKey priv) {
        this.skt = skt;
        this.serverPublicKey = pub;
        this.serverPrivateKey = priv;
    }

    @Override
    public void run() {
        try {
            in = new DataInputStream(skt.getInputStream());
            out = new DataOutputStream(skt.getOutputStream());



            // 1 Send pub key
            byte[] pubKeyBytes = serverPublicKey.getEncoded();
            out.writeInt(pubKeyBytes.length); //sending the length of the key first
            out.write(pubKeyBytes);  //sending the ky bytes next
            //System.out.println("Sent public key");
            // 2 Send Sig.
            byte[] signature = signData(pubKeyBytes, serverPrivateKey);
            out.writeInt(signature.length);
            out.write(signature);
            out.flush(); //to send both
            System.out.println("Sent signature and public key");

            //accept secret key from client
            int secretKeyLen = in.readInt();
            byte[] secretKeyBytes = new byte[secretKeyLen];
            in.readFully(secretKeyBytes);
            System.out.println("Received secret key from  client");


            //decrypting the secret key to use it
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
            byte[] decryptedAesBytes = rsaCipher.doFinal(secretKeyBytes);

            // Reconstruct the AES SecretKey object
            SecretKey secretKey = new SecretKeySpec(decryptedAesBytes, "AES");
            System.out.println("AES Tunnel Established.");
            //now logic for user login
            int attempts = 0;
            boolean authenticated = false;
            String currentUser = "";
            while (attempts < 3 && !authenticated) {

                // Receive encrypted creds from client
                // client sends: [IV Length][IV][Data Length][Data]
                int ivLen = in.readInt();
                byte[] iv = new byte[ivLen];
                in.readFully(iv);

                int cipherTextLen = in.readInt();
                byte[] cipherText = new byte[cipherTextLen];
                in.readFully(cipherText);


                Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
                aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new javax.crypto.spec.GCMParameterSpec(128, iv));
                byte[] plainText = aesCipher.doFinal(cipherText);

                //get username and pass from the client

                // Convert to String (Expected format: "username:passwordDigest")
                String creds = new String(plainText, "UTF-8");
                String[] parts = creds.split(":");
                String username = parts[0];
                String password = parts[1];


                UserInfo info = DatabaseManager.verifyWithDatabase(username, password);

                if (info != null) {
                    this.userUUID = info.uuid;
                    this.userRole = info.role;
                    this.currentSessionKey = UUID.randomUUID().toString();

                    this.sessionExpiryTime = System.currentTimeMillis() + SESSION_DURATION_MS;

                    String response = "SUCCESS:" + this.currentSessionKey + ":" + this.userRole + ":"+ this.userUUID;
                    byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
                    sendEncryptedBytes(responseBytes , secretKey);

                    authenticated = true;
                    currentUser = username;
                    System.out.println("Login Successful. Session Key generated for: " + username);
                } else {
                    attempts++;
                    String response = "FAIL";
                    byte[] responseBytes = response.getBytes(StandardCharsets.UTF_8);
                    sendEncryptedBytes(responseBytes,secretKey);
                    server.logAction("Failed login attempt [" + username+ "]");
                }

            }

            if (!authenticated) {
                return; // Exit thread and close connection if they fail 3 times
            }

            System.out.println("Entering command loop for user: " + currentUser);
            startCommandLoop(secretKey);


        } catch (Exception e) {
            System.out.println("Client disconnected or error: " + e.getMessage());
        } finally {
            closeConnections();
        }
    }

    private byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key);
        sig.update(data);
        return sig.sign();
    }

    private void closeConnections() {
        try { if(in!=null)in.close(); if(out!=null)out.close(); if(skt!=null)skt.close(); }
        catch (IOException e) { e.printStackTrace(); }
    }

    private void sendEncryptedBytes(byte[] plainText, SecretKey secretKey) throws Exception {

        // Setup Cipher and IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv); // Unique IV for every packet
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        // Encrypt
        byte[] cipherText = cipher.doFinal(plainText);

        // Send IV (Length then Bytes)
        out.writeInt(iv.length);
        out.write(iv);

        // 4. Send Ciphertext (Length then Bytes)
        out.writeInt(cipherText.length);
        out.write(cipherText);

        out.flush();
    }

    private void handleListFiles( SecretKey secretKey) throws Exception {

        byte[] requestedUUIDBytes = receiveEncryptedBytes(secretKey);
        String requestedUUID = new String(requestedUUIDBytes, StandardCharsets.UTF_8).trim();

        File folder = getTargetDirectory(requestedUUID);

        if (!folder.exists()) {
            //System.out.println("Folder doesn't exist");
            sendEncryptedBytes("ERROR: Folder does not exist.".getBytes(StandardCharsets.UTF_8), secretKey);
            return;
        }

        File[] listOfFiles = folder.listFiles();
        StringBuilder sb = new StringBuilder();
        sb.append("--- Private Files ---\n");

        if (listOfFiles == null || listOfFiles.length == 0) {
            sb.append("(Folder is empty)");
        } else {
            for (File file : listOfFiles) {
                if (file.isFile()) {
                    sb.append("📄 ").append(file.getName())
                            .append(" (").append(file.length()).append(" bytes)\n");
                }
            }
        }

        // Encrypt the list and send it back
        String sbString = sb.toString();
        byte[] sbBytes = sbString.getBytes(StandardCharsets.UTF_8);
        sendEncryptedBytes(sbBytes, secretKey);
    }

    private byte[] receiveEncryptedBytes(SecretKey key) throws Exception {
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

    private void startCommandLoop( SecretKey secretKey) throws Exception {
        int sessionFailures = 0;

        while (true) {
            try {
                // Receive "KEY:COMMAND"
                byte[] encryptedPayloadBytes = receiveEncryptedBytes(secretKey);
                String encryptedPayload = new String(encryptedPayloadBytes, StandardCharsets.UTF_8);

                // Split the payload
                String[] parts = encryptedPayload.split(":", 2);
                if (parts.length < 2) {
                    String msg = "ERROR: Something went wrong please try again!";
                    byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
                    sendEncryptedBytes(msgBytes, secretKey);
                    continue;
                }

                String receivedSessionKey = parts[0];
                String commandCode = parts[1].trim();

                if (System.currentTimeMillis() > this.sessionExpiryTime) {
                    String msg = "TERMINATE: Session expired. Please log in again.";
                    server.logAction("Session Expired for [UUID: " + this.userUUID + "]");
                    byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
                    sendEncryptedBytes(msgBytes, secretKey);
                    closeConnections();
                    break; // Kill the thread
                }

                //Verify Session Key
                if (!this.currentSessionKey.equals(receivedSessionKey)) {
                    sessionFailures++;
                    if (sessionFailures >= 3) {
                        String msg = "TERMINATE: Too many invalid session attempts.";
                        server.logAction("Failed providing the correct session key 3 times in a row [ UUID: " + this.userUUID+ "]" +" [Role: "+ this.userRole+"]");
                        byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
                        sendEncryptedBytes(msgBytes, secretKey);
                        closeConnections();
                        break;
                    }
                    String msg = "ERROR: Invalid Session Key (" + sessionFailures + "/3)";
                    byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
                    sendEncryptedBytes(msgBytes, secretKey);
                    continue;
                }else{
                    sessionFailures = 0;
                    String msg = "PROCEED";
                    byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
                    sendEncryptedBytes(msgBytes, secretKey);
                }

                // Handle the Command
                if (commandCode.equals("0") || commandCode.equalsIgnoreCase("EXIT")) break;

                switch (commandCode) {
                    case "1":
                        handleListFiles(secretKey);
                        break;
                    case "2":

                        handleUpload(secretKey);
                        break;

                    case "3":

                        handleDownload(secretKey);
                        break;
                    case "4":
                        handleDelete(secretKey);
                        break;
                    case "5":
                        handleListUsers(secretKey);
                        break;


                    default:
                        String msg = "ERROR: Unknown Command";
                        byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
                        sendEncryptedBytes(msgBytes, secretKey);
                }

            } catch (Exception e) {
                System.out.println("Connection closed.");
                break;
            }
        } //end while
    }


    private void handleUpload(SecretKey secretKey) throws Exception {
        //System.out.println("In upload file method");
        byte[] requestedUUIDBytes = receiveEncryptedBytes(secretKey);
        String requestedUUID = new String(requestedUUIDBytes, StandardCharsets.UTF_8).trim();



        byte[] fileNameBytes = receiveEncryptedBytes(secretKey);
        String fileName = new String (fileNameBytes,StandardCharsets.UTF_8);
        if (fileName.equals("ABORT")) return;
        byte[] fileContentBytes = receiveEncryptedBytes(secretKey);

        File userDir = getTargetDirectory(requestedUUID);
        if (!userDir.exists()) userDir.mkdirs();  //if user has no folder we make them a folder even tho not necessary

        File targetFile = new File(userDir, new File(fileName).getName());

        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(fileContentBytes);
            fos.flush();

            String msg = "File uploaded successfully.";
            byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
            sendEncryptedBytes(msgBytes, secretKey);
        }catch (IOException e) {
            // Error uploading
            sendEncryptedBytes("ERROR: Server could not write file to disk.".getBytes(), secretKey);
            server.logAction("Upload failed for " + fileName + ": " + e.getMessage());
        }
    }

    private void handleDownload(SecretKey secretKey) throws Exception {

        byte[] requestedUUIDBytes = receiveEncryptedBytes(secretKey);
        String requestedUUID = new String(requestedUUIDBytes, StandardCharsets.UTF_8).trim();

        File userDir = getTargetDirectory(requestedUUID);

        byte[] fileNameBytes = receiveEncryptedBytes(secretKey);
        String fileName = new String(fileNameBytes, StandardCharsets.UTF_8);

        File file = new File(userDir , new File(fileName).getName());

        if (!file.exists() || !file.isFile()) {

            String msg = "ERROR: File not found";
            byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
            sendEncryptedBytes(msgBytes, secretKey);
            return;
        }

        // Send the file content bytes
        byte[] fileContent = java.nio.file.Files.readAllBytes(file.toPath());
        sendEncryptedBytes(fileContent, secretKey);
        System.out.println("Sent " + fileName + " to client.");
    }

    private void handleDelete(SecretKey secretKey) throws Exception {
        byte[] requestedUUIDBytes = receiveEncryptedBytes(secretKey);
        String requestedUUID = new String(requestedUUIDBytes, StandardCharsets.UTF_8).trim();

        File userDir = getTargetDirectory(requestedUUID);

        //receive filename
        byte[] fileNameBytes = receiveEncryptedBytes(secretKey);
        String fileName = new String(fileNameBytes, StandardCharsets.UTF_8);

        //Locate the file in the user's specific folder
        File fileToDelete = new File(userDir,new File(fileName).getName());

        //Attempt deletion and prepare response
        String response;
        if (fileToDelete.exists() && fileToDelete.isFile()) {
            if (fileToDelete.delete()) {
                response = "SUCCESS: File '" + fileName + "' deleted.";
                server.logAction("Deleted a file! " + "[File: "+fileName+ "] [Folder: "+requestedUUID + "] [UUID:" + this.userUUID+ "]" +" [Role: "+ this.userRole+"]");
            } else {
                response = "ERROR: Could not delete file.";
            }
        } else {
            response = "ERROR: File not found.";
        }

        sendEncryptedBytes(response.getBytes(StandardCharsets.UTF_8), secretKey);
    }

    private void handleListUsers(SecretKey secretKey) throws Exception {
        if (!"admin".equalsIgnoreCase(this.userRole)) {
            sendEncryptedBytes("ERROR: Unknown Command".getBytes(), secretKey);
            return;
        }
        File storage = new File("storage");
        String[] folders = storage.list((dir, name) -> new File(dir, name).isDirectory());
        String list = (folders == null) ? "No users found." : String.join("\n", folders);
        sendEncryptedBytes(list.getBytes(StandardCharsets.UTF_8), secretKey);
    }

    private File getTargetDirectory(String requestedUUID) {
        // Default
        String target = this.userUUID;

        if ("admin".equalsIgnoreCase(this.userRole) && requestedUUID != null && !requestedUUID.isEmpty()) {
            target = requestedUUID;
        }

        // Sanitize the target string to prevent directory traversal
        String UUID = new File(target).getName();


        File dir = new File("storage/" + UUID);
        if (!dir.exists()) System.out.println("Folder does not exist");
        return dir;
    }

}

// This is just a container to hold data fetched from the DB
class UserInfo {
    String uuid;
    String role;

    UserInfo(String uuid, String role) {
        this.uuid = uuid;
        this.role = role;
    }
}