import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.HashMap;
import java.util.Map;
import java.io.*;

public class PasswordManager {
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        Map<String, String> passwordData = new HashMap<>();
        File passwordFile = new File("passwords.txt");
        byte[] salt;
        byte[] encryptedToken;

        if (!passwordFile.exists()) {
            System.out.print("Enter the passcode to create the password manager: ");
            String masterPassword = scanner.nextLine();
            salt = generateSalt();
            encryptedToken = encryptToken(masterPassword, salt);
            saveToFile(passwordData, salt, encryptedToken);
            System.out.println("No pasword file detected. Creating a new password file.");
        } else {
            System.out.print("Enter the passcode to access your passwords: ");
            String masterPassword = scanner.nextLine();
            passwordData = loadFromFile();
            if (!passwordData.containsKey("salt") || !passwordData.containsKey("token")) {
                System.err.println("Password file is corrupted or incomplete.");
                System.exit(1);
            }
            salt = Base64.getDecoder().decode(passwordData.get("salt"));
            encryptedToken = Base64.getDecoder().decode(passwordData.get("token"));
            if (!verifyToken(masterPassword, salt, encryptedToken)) {
                System.err.println("incorrect password");
                System.exit(1);
            }
        }

        while (true) {
            System.out.println("a : Add Password\nr : Read Password\nq : Quit");
            System.out.print("Enter choice: ");
            String choice = scanner.nextLine();
            switch (choice) {
                case "a":
                    addPassword(scanner, passwordData, salt);
                    saveToFile(passwordData, salt, encryptedToken);
                    break;
                case "r":
                    readPassword(scanner, passwordData, salt);
                    break;
                case "q":
                    System.out.println("Quitting");
                    System.exit(0);
                    break;
                default:
                    System.out.println("Invalid choice.");
                    break;
            }
        }
    }

    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    private static byte[] encryptToken(String password, byte[] salt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(password, salt);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        String token = "verify";
        return cipher.doFinal(token.getBytes());
    }

    private static boolean verifyToken(String password, byte[] salt, byte[] encryptedToken) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = deriveKeyFromPassword(password, salt);
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decryptedToken = cipher.doFinal(encryptedToken);
            return new String(decryptedToken).equals("verify");
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            System.err.println("incorrect password");
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static SecretKeySpec deriveKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] key = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    private static void addPassword(Scanner scanner, Map<String, String> passwordData, byte[] salt) throws Exception {
        System.out.print("Enter label for password: ");
        String label = scanner.nextLine();
        System.out.print("Enter password to store: ");
        String password = scanner.nextLine();
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(label, salt);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());
        passwordData.put(label, Base64.getEncoder().encodeToString(encryptedPassword));
    }

    private static void readPassword(Scanner scanner, Map<String, String> passwordData, byte[] salt) throws Exception {
        System.out.print("Enter label for password: ");
        String label = scanner.nextLine();
        String encryptedPassword = passwordData.get(label);
        if (encryptedPassword == null) {
            System.out.println("Password not found for label: " + label);
            return;
        }
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = deriveKeyFromPassword(label, salt);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedPassword = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        System.out.println("Found: " + new String(decryptedPassword));
    }

    private static void saveToFile(Map<String, String> passwordData, byte[] salt, byte[] encryptedToken) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter("passwords.txt"));
        String encodedSalt = Base64.getEncoder().encodeToString(salt);
        String encodedToken = Base64.getEncoder().encodeToString(encryptedToken);
        writer.write(encodedSalt + ":" + encodedToken + "\n");
        for (Map.Entry<String, String> entry : passwordData.entrySet()) {
            if (!entry.getKey().equals("salt") && !entry.getKey().equals("token")) {
                writer.write(entry.getKey() + ":" + entry.getValue() + "\n");
            }
        }
        writer.close();
    }

    private static Map<String, String> loadFromFile() throws IOException {
        Map<String, String> passwordData = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader("passwords.txt"));
        String line;
        if ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            if (parts.length == 2) {
                passwordData.put("salt", parts[0]);
                passwordData.put("token", parts[1]);
            } else {
                System.err.println("Incorrect format in salt/token line.");
                System.exit(1);
            }
        }
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            if (parts.length == 2) {
                passwordData.put(parts[0], parts[1]);
            } else {
                System.err.println("Incorrect format in password entry: " + line);
            }
        }
        reader.close();
        return passwordData;
    }
}
