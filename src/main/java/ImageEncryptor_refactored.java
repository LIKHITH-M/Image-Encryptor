package ImageEncryptor;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Scanner;

public class ImageEncryptor {

    // Method to generate a secret key based on the chosen algorithm and key size
    private static SecretKey generateKey(String algorithm, int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(algorithm); // Get the KeyGenerator for the algorithm (AES or DES)
        keyGen.init(keySize); // Initialize with the specified key size (e.g., 128, 192, or 256 for AES)
        return keyGen.generateKey(); // Generate the secret key
    }

    // Method to process (encrypt or decrypt) a file using the given cipher configuration
    private static byte[] processFile(byte[] data, SecretKey key, String algorithm, String mode, int opMode) throws Exception {
        // Define the cipher instance using the provided algorithm, mode (e.g., ECB or CBC), and padding
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/PKCS5Padding");
        // If the mode is CBC (Cipher Block Chaining), generate an IV (Initialization Vector)
        if ("CBC".equals(mode)) {
            IvParameterSpec iv = new IvParameterSpec(generateIV(cipher.getBlockSize())); // Generate the IV
            cipher.init(opMode, key, iv); // Initialize the cipher for the given operation mode (encrypt/decrypt)
        } else {
            cipher.init(opMode, key); // For ECB mode, no IV is needed
        }
        return cipher.doFinal(data); // Apply the cipher to the file data (either encrypt or decrypt)
    }

    // Method to save the generated key to a file for later use (decryption)
    private static void saveKey(SecretKey key, String algorithm) throws IOException {
        // Write the key to a file with the specified algorithm name (e.g., "encryptionKey.aes" or "encryptionKey.des")
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("encryptionKey." + algorithm.toLowerCase()))) {
            out.writeObject(key); // Save the secret key object
        }
    }

    // Method to load a secret key from a previously saved key file
    private static SecretKey loadKey(String path) throws Exception {
        // Read the key object from the file and return it
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream(path))) {
            return (SecretKey) in.readObject();
        }
    }

    // Method to generate a random Initialization Vector (IV) of the specified block size
    private static byte[] generateIV(int blockSize) {
        byte[] iv = new byte[blockSize]; // Create an array of the specified block size
        new SecureRandom().nextBytes(iv); // Fill the array with random bytes
        return iv;
    }

    // Main method that runs the encryption/decryption operations in a loop
    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                // Ask the user to select whether the file is an image or another type
                System.out.print("Select file type (1 - Image, 2 - Other) [ENTER to quit]: ");
                String fileTypeChoice = scanner.nextLine();
                if (fileTypeChoice.isEmpty()) return; // If input is empty, exit the program

                boolean isImage = "1".equals(fileTypeChoice); // Determine if the file is an image (choice 1)

                // Ask the user to choose between encrypting or decrypting the file
                int operation = getChoice(scanner, "Choose operation (1 - Encrypt, 2 - Decrypt) [ENTER to quit]: ", 1, 2);
                if (operation == -1) return; // Exit if the user presses Enter without a valid choice

                SecretKey key = null;
                String algorithm = null;
                String mode = getMode(scanner); // Ask the user for the mode (ECB or CBC)
                if (mode == null) return; // Exit if no valid mode is provided

                // If the operation is encryption, ask for the algorithm (AES or DES) and key size
                if (operation == Cipher.ENCRYPT_MODE) {
                    algorithm = getAlgorithm(scanner); // Get the encryption algorithm (AES or DES)
                    if (algorithm == null) return; // Exit if no valid algorithm is chosen

                    int keySize = getKeySize(scanner, algorithm); // Ask for the key size
                    if (keySize == -1) return; // Exit if no valid key size is provided

                    try {
                        key = generateKey(algorithm, keySize); // Generate the key for encryption
                        saveKey(key, algorithm); // Save the generated key to a file for later use in decryption
                    } catch (Exception e) {
                        System.out.println("[ERROR] generating or saving key: " + e.getMessage());
                        return;
                    }
                } else {
                    // If the operation is decryption, load the key from the file
                    String keyFilePath = getFilePath(scanner, "Enter key file path for decryption (e.g., 'encryptionKey.des' || encryptionKey.aes') [ENTER to quit]: ");
                    if (keyFilePath == null || keyFilePath.trim().isEmpty()) {
                        return;
                    }

                    algorithm = getAlgorithmFromKeyFile(keyFilePath); // Determine the algorithm from the key file
                    if (algorithm == null) continue; // Skip if the key file has an invalid extension

                    try {
                        key = loadKey(keyFilePath); // Load the secret key from the file
                    } catch (Exception e) {
                        System.out.println("[ERROR] loading key file: " + e.getMessage());
                        return;
                    }
                }

                // Ask for the input file path (image or other file)
                String inputFilePath = getFilePath(scanner, "Enter input file path: [ENTER to quit]: ");
                if (inputFilePath == null) return;

                // Ask for the output file path where the processed file will be saved
                String outputFilePath = getOutputFilePath(scanner, isImage);

                // Process the file based on whether it is an image or not
                if (isImage) {
                    processAndSaveImageFile(inputFilePath, outputFilePath, key, algorithm, mode, operation);
                } else {
                    processAndSaveOtherFile(inputFilePath, outputFilePath, key, algorithm, mode, operation);
                }
            }
        } catch (Exception e) {
            System.out.println("[ERROR]: " + e.getMessage());
        }
    }

    // Process and save an image file after applying encryption or decryption
    private static void processAndSaveImageFile(String inputFilePath, String outputFilePath, SecretKey key, String algorithm, String mode, int operation) {
        try {
            byte[] fileContent = readFile(inputFilePath); // Read the image file content
            if (fileContent == null) return; // Exit if file reading fails

            // Split the image file into header (first 54 bytes) and pixel data (remaining bytes)
            byte[] header = new byte[54];
            byte[] pixelData = new byte[fileContent.length - 54];
            System.arraycopy(fileContent, 0, header, 0, 54); // Copy header
            System.arraycopy(fileContent, 54, pixelData, 0, pixelData.length); // Copy pixel data

            // Process the pixel data (encrypt or decrypt)
            byte[] processedData = processFile(pixelData, key, algorithm, mode, operation);

            // Write the processed data back to a new file
            try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
                fos.write(header); // Write the header first
                fos.write(processedData); // Write the processed pixel data
            }

            System.out.println((operation == Cipher.ENCRYPT_MODE ? "Encrypted" : "Decrypted") + " image successfully to: " + outputFilePath + "\n");
        } catch (Exception e) {
            System.out.println("[ERROR] processing image file: " + e.getMessage());
        }
    }

    // Process and save other file types (non-image) after applying encryption or decryption
    private static void processAndSaveOtherFile(String inputFilePath, String outputFilePath, SecretKey key, String algorithm, String mode, int operation) {
        try {
            byte[] fileContent = readFile(inputFilePath); // Read the file content
            if (fileContent == null) return; // Exit if file reading fails

            // Process the file data (encrypt or decrypt)
            byte[] processedData = processFile(fileContent, key, algorithm, mode, operation);

            // Write the processed data back to a new file
            try (FileOutputStream fos = new FileOutputStream(outputFilePath)) {
                fos.write(processedData);
            }

            System.out.println((operation == Cipher.ENCRYPT_MODE ? "Encrypted" : "Decrypted") + " file successfully to: " + outputFilePath + "\n");
        } catch (Exception e) {
            System.out.println("[ERROR] processing file: " + e.getMessage());
        }
    }

    // Method to read the content of a file into a byte array
    private static byte[] readFile(String filePath) {
        try {
            return new FileInputStream(filePath).readAllBytes(); // Read the entire file as byte array
        } catch (IOException e) {
            System.out.println("[ERROR] reading file: " + e.getMessage());
            return null;
        }
    }

    // Helper method to get a valid choice input (e.g., operation type, mode, algorithm, etc.)
    private static int getChoice(Scanner scanner, String prompt, int min, int max) {
        while (true) {
            System.out.print(prompt);
            String input = scanner.nextLine();
            if (input.isEmpty()) return -1;

            try {
                int choice = Integer.parseInt(input);
                if (choice >= min && choice <= max) return choice;
                else System.out.println("Invalid choice. Please try again.");
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please try again.");
            }
        }
    }

    // Helper method to get the encryption mode (ECB or CBC)
    private static String getMode(Scanner scanner) {
        int choice = getChoice(scanner, "Choose mode (1 - ECB, 2 - CBC) [ENTER to quit]: ", 1, 2);
        return choice == 1 ? "ECB" : choice == 2 ? "CBC" : null;
    }

    // Helper method to get the encryption algorithm (AES or DES)
    private static String getAlgorithm(Scanner scanner) {
        int choice = getChoice(scanner, "Choose algorithm (1 - AES, 2 - DES) [ENTER to quit]: ", 1, 2);
        return choice == 1 ? "AES" : choice == 2 ? "DES" : null;
    }

    // Helper method to get the AES key size (128, 192, or 256 bits)
    private static int getKeySize(Scanner scanner, String algorithm) {
        if ("DES".equals(algorithm)) return 56;
        while (true) {
            System.out.print("Enter AES key size (128, 192, 256) [ENTER to quit]: ");
            String input = scanner.nextLine();
            if (input.isEmpty()) return -1;

            try {
                int keySize = Integer.parseInt(input);
                if (keySize == 128 || keySize == 192 || keySize == 256) return keySize;
                else System.out.println("Invalid key size. Please enter a number between [128, 192, or 256].");
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a valid AES key size.");
            }
        }
    }

    // Helper method to get a valid file path (checks if the file exists)
    private static String getFilePath(Scanner scanner, String prompt) {
        while (true) {
            System.out.print(prompt);
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) return null;

            if (new File(input).exists()) return input;
            System.out.println("File not found. Please try again.");
        }
    }

    // Helper method to get the output file path
    private static String getOutputFilePath(Scanner scanner, boolean isImage) {
        System.out.print("Enter output file path [ENTER to quit]: ");
        String outputFilePath = scanner.nextLine().trim();
        if (isImage && !outputFilePath.contains(".")) outputFilePath += ".bmp"; // Add .bmp extension for image files
        return outputFilePath;
    }

    // Helper method to determine the encryption algorithm based on the key file extension
    private static String getAlgorithmFromKeyFile(String keyFilePath) {
        if (keyFilePath.endsWith(".aes")) return "AES";
        if (keyFilePath.endsWith(".des")) return "DES";
        System.out.println("Invalid key file extension. Please use '.aes' or '.des'.");
        return null;
    }
}
