package com.sync.xxx.crypto

import android.util.Log
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

object FileCryptoManager {
    private const val ALGORITHM = "AES/CBC/PKCS5Padding"
    private const val TAG = "FileCrypto"
    
    private fun getSecretKey(secretKey: String): SecretKeySpec {
        // Pastikan key 32 byte untuk AES-256
        val keyBytes = secretKey.toByteArray(Charsets.UTF_8)
        val paddedKey = if (keyBytes.size >= 32) {
            keyBytes.copyOf(32)
        } else {
            val result = ByteArray(32)
            System.arraycopy(keyBytes, 0, result, 0, keyBytes.size)
            result
        }
        Log.d(TAG, "Key length: ${paddedKey.size} bytes")
        return SecretKeySpec(paddedKey, "AES")
    }
    
    private fun getIv(): IvParameterSpec {
        // IV STATIS 16 BYTE (agar kompatibel lintas perangkat)
        return IvParameterSpec(ByteArray(16))
    }
    
    fun encryptFile(inputFile: File, outputFile: File, secretKey: String): Boolean {
        return try {
            Log.d(TAG, "Encrypt: ${inputFile.name} → ${outputFile.name}")
            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(secretKey), getIv())
            
            FileInputStream(inputFile).use { fis ->
                CipherOutputStream(FileOutputStream(outputFile), cipher).use { cos ->
                    val buffer = ByteArray(4096)
                    var bytesRead: Int
                    while (fis.read(buffer).also { bytesRead = it } != -1) {
                        cos.write(buffer, 0, bytesRead)
                    }
                }
            }
            Log.d(TAG, "Encrypt success: ${inputFile.name}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Encrypt failed: ${e.message}")
            false
        }
    }
    
    fun decryptFile(inputFile: File, outputFile: File, secretKey: String): Boolean {
        return try {
            Log.d(TAG, "Decrypt: ${inputFile.name} → ${outputFile.name}")
            val cipher = Cipher.getInstance(ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, getSecretKey(secretKey), getIv())
            
            CipherInputStream(FileInputStream(inputFile), cipher).use { cis ->
                FileOutputStream(outputFile).use { fos ->
                    val buffer = ByteArray(4096)
                    var bytesRead: Int
                    while (cis.read(buffer).also { bytesRead = it } != -1) {
                        fos.write(buffer, 0, bytesRead)
                    }
                }
            }
            Log.d(TAG, "Decrypt success: ${inputFile.name}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Decrypt failed: ${e.message}")
            false
        }
    }
}