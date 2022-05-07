package security

import org.bouncycastle.crypto.generators.SCrypt;
import java.io.IOException;
import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;

object Encode {

  val SALT = "abc123";

  // DifficultyFactor
  // These should be powers of 2
  val cpu = 8;
  val memory = 8;
  val parallelism = 8;
  val outputLength = 32;

  @throws(classOf[IOException])
  def compress(hash: String): Array[Byte] = {
    val compress: Array[Byte] = GZIPCompression.compress(hash);
    return compress
  }

  @throws(classOf[Exception])
  def encrypt(keypair: KeyPair, hash: String): Array[Byte] = {

    val cipherText: Array[Byte] = Encryption.do_RSAEncryption(hash, keypair);

    val newHash: String = DatatypeConverter.printHexBinary(cipherText);

    return compress(newHash);
  }

  def hashpw(keypair: KeyPair, pass: String): String = {

      val hash: Array[Byte] = SCrypt.generate(pass.getBytes(), SALT.getBytes(), cpu, memory, parallelism, outputLength);

      val stored: String = DatatypeConverter.printHexBinary(hash);

    try {

      val newHash: Array[Byte] = encrypt(keypair, stored);

      return DatatypeConverter.printHexBinary(newHash);

    } catch {
      case e: Exception => {

      return "";
      }
    }

  }

  def verify(keypair: KeyPair, pass :String, hash: String): Boolean = {

    val newPass: String = hashpw(keypair, pass)

    return newPass.equals(hash)
  }
}
