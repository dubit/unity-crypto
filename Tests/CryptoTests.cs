using System.Security.Cryptography;
using NUnit.Framework;
using UnityEditor.VersionControl;

namespace DUCK.Crypto.Tests
{
	public class CryptoTests
	{
		private readonly string plaintext = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor.";

		private readonly string password1 = "$tr0ngP4ssw0rd!";
		private readonly string password2 = "U|n8r34k@bl3?";

		private readonly string exampleValidIV = "c+MasEKX86kbnwFowjVAyA==";

		[Test]
		public void ExpectEmptyInputsToProduceValidEncryption()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(string.Empty, string.Empty);

			Assert.IsTrue(!string.IsNullOrEmpty(encryptionResult.IV));
			Assert.IsTrue(!string.IsNullOrEmpty(encryptionResult.EncryptedText));
		}

		[Test]
		public void ExpectValidEncryptionToSucceed()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(plaintext, password1);

			Assert.IsTrue(!string.IsNullOrEmpty(encryptionResult.EncryptedText));

			Assert.AreNotEqual(plaintext, encryptionResult.EncryptedText);
		}

		[Test]
		public void ExpectValidDecryptionToSucceed()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(plaintext, password1);
			var decryptedText = SimpleAESEncryption.Decrypt(encryptionResult, password1);

			Assert.AreEqual(plaintext, decryptedText);
		}

		[Test]
		public void ExpectWrongPasswordToFail()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(plaintext, password1);

			Assert.Throws<CryptographicException>(() =>
			{
				SimpleAESEncryption.Decrypt(encryptionResult, password2);
			});
		}

		[Test]
		public void ExpectEmptyPasswordToFail()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(plaintext, password1);

			Assert.Throws<CryptographicException>(() =>
			{
				SimpleAESEncryption.Decrypt(encryptionResult, string.Empty);
			});
		}

		[Test]
		public void ExpectWrongIVToFail()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(plaintext, password1);
			var decryptedText = SimpleAESEncryption.Decrypt(encryptionResult.EncryptedText, exampleValidIV, password1);

			Assert.IsTrue(!string.IsNullOrEmpty(encryptionResult.EncryptedText));

			Assert.AreNotEqual(plaintext, encryptionResult.EncryptedText);
			Assert.AreNotEqual(plaintext, decryptedText);
		}

		[Test]
		public void ExpectEmptyIVToFail()
		{
			var encryptionResult = SimpleAESEncryption.Encrypt(plaintext, password1);

			Assert.Throws<CryptographicException>(() =>
			{
				SimpleAESEncryption.Decrypt(encryptionResult.EncryptedText, string.Empty, password1);
			});
		}
	}
}

