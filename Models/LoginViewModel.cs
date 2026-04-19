using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace AssetGuard.ViewModels
{
    public class LoginViewModel : INotifyPropertyChanged
    {
        // Properties used by the Unit Test
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public bool IsAuthenticated { get; private set; }

        private const string KeyUsername = "cred_username";
        private const string KeyPasswordHash = "cred_password_hash";
        private const string KeySalt = "cred_salt";

        // The method your test is calling
        public async Task<bool> LoginAsync()
        {
            IsAuthenticated = await VerifyCredentialsAsync(Username, Password);
            return IsAuthenticated;
        }

        public async Task<bool> VerifyCredentialsAsync(string username, string password)
        {
            try
            {
                var storedUser = await SecureStorage.Default.GetAsync(KeyUsername);
                if (string.IsNullOrEmpty(storedUser) || !storedUser.Equals(username, StringComparison.OrdinalIgnoreCase))
                    return false;

                var storedHashB64 = await SecureStorage.Default.GetAsync(KeyPasswordHash);
                var storedSaltB64 = await SecureStorage.Default.GetAsync(KeySalt);
                if (storedHashB64 == null || storedSaltB64 == null) return false;

                var salt = Convert.FromBase64String(storedSaltB64);
                var expectedHash = Convert.FromBase64String(storedHashB64);
                var computedHash = HashPassword(password, salt);

                return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
            }
            catch { return false; }
        }

        public static byte[] HashPassword(string password, byte[] salt)
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                password: password,
                salt: salt,
                iterations: 100_000,
                hashAlgorithm: HashAlgorithmName.SHA256,
                outputLength: 32);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = "") => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}