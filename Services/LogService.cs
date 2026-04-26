namespace AssetGuard.Services
{
    public class LogService
    {
        private readonly string? _logFilePath;

        // Empty constructor for Unit Testing/Moq ---
        // This stops the test from crashing when trying to find a real file path
        public LogService() { }

        public LogService(string logFilePath)
        {
            _logFilePath = logFilePath;
        }

        public virtual void LogAction(string action)
        {
            // If we are in a test and _logFilePath is null, don't try to write to a file
            if (string.IsNullOrEmpty(_logFilePath)) return;

            var logEntry = $"{DateTime.Now:dd-MM-yyyy HH:mm:ss} - {action}{Environment.NewLine}";
            File.AppendAllText(_logFilePath, logEntry);
        }

        // Marked as virtual so Moq can handle it in tests if needed
        public virtual string LogFilePath => _logFilePath ?? string.Empty;

        // Marked as virtual so Moq can "fake" reading logs without looking for a real file
        public virtual string ReadAll()
        {
            if (string.IsNullOrEmpty(_logFilePath)) return string.Empty;

            return File.Exists(_logFilePath) ? File.ReadAllText(_logFilePath) : string.Empty;
        }
    }
}