using System;
using System.IO;

namespace AssetGuard.Services
{
    public class LogService
    {
        private readonly string logFilePath;

        public LogService(string logFilePath)
        {
            this.logFilePath = logFilePath;
        }

        public void LogAction(string action)
        {
            var logEntry = $"{DateTime.Now:dd-MM-yyyy HH:mm:ss} - {action}{Environment.NewLine}";
            File.AppendAllText(logFilePath, logEntry);
        }

        public string LogFilePath => logFilePath;
    }
}