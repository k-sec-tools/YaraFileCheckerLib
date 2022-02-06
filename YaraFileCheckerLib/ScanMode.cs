namespace YaraFileCheckerLib;

public partial class FileChecker : IFileChecker
{
    public enum ScanMode
    {
        Custom = 0,
        Lite = 1,
        Mid = 2,
        Hard = 3
    }
}