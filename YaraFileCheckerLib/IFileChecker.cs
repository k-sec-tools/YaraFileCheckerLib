namespace YaraFileCheckerLib;

public interface IFileChecker
{
    FileScanResult CheckFile(FileObject fileObject, string scanProfileName = null);
}