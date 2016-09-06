#ifndef ENGINE_H
#define ENGINE_H

#include <string>
#include <vector>
#include <set>

class Engine
{
    struct MD5Record
    {
        std::string Signature;
        size_t Size;
        std::string Verdict;

        bool operator<(const MD5Record &record) const {
            return Signature < record.Signature;
        }
    };

    struct StringRecord
    {
        enum class RecordType : int 
        { 
            ENUM_BEGIN = -1, 
            ANY, 
            PE, 
            OLE2, 
            HTML, 
            MAIL, 
            GRAPHICS, 
            ELF, 
            ASCII, 
            UNUSED,
            MACH_O,
            PDF,
            FLASH,
            JAVA,
            ENUM_END
        };
        std::string Signature;
        RecordType Type;
        std::string Offset;
        std::string Verdict;
    };
    std::set<MD5Record> WholeMD5Records;
    std::set<MD5Record> PartialMD5Records;
    std::vector<StringRecord> StringRecords;

private:
    void LoadHDB(const std::string &path);
    void LoadMDB(const std::string &path);
    void LoadNDB(const std::string &path);

private:
    std::string CheckWholeFile(const std::vector<unsigned char> &file);
    std::string CheckParts(const std::vector<unsigned char> &file);
    std::string CheckStrings(const std::vector<unsigned char> &file);

public:
    Engine(const std::string base_path);
    ~Engine() {}
    std::string Check(const std::vector<unsigned char> &file);
};
#endif
