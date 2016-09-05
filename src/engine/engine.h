#pragma once

#include <string>
#include <vector>
#include <fstream>
#include <regex>

#include "md5.h"
#include "pe.h"

#include <iostream>
using namespace std;

class Engine
{

    struct MD5Record
    {
        std::string Signature;
        size_t Size;
        std::string Verdict;
    };

    struct StringRecord
    {
        enum class RecordType : int { LEFT_BOUND = -1, ANY, PE, OLE2, HTML, MAIL, GRAPHICS, ELF, ASCII, RIGHT_BOUND };
        std::string Signature;
        RecordType Type;
        std::string Offset;
        std::string Verdict;
    };

    std::vector<MD5Record> WholeMD5Records;
    std::vector<MD5Record> PartialMD5Records;
    std::vector<StringRecord> StringRecords;

    void LoadHDB(const std::string path)
    {
        std::ifstream in(path);
        std::string temp;
        while (std::getline(in, temp))
        {
            if (temp.find(':') == std::string::npos)
                continue;
            MD5Record new_record;

            auto it = temp.find(':');
            new_record.Signature = temp.substr(0, it);
            auto nit = temp.find(':', it + 1);
            new_record.Size = atoi(temp.substr(it + 1, nit - it - 1).c_str());
            new_record.Verdict = temp.substr(nit + 1);
            WholeMD5Records.emplace_back(new_record);
        }
    }

    void LoadMDB(const std::string path)
    {
        std::ifstream in(path);
        std::string temp;
        while (std::getline(in, temp))
        {
            if (temp.find(':') == std::string::npos)
                continue;
            MD5Record new_record;

            auto it = temp.find(':');
            new_record.Size = atoi(temp.substr(it).c_str());
            auto nit = temp.find(':', it + 1);
            new_record.Signature = temp.substr(it + 1, nit - it - 1);
            new_record.Verdict = temp.substr(nit + 1);
            PartialMD5Records.emplace_back(new_record);
        }
    }

    void LoadNDB(const std::string path)
    {
        std::ifstream in(path);
        std::string temp;
        while (std::getline(in, temp))
        {
            if (temp.find(':') == std::string::npos)
                continue;

            StringRecord new_record;
            auto it = temp.find(':');
            new_record.Verdict = temp.substr(0, it);
            auto nit = temp.find(':', it + 1);
            auto type = atoi(temp.substr(it + 1, nit - it - 1).c_str());
            assert(type > static_cast<int>(StringRecord::RecordType::LEFT_BOUND) && type < static_cast<int>(StringRecord::RecordType::RIGHT_BOUND));
            new_record.Type = static_cast<StringRecord::RecordType>(type);
            it = nit;
            nit = temp.find(':', it + 1);
            auto offset = temp.substr(it + 1, nit - it - 1);
            if (offset == "*")
                new_record.Offset = "0";
            else
                new_record.Offset = offset;     // there are offsets like EP+0,200
            it = nit;
            nit = temp.find(':', it + 1);
            if (nit == std::string::npos)
                new_record.Signature = temp.substr(it + 1);
            else
                new_record.Signature = temp.substr(it + 1, nit - it - 1);
            StringRecords.emplace_back(new_record);
        }
    }

    std::string CheckWholeFile(const std::vector<unsigned char> &file)
    {

        std::string MD5 = md5(file);
        for (auto & x : WholeMD5Records)
            if (x.Signature == MD5 && file.size() == x.Size)
                return x.Verdict;
        return "";
    }

    std::string CheckParts(const std::vector<unsigned char> &file)
    {
        auto sections = PESections(file);
        for (auto & section : sections)
        {
            std::string MD5 = md5(file);
            for (auto & x : PartialMD5Records)
                if (x.Signature == MD5 && section.second.size() == x.Size)
                    return x.Verdict;
        }
        return "";
    }

    std::string CheckStrings(const std::vector<unsigned char> &file)
    {

        return "";
    }

public:
    // TODO: different path styles
    Engine(const std::string base_path)
    {
        LoadHDB(base_path + "/main.hdb");
        LoadMDB(base_path + "/main.mdb");
        LoadNDB(base_path + "/main.ndb");
    }
    ~Engine() {}

    std::string Check(const std::vector<unsigned char> &file)
    {
        auto x = CheckWholeFile(file);
        if (x.size())
            return x;

        x = CheckParts(file);
        if (x.size())
            return x;

        return CheckStrings(file);
    }
};
