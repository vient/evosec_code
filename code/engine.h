#pragma once

#include <string>
#include <vector>
#include <fstream>

#include "md5.h"
#include "pe.h"

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
        std::string Signature;
        size_t Begin;
        size_t End;
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
            WholeMD5Records.emplace_back(new_record);
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
            auto beg = temp.substr(it + 1, nit - it - 1);
            if (beg == "*")
                new_record.Begin = 0;
            else
                new_record.Begin = atoi(beg.c_str());
            it = nit;
            nit = temp.find(':', it + 1);
            auto end = temp.substr(it + 1, nit - it - 1);
            if (end == "*")
                new_record.Begin = 0;
            else
                new_record.Begin = atoi(end.c_str());
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
        auto md5_provider = MD5();
        std::string MD5(md5_provider.digestMemory(file.data(), file.size()));
        for (auto & x : WholeMD5Records)
            if (x.Signature == MD5 && file.size() == x.Size)
                return x.Verdict;
    }

    std::string CheckParts(const std::vector<unsigned char> &file)
    {
        auto md5_provider = MD5();
        auto sections = PESections(file);
        for (auto & section : sections)
        {
            std::string MD5(md5_provider.digestMemory(section.second.data(), section.second.size()));
            for (auto & x : PartialMD5Records)
                if (x.Signature == MD5 && section.second.size() == x.Size)
                    return x.Verdict;
        }
    }

    std::string CheckStrings(const std::vector<unsigned char> &file)
    {
        return "";
    }

public:
    Engine(const std::string base_path)     // TODO: different path styles
    {
        LoadHDB(base_path + "\\main.hdb");
        LoadMDB(base_path + "\\main.mdb");
        LoadNDB(base_path + "\\main.ndb");
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