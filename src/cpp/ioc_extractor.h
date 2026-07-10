#ifndef IOC_EXTRACTOR_H
#define IOC_EXTRACTOR_H

#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <vector>

struct IOC {
    std::string type;
    std::string value;
    float confidence;
    std::string context;
    int file_offset;
};

struct StringArtifact {
    std::string value;
    int file_offset;
};

class IOCExtractor {
public:
    IOCExtractor();

    std::vector<IOC> extract(const std::vector<std::string>& strings) const;
    std::vector<IOC> extract(const std::vector<StringArtifact>& strings) const;

    static double scoreDgaDomain(const std::string& domain);
    static std::string defang(const std::string& value);

    nlohmann::json toJson(const std::vector<IOC>& iocs, bool defang_output = false) const;
    std::string toCsv(const std::vector<IOC>& iocs, bool defang_output = false) const;
    nlohmann::json toStixBundle(const std::vector<IOC>& iocs, bool defang_output = false) const;

private:
    std::set<std::string> known_legitimate_domains;
    std::set<std::string> valid_tlds;

    void extractFromString(
        const StringArtifact& artifact,
        std::vector<IOC>& out,
        std::set<std::string>& seen) const;

    void addIoc(
        std::vector<IOC>& out,
        std::set<std::string>& seen,
        const std::string& type,
        const std::string& value,
        float confidence,
        const std::string& source,
        int base_offset,
        size_t match_offset) const;

    bool isFalsePositive(const std::string& type, const std::string& value) const;
    bool isLegitimateDomain(const std::string& domain) const;
    bool hasValidTld(const std::string& domain) const;

    static bool isExcludedIpv4(const std::string& value);
    static bool isLikelyPassword(const std::string& candidate);
    static double shannonEntropy(const std::string& value);
    static std::string normalizeLower(const std::string& value);
    static std::string trimTrailingPunctuation(const std::string& value);
    static std::string makeContext(const std::string& source, size_t match_offset, size_t match_length);
    static std::string csvEscape(const std::string& value);
    static std::string indicatorPatternType(const std::string& ioc_type);
    static std::string stixPattern(const IOC& ioc, const std::string& value);
    static std::string deterministicStixId(const IOC& ioc);
};

#endif
