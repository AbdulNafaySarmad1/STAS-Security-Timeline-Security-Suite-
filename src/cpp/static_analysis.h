#ifndef STATIC_ANALYSIS_H
#define STATIC_ANALYSIS_H

#include <string>
#include <vector>

struct SectionEntropy {
    std::string name;
    double entropy;
    std::string verdict;
    std::string explanation;
    bool suspicious;
};

class StaticAnalysis {
private:
    std::string filepath;
    std::vector<std::string> imported_functions;
    std::vector<SectionEntropy> section_entropies;
    int overall_packed_confidence;

    static double calculateShannonEntropy(const unsigned char* data, size_t size);
    static SectionEntropy interpretSectionEntropy(const std::string& name, double entropy);
    static int calculatePackedConfidence(const std::vector<SectionEntropy>& sections);
public:
    StaticAnalysis(const std::string& file);
    void performAnalysis();
    void computeHashes();
    void calculateEntropy();
    void detectPackers();
    const std::vector<std::string>& getImportedFunctions() const;
    const std::vector<SectionEntropy>& getSectionEntropies() const;
    int getOverallPackedConfidence() const;
};

#endif
