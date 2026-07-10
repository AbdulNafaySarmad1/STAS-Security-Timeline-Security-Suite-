#ifndef IMPORT_PROFILER_H
#define IMPORT_PROFILER_H

#include <nlohmann/json.hpp>

#include <map>
#include <string>
#include <vector>

struct CategoryProfile {
    int import_count;
    std::vector<std::string> matched_imports;
    int risk_contribution;
};

struct ImportProfile {
    std::map<std::string, std::vector<std::string>> categories;
    std::map<std::string, CategoryProfile> category_details;
    std::string behavior_prediction;
    std::vector<std::string> top_capabilities;
    int stealth_score;
};

struct CapabilityRule {
    std::string category;
    std::vector<std::string> imports;
    int risk_contribution;
};

struct BehaviorPredictionRule {
    std::vector<std::string> required_categories;
    std::string prediction;
    int priority;
};

class ImportProfiler {
public:
    ImportProfiler();

    bool loadRulesFromFile(const std::string& rules_path);
    void loadRulesFromJson(const nlohmann::json& rules_json);
    void setRules(
        const std::vector<CapabilityRule>& capability_rules,
        const std::vector<BehaviorPredictionRule>& prediction_rules);

    ImportProfile profileImports(const std::vector<std::string>& imports) const;
    nlohmann::json toJson(const ImportProfile& profile) const;

private:
    std::vector<CapabilityRule> capability_rules;
    std::vector<BehaviorPredictionRule> prediction_rules;

    static std::string normalize(const std::string& value);
    static std::string baseImportName(const std::string& value);
    static bool containsImport(
        const std::vector<std::string>& normalized_imports,
        const std::string& wanted_import);
    static std::string predictBehavior(
        const std::map<std::string, CategoryProfile>& category_details,
        const std::vector<BehaviorPredictionRule>& prediction_rules);
    static std::vector<std::string> calculateTopCapabilities(
        const std::map<std::string, CategoryProfile>& category_details);
    static int calculateStealthScore(
        const std::map<std::string, CategoryProfile>& category_details);
};

#endif
