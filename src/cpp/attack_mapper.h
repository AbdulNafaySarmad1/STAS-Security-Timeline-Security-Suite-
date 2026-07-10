#ifndef ATTACK_MAPPER_H
#define ATTACK_MAPPER_H

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

struct ATTACKTechnique {
    std::string id;
    std::string name;
    std::string tactic;
    float confidence;
    std::vector<std::string> triggered_by;
};

struct ATTACKRule {
    std::string id;
    std::string name;
    std::string tactic;
    float confidence;
    std::vector<std::string> required_imports;
    std::vector<std::string> required_behaviors;
};

class ATTACKMapper {
public:
    ATTACKMapper();

    bool loadRulesFromFile(const std::string& rules_path);
    void loadRulesFromJson(const nlohmann::json& rules_json);
    void setRules(const std::vector<ATTACKRule>& rules);

    std::vector<ATTACKTechnique> mapTechniques(
        const std::vector<std::string>& imports,
        const std::vector<std::string>& behavioral_events) const;

    nlohmann::json toStixBundle(const std::vector<ATTACKTechnique>& techniques) const;
    nlohmann::json techniqueToStix(const ATTACKTechnique& technique) const;

private:
    std::vector<ATTACKRule> rules;

    static std::string normalize(const std::string& value);
    static bool matchesPattern(const std::string& value, const std::string& pattern);
    static bool containsRequirement(
        const std::vector<std::string>& normalized_values,
        const std::string& requirement);
    static std::string tacticToPhaseName(const std::string& tactic);
    static std::string techniqueUrlPath(const std::string& attack_id);
    static std::string makeDeterministicStixId(const ATTACKTechnique& technique);
};

#endif
