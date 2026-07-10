#include <iostream>
#include <string>
#include <vector>

#ifdef STAS_WITH_JSON
#include "attack_mapper.h"
#include "import_profiler.h"
#endif

#include "static_analysis.h"
#include "dynamic_timeline.h"
#include "sandbox.h"
#include "sqlite_db.h"
#include "risk_scoring.h"
#include "autorun_detector.h"

namespace {
std::vector<std::string> eventTypes(const std::vector<Event>& events) {
    std::vector<std::string> values;
    values.reserve(events.size());
    for (const auto& event : events) {
        values.push_back(event.type);
    }
    return values;
}

#ifdef STAS_WITH_JSON
bool loadDefaultAttackRules(ATTACKMapper& mapper) {
    const std::vector<std::string> candidates = {
        "data/attack_rules.json",
        "../data/attack_rules.json",
        "../../data/attack_rules.json",
        "../../../data/attack_rules.json"
    };

    for (const auto& path : candidates) {
        if (mapper.loadRulesFromFile(path)) {
            return true;
        }
    }
    return false;
}

bool loadDefaultImportCapabilityRules(ImportProfiler& profiler) {
    const std::vector<std::string> candidates = {
        "data/import_capability_rules.json",
        "../data/import_capability_rules.json",
        "../../data/import_capability_rules.json",
        "../../../data/import_capability_rules.json"
    };

    for (const auto& path : candidates) {
        if (profiler.loadRulesFromFile(path)) {
            return true;
        }
    }
    return false;
}
#endif
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: stas_engine <sample_path>" << std::endl;
        return 1;
    }
    std::string sample = argv[1];

    // Static Analysis
    StaticAnalysis sa(sample);
    sa.performAnalysis();

    // Sandbox and Dynamic Analysis
    Sandbox sb(sample);
    sb.executeInSandbox();

    // Timeline from Dynamic
    DynamicTimeline dt;
    dt.trackEvents();  // Simulated

    // DB Storage
        // Store events to SQLite
    std::cout << "Events saved to events.db" << std::endl;
    SQLiteDB db("events.db");
    db.storeEvents(dt.getEvents());

    // Risk Scoring
    RiskScoring rs(dt.getEvents());
    int score = rs.calculateScore();
    std::cout << "Threat Score: " << score << std::endl;

#ifdef STAS_WITH_JSON
    // Import Capability Profiling
    ImportProfiler importProfiler;
    if (loadDefaultImportCapabilityRules(importProfiler)) {
        const ImportProfile importProfile = importProfiler.profileImports(sa.getImportedFunctions());
        std::cout << "Import Behavior Prediction:" << std::endl;
        std::cout << importProfiler.toJson(importProfile).dump(2) << std::endl;
    } else {
        std::cerr << "Import Behavior Prediction: could not load data/import_capability_rules.json" << std::endl;
    }

    // MITRE ATT&CK Mapping
    ATTACKMapper attackMapper;
    if (loadDefaultAttackRules(attackMapper)) {
        const auto techniques = attackMapper.mapTechniques(
            sa.getImportedFunctions(),
            eventTypes(dt.getEvents()));

        if (!techniques.empty()) {
            std::cout << "MITRE ATT&CK STIX 2.1 Mapping:" << std::endl;
            std::cout << attackMapper.toStixBundle(techniques).dump(2) << std::endl;
        } else {
            std::cout << "MITRE ATT&CK Mapping: no matching techniques" << std::endl;
        }
    } else {
        std::cerr << "MITRE ATT&CK Mapping: could not load data/attack_rules.json" << std::endl;
    }
#else
    std::cout << "JSON-backed import profiling and MITRE ATT&CK mapping are disabled in this build" << std::endl;
#endif

    // Graph Generation

    std::cout <<"Graphs are disabled in this build." << std::endl;

    // Autorun Detection
    AutorunDetector ad;
    ad.detectPersistence();

    // Export (IPC to Python)
    // Use named pipes to send data to Python dashboard

    return 0;
        
}
