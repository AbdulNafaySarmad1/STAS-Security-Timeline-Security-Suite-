#include "dynamic_timeline.h"

#include <chrono>

namespace {
std::uint64_t monotonicMilliseconds() {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}
}

DynamicTimeline::DynamicTimeline() {
    // Constructor - empty for now
}

void DynamicTimeline::trackEvents() {
    // Simulated malware events (replace with real hooking later)
    const std::uint64_t base = monotonicMilliseconds();
    events.push_back({"ProcessCreate", base});
    events.push_back({"FileCreate", base + 100});
    events.push_back({"RegistryModify", base + 200});
    events.push_back({"NetworkConnect", base + 300});
}

std::vector<Event> DynamicTimeline::getEvents() const {
    return events;
}
