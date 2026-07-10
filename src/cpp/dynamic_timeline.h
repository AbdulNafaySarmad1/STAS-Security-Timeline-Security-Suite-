#ifndef DYNAMIC_TIMELINE_H
#define DYNAMIC_TIMELINE_H

#include <cstdint>
#include <vector>
#include <string>

struct Event {
    std::string type;
    std::uint64_t timestamp;
    // Add more fields later if needed (pid, details, etc.)
};

class DynamicTimeline {
private:
    std::vector<Event> events;

public:
    DynamicTimeline();
    void trackEvents();  // Simulated events for now
    std::vector<Event> getEvents() const;
};

#endif
