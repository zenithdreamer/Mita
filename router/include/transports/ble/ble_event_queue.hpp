#ifndef MITA_BLE_EVENT_QUEUE_HPP
#define MITA_BLE_EVENT_QUEUE_HPP

#include "ble_event.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <atomic>

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            class BLEEventQueue
            {
            public:
                explicit BLEEventQueue(size_t max_size = 1000);
                ~BLEEventQueue() = default;

                BLEEventQueue(const BLEEventQueue &) = delete;
                BLEEventQueue &operator=(const BLEEventQueue &) = delete;

                bool enqueue(BLEEvent event);
                std::optional<BLEEvent> dequeue();
                std::optional<BLEEvent> try_dequeue();
                void stop();
                void restart();

                bool is_stopped() const { return stopped_; }
                size_t size() const;
                bool is_empty() const;
                bool is_full() const;

                size_t total_enqueued() const { return total_enqueued_; }
                size_t total_dequeued() const { return total_dequeued_; }
                size_t total_dropped() const { return total_dropped_; }
                void reset_stats();

            private:
                std::queue<BLEEvent> queue_;
                mutable std::mutex mutex_;
                std::condition_variable cv_;
                size_t max_size_;
                std::atomic<bool> stopped_{false};

                // Statistics
                std::atomic<size_t> total_enqueued_{0};
                std::atomic<size_t> total_dequeued_{0};
                std::atomic<size_t> total_dropped_{0};
            };

        } // namespace ble
    }     // namespace transports
} // namespace mita

#endif // MITA_BLE_EVENT_QUEUE_HPP
