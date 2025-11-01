#include "transports/ble/ble_event_queue.hpp"

namespace mita
{
    namespace transports
    {
        namespace ble
        {

            BLEEventQueue::BLEEventQueue(size_t max_size)
                : max_size_(max_size)
            {
            }


            bool BLEEventQueue::enqueue(BLEEvent event)
            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (stopped_)
                {
                    return false;
                }

                // check if queue is full
                if (max_size_ > 0 && queue_.size() >= max_size_)
                {
                    total_dropped_++;
                    return false;
                }

                queue_.push(std::move(event));
                total_enqueued_++;

                cv_.notify_one();

                return true;
            }


            std::optional<BLEEvent> BLEEventQueue::dequeue()
            {
                std::unique_lock<std::mutex> lock(mutex_);

                // wait untill it available
                cv_.wait(lock, [this] { return !queue_.empty() || stopped_; });

                if (stopped_ && queue_.empty())
                {
                    return std::nullopt;
                }

                if (queue_.empty())
                {
                    return std::nullopt;
                }

                // pop event from queue
                BLEEvent event = std::move(queue_.front());
                queue_.pop();
                total_dequeued_++;

                return event;
            }

            std::optional<BLEEvent> BLEEventQueue::try_dequeue()
            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (queue_.empty())
                {
                    return std::nullopt;
                }

                // pop event from queue
                BLEEvent event = std::move(queue_.front());
                queue_.pop();
                total_dequeued_++;

                return event;
            }

            void BLEEventQueue::stop()
            {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    stopped_ = true;
                }

                cv_.notify_all();
            }

            void BLEEventQueue::restart()
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopped_ = false;
            }


            size_t BLEEventQueue::size() const
            {
                std::lock_guard<std::mutex> lock(mutex_);
                return queue_.size();
            }

            bool BLEEventQueue::is_empty() const
            {
                std::lock_guard<std::mutex> lock(mutex_);
                return queue_.empty();
            }

            bool BLEEventQueue::is_full() const
            {
                std::lock_guard<std::mutex> lock(mutex_);

                if (max_size_ == 0)
                {
                    return false;
                }

                return queue_.size() >= max_size_;
            }

            void BLEEventQueue::reset_stats()
            {
                total_enqueued_ = 0;
                total_dequeued_ = 0;
                total_dropped_ = 0;
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
