#include "transports/ble/ble_device_registry.hpp"
#include "transports/ble/ble_device_handler.hpp"

namespace mita
{
    namespace transports
    {
        namespace ble
        {


            bool BLEDeviceRegistry::add_device(const std::string &address,
                                              std::shared_ptr<BLEDeviceHandler> handler)
            {
                std::unique_lock<std::shared_mutex> lock(mutex_); 

                if (!handler)
                {
                    return false;
                }

                // dont fucking call add device here it will be triple lock and we cooked
                if (devices_.find(address) != devices_.end())
                {
                    return false;
                }

                devices_[address] = handler;
                return true;
            }

            bool BLEDeviceRegistry::remove_device(const std::string &address)
            {
                std::unique_lock<std::shared_mutex> lock(mutex_);

                auto it = devices_.find(address);

                if (it != devices_.end())
                {
                    devices_.erase(it);
                    return true;
                }

                return false;
            }

            int BLEDeviceRegistry::get_device_count() const
            {
                std::shared_lock<std::shared_mutex> lock(mutex_); 

                return static_cast<int>(devices_.size());
            }

            std::shared_ptr<BLEDeviceHandler> BLEDeviceRegistry::find_by_device_id(const std::string &device_id) const
            {
                std::shared_lock<std::shared_mutex> lock(mutex_); 

                for (const auto &[address, handler] : devices_)
                {
                    if (handler && handler->get_device_id() == device_id)
                    {
                        return handler;
                    }
                }

                return nullptr;
            }


            std::vector<std::shared_ptr<BLEDeviceHandler>> BLEDeviceRegistry::get_all_devices() const
            {
                std::shared_lock<std::shared_mutex> lock(mutex_); 

                std::vector<std::shared_ptr<BLEDeviceHandler>> result;
                result.reserve(devices_.size());

                for (const auto &[address, handler] : devices_)
                {
                    result.push_back(handler);
                }

                return result;
            }

            std::vector<std::shared_ptr<BLEDeviceHandler>> BLEDeviceRegistry::get_authenticated_devices() const
            {
                std::shared_lock<std::shared_mutex> lock(mutex_); 

                std::vector<std::shared_ptr<BLEDeviceHandler>> result;

                for (const auto &[address, handler] : devices_)
                {
                    if (handler && handler->is_authenticated())
                    {
                        result.push_back(handler);
                    }
                }

                return result;
            }

            bool BLEDeviceRegistry::has_device(const std::string &address) const
            {
                std::shared_lock<std::shared_mutex> lock(mutex_); 

                return devices_.find(address) != devices_.end();
            }

            std::shared_ptr<BLEDeviceHandler> BLEDeviceRegistry::get_device(const std::string &address) const
            {
                std::shared_lock<std::shared_mutex> lock(mutex_); 

                auto it = devices_.find(address);
                if (it != devices_.end())
                {
                    return it->second;
                }

                return nullptr;
            }

            size_t BLEDeviceRegistry::remove_disconnected()
            {
                std::unique_lock<std::shared_mutex> lock(mutex_); 

                size_t removed = 0;

                auto it = devices_.begin();
                while (it != devices_.end())
                {
                    if (it->second && !it->second->is_connected())
                    {
                        it = devices_.erase(it);
                        removed++;
                    }
                    else
                    {
                        ++it;
                    }
                }

                return removed;
            }

            void BLEDeviceRegistry::clear()
            {
                std::unique_lock<std::shared_mutex> lock(mutex_);

                devices_.clear();
            }

        } // namespace ble
    }     // namespace transports
} // namespace mita
