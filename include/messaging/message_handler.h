#ifndef MESSAGE_HANDLER_H
#define MESSAGE_HANDLER_H

#include <string>
#include <ArduinoJson.h>
#include "../../shared/protocol/protocol_types.h"

class IMessageHandler
{
public:
    virtual ~IMessageHandler() = default;
    virtual bool canHandle(const std::string &message_type) const = 0;
    virtual bool handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response) = 0;
};

class CommandHandler : public IMessageHandler
{
private:
    std::string device_id;

public:
    CommandHandler(const std::string &device_id);
    bool canHandle(const std::string &message_type) const override;
    bool handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response) override;

private:
    bool handleStatusCommand(DynamicJsonDocument &response);
    bool handleRestartCommand(DynamicJsonDocument &response);
    bool handleLedCommand(const std::string &command, DynamicJsonDocument &response);
};

class PingHandler : public IMessageHandler
{
private:
    std::string device_id;

public:
    PingHandler(const std::string &device_id);
    bool canHandle(const std::string &message_type) const override;
    bool handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response) override;
};

class MessageDispatcher
{
private:
    IMessageHandler **handlers;
    size_t handler_count;
    size_t max_handlers;

public:
    MessageDispatcher(size_t max_handlers = 10);
    ~MessageDispatcher();

    bool addHandler(IMessageHandler *handler);
    bool processMessage(const std::string &json_message, std::string &response);
};

#endif // MESSAGE_HANDLER_H