#include "../include/messaging/message_handler.h"

#ifndef LED_BUILTIN
#define LED_BUILTIN 2
#endif

// CommandHandler implementation
CommandHandler::CommandHandler(const String &device_id) : device_id(device_id) {}

bool CommandHandler::canHandle(const String &message_type) const
{
    return message_type == "command";
}

bool CommandHandler::handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response)
{
    const char *command = message["command"];
    if (!command)
    {
        return false;
    }

    response["type"] = "command_response";
    response["device_id"] = device_id;
    response["command"] = command;
    response["timestamp"] = millis();

    String cmd_str(command);

    if (cmd_str == "status")
    {
        return handleStatusCommand(response);
    }
    else if (cmd_str == "restart")
    {
        return handleRestartCommand(response);
    }
    else if (cmd_str == "led_on" || cmd_str == "led_off")
    {
        return handleLedCommand(cmd_str, response);
    }
    else
    {
        response["status"] = "unknown_command";
        return true;
    }
}

bool CommandHandler::handleStatusCommand(DynamicJsonDocument &response)
{
    response["status"] = "online";
    response["uptime"] = millis() / 1000;
    response["free_heap"] = ESP.getFreeHeap();
    return true;
}

bool CommandHandler::handleRestartCommand(DynamicJsonDocument &response)
{
    response["status"] = "restarting";
    // Note: The actual restart should be handled by the caller after sending response
    return true;
}

bool CommandHandler::handleLedCommand(const String &command, DynamicJsonDocument &response)
{
    if (command == "led_on")
    {
        digitalWrite(LED_BUILTIN, HIGH);
        response["status"] = "led_on";
    }
    else if (command == "led_off")
    {
        digitalWrite(LED_BUILTIN, LOW);
        response["status"] = "led_off";
    }
    return true;
}

// PingHandler implementation
PingHandler::PingHandler(const String &device_id) : device_id(device_id) {}

bool PingHandler::canHandle(const String &message_type) const
{
    return message_type == "ping";
}

bool PingHandler::handleMessage(const DynamicJsonDocument &message, DynamicJsonDocument &response)
{
    response["type"] = "pong";
    response["device_id"] = device_id;
    response["timestamp"] = millis();

    if (message.containsKey("ping_id"))
    {
        response["ping_id"] = message["ping_id"];
    }

    return true;
}

// MessageDispatcher implementation
MessageDispatcher::MessageDispatcher(size_t max_handlers)
    : handler_count(0), max_handlers(max_handlers)
{
    handlers = new IMessageHandler *[max_handlers];
    for (size_t i = 0; i < max_handlers; i++)
    {
        handlers[i] = nullptr;
    }
}

MessageDispatcher::~MessageDispatcher()
{
    delete[] handlers;
}

bool MessageDispatcher::addHandler(IMessageHandler *handler)
{
    if (handler_count >= max_handlers)
    {
        return false;
    }

    handlers[handler_count++] = handler;
    return true;
}

bool MessageDispatcher::processMessage(const String &json_message, String &response)
{
    DynamicJsonDocument message_doc(256);
    DeserializationError error = deserializeJson(message_doc, json_message);

    if (error)
    {
        Serial.printf("MessageDispatcher: JSON parse error: %s\n", error.c_str());
        return false;
    }

    const char *type = message_doc["type"];
    if (!type)
    {
        Serial.println("MessageDispatcher: No message type found");
        return false;
    }

    String message_type(type);
    Serial.printf("MessageDispatcher: Processing message type: %s\n", message_type.c_str());

    // Find appropriate handler
    for (size_t i = 0; i < handler_count; i++)
    {
        if (handlers[i] && handlers[i]->canHandle(message_type))
        {
            DynamicJsonDocument response_doc(256);

            if (handlers[i]->handleMessage(message_doc, response_doc))
            {
                serializeJson(response_doc, response);
                Serial.printf("MessageDispatcher: Response generated: %s\n", response.c_str());
                return true;
            }
            else
            {
                Serial.printf("MessageDispatcher: Handler failed for type: %s\n", message_type.c_str());
                return false;
            }
        }
    }

    Serial.printf("MessageDispatcher: No handler found for message type: %s\n", message_type.c_str());
    return false;
}