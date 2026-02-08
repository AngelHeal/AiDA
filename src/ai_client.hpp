#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

#include <ida.hpp>
#include <kernwin.hpp>
namespace httplib { class Client; }
#include "settings.hpp"

class AIClientBase
{
public:
    using callback_t = std::function<void(const std::string&)>;
    using addr_callback_t = std::function<void(ea_t)>;

    virtual ~AIClientBase() = default;

    virtual bool is_available() const = 0;
    virtual void analyze_function(ea_t ea, callback_t callback) = 0;
    virtual void suggest_name(ea_t ea, callback_t callback) = 0;
    virtual void generate_struct(ea_t ea, callback_t callback) = 0;
    virtual void generate_comments(ea_t ea, callback_t callback) = 0;
    virtual void generate_hook(ea_t ea, callback_t callback) = 0;
    virtual void custom_query(ea_t ea, const std::string& question, callback_t callback) = 0;
    virtual void locate_global_pointer(ea_t ea, const std::string& target_name, addr_callback_t callback) = 0;
    virtual void rename_all(ea_t ea, callback_t callback) = 0;
};

class AIClient : public AIClientBase
{
public:
    AIClient(const settings_t& settings);
    ~AIClient() override;

    void analyze_function(ea_t ea, callback_t callback) override;
    void suggest_name(ea_t ea, callback_t callback) override;
    void generate_struct(ea_t ea, callback_t callback) override;
    void generate_comments(ea_t ea, callback_t callback) override;
    void generate_hook(ea_t ea, callback_t callback) override;
    void custom_query(ea_t ea, const std::string& question, callback_t callback) override;
    void locate_global_pointer(ea_t ea, const std::string& target_name, addr_callback_t callback) override;
    void rename_all(ea_t ea, callback_t callback) override;

    void cancel_current_request();

    std::atomic<bool> _task_done{false};
    std::atomic<bool> _is_request_active{false};
    qstring _current_request_type;
    std::atomic<int> _elapsed_secs{0};

protected:
    const settings_t& _settings;
    std::string _model_name;

    std::thread _worker_thread;
    std::mutex _worker_thread_mutex;

    std::shared_ptr<httplib::Client> _http_client;
    std::mutex _http_client_mutex;

    std::atomic<bool> _cancelled{false};

    void _generate(const std::string& prompt_text, callback_t callback, double temperature, const qstring& request_type);
    std::string _blocking_generate(const std::string& prompt_text, double temperature);
    std::string _http_post_request(
        const std::string& host,
        const std::string& path,
        const httplib::Headers& headers,
        const std::string& body,
        std::function<std::string(const nlohmann::json&)> response_parser);
protected:
    virtual std::string _get_api_host() const = 0;
    virtual std::string _get_api_path(const std::string& model_name) const = 0;
    virtual httplib::Headers _get_api_headers() const = 0;
    virtual nlohmann::json _get_api_payload(const std::string& prompt_text, double temperature) const = 0;
    virtual std::string _parse_api_response(const nlohmann::json& response) const = 0;

private:
    std::shared_ptr<void> _validity_token;
    
    struct ai_request_t;
};

class GeminiClient : public AIClient
{
public:
    GeminiClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _get_api_host() const override;
    std::string _get_api_path(const std::string& model_name) const override;
    httplib::Headers _get_api_headers() const override;
    nlohmann::json _get_api_payload(const std::string& prompt_text, double temperature) const override;
    std::string _parse_api_response(const nlohmann::json& response) const override;
};

class OpenAIClient : public AIClient
{
public:
    OpenAIClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _get_api_host() const override;
    std::string _get_api_path(const std::string& model_name) const override;
    httplib::Headers _get_api_headers() const override;
    nlohmann::json _get_api_payload(const std::string& prompt_text, double temperature) const override;
    std::string _parse_api_response(const nlohmann::json& response) const override;
};

class OpenRouterClient : public OpenAIClient
{
public:
    OpenRouterClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _get_api_host() const override;
    std::string _get_api_path(const std::string& model_name) const override;
    httplib::Headers _get_api_headers() const override;
};

class OllamaClient : public AIClient
{
public:
    OllamaClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _get_api_host() const override;
    std::string _get_api_path(const std::string& model_name) const override;
    httplib::Headers _get_api_headers() const override;
    nlohmann::json _get_api_payload(const std::string& prompt_text, double temperature) const override;
    std::string _parse_api_response(const nlohmann::json& response) const override;
};

class AnthropicClient : public AIClient
{
public:
    AnthropicClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _get_api_host() const override;
    std::string _get_api_path(const std::string& model_name) const override;
    httplib::Headers _get_api_headers() const override;
    nlohmann::json _get_api_payload(const std::string& prompt_text, double temperature) const override;
    std::string _parse_api_response(const nlohmann::json& response) const override;
};

class CopilotClient : public AIClient
{
public:
    CopilotClient(const settings_t& settings);
    bool is_available() const override;
protected:
    std::string _get_api_host() const override;
    std::string _get_api_path(const std::string& model_name) const override;
    httplib::Headers _get_api_headers() const override;
    nlohmann::json _get_api_payload(const std::string& prompt_text, double temperature) const override;
    std::string _parse_api_response(const nlohmann::json& response) const override;
};

std::unique_ptr<AIClient> get_ai_client(const settings_t& settings);
