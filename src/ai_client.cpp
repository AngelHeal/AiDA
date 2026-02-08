#include "aida_pro.hpp"
using json = nlohmann::json;


static int idaapi timer_cb(void* ud);
static std::string get_base_prompt_text();

struct AIClient::ai_request_t : public exec_request_t
{
    std::string result;
    bool was_cancelled;
    AIClient::callback_t callback;
    qtimer_t timer;
    qstring request_type;
    std::weak_ptr<void> client_validity_token;

    ai_request_t(
        AIClient::callback_t cb,
        qtimer_t t,
        qstring req_type,
        std::shared_ptr<void> validity_token)
        : was_cancelled(false),
        callback(std::move(cb)),
        timer(t),
        request_type(std::move(req_type)),
        client_validity_token(validity_token) {}

    ~ai_request_t() override = default;

    ssize_t idaapi execute() override
    {
        std::shared_ptr<void> client_validity_sp = client_validity_token.lock();
        if (!client_validity_sp)
        {
            delete this;
            return 0;
        }

        try
        {
            if (timer != nullptr)
            {
                unregister_timer(timer);
                timer = nullptr;
            }

            if (was_cancelled)
            {
                msg(localization::tr("AiDA: Request for %s was cancelled.\n", "AiDA: Запрос для %s был отменён.\n"), request_type.c_str());
            }
            else if (callback)
            {
                callback(result);
            }
        }
        catch (const std::exception& e)
        {
            warning(localization::tr(
                "AI Assistant: Exception caught during AI request callback execution: %s",
                "AI Assistant: Исключение при выполнении callback запроса AI: %s"),
                e.what());
        }
        catch (...)
        {
            warning(localization::tr(
                "AI Assistant: Unknown exception caught during AI request callback execution.",
                "AI Assistant: Неизвестное исключение при выполнении callback запроса AI."));
        }

        delete this;
        return 0;
    }
};

static int idaapi timer_cb(void* ud)
{
    auto* client = static_cast<AIClient*>(ud);

    if (client->_task_done.load())
    {
        return -1;
    }

    if (user_cancelled())
    {
        client->cancel_current_request();
        return -1;
    }

    if (!client->_is_request_active.load())
    {
        client->_is_request_active = true;
        msg(localization::tr(
            "AiDA: Request for %s is in progress, please wait...\n",
            "AiDA: Запрос для %s выполняется, пожалуйста подождите...\n"),
            client->_current_request_type.c_str());
    }
    else
    {
        int elapsed = client->_elapsed_secs.load();
        msg(localization::tr(
            "AiDA: Request for %s is in progress... elapsed time: %d second%s.\n",
            "AiDA: Запрос для %s выполняется... прошло: %d секунд%s.\n"),
            client->_current_request_type.c_str(),
            elapsed,
            elapsed == 1 ? "" : "s");
    }

    client->_elapsed_secs++;
    return 1000; // Reschedule for 1 second later
}

static std::string get_base_prompt_text()
{
    const char* base_prompt = g_settings.prompt_profile == "pro"
        ? BASE_PROMPT_PRO
        : BASE_PROMPT;
    nlohmann::json context = {
        {"response_language", g_settings.response_language}
    };
    return ida_utils::format_prompt(base_prompt, context);
}

AIClient::AIClient(const settings_t& settings)
    : _settings(settings), _validity_token(std::make_shared<char>()) {}

AIClient::~AIClient()
{
    _validity_token.reset();
    cancel_current_request();
    if (_worker_thread.joinable())
    {
        _worker_thread.join();
    }
}

void AIClient::cancel_current_request()
{
    _cancelled = true;
    std::shared_ptr<httplib::Client> client_to_stop;
    {
        std::lock_guard<std::mutex> lock(_http_client_mutex);
        client_to_stop = _http_client;
    }

    if (client_to_stop)
    {
        client_to_stop->stop();
    }
}

void AIClient::_generate(const std::string& prompt_text, callback_t callback, double temperature, const qstring& request_type)
{
    std::lock_guard<std::mutex> lock(_worker_thread_mutex);
    if (_worker_thread.joinable())
    {
        _worker_thread.join();
    }

    _cancelled = false;
    _task_done = false;
    _is_request_active = false;
    _current_request_type = request_type;
    _elapsed_secs = 0;

    qtimer_t timer = register_timer(1000, timer_cb, this);

    auto req = new ai_request_t(callback, timer, request_type, _validity_token);

    auto worker_func = [this, prompt_text, temperature, req, validity_token = this->_validity_token]() {
        std::string result;
        try
        {
            result = this->_blocking_generate(prompt_text, temperature);
        }
        catch (const std::exception& e)
        {
            result = localization::tr("Error: Exception in worker thread: ", "Ошибка: Исключение в рабочем потоке: ");
            result += e.what();
            warning(localization::tr("AiDA: %s", "AiDA: %s"), result.c_str());
        }
        catch (...)
        {
            result = localization::tr("Error: Unknown exception in worker thread.", "Ошибка: Неизвестное исключение в рабочем потоке.");
            warning(localization::tr("AiDA: %s", "AiDA: %s"), result.c_str());
        }

        _task_done = true;

        req->was_cancelled = _cancelled.load();
        if (!req->was_cancelled)
        {
            req->result = std::move(result);
        }

        execute_sync(*req, MFF_NOWAIT);
    };

    _worker_thread = std::thread(worker_func);
}

std::string AIClient::_http_post_request(
    const std::string& host,
    const std::string& path,
    const httplib::Headers& headers,
    const std::string& body,
    std::function<std::string(const json&)> response_parser)
{
    std::shared_ptr<httplib::Client> current_client;
    try
    {
        {
            std::lock_guard<std::mutex> lock(_http_client_mutex);
            _http_client = std::make_shared<httplib::Client>(host.c_str());
            current_client = _http_client;
        }

        current_client->set_default_headers(headers);
        current_client->set_read_timeout(600); // 10 minutes
        current_client->set_connection_timeout(10);

        auto res = current_client->Post(
            path.c_str(),
            body.c_str(),
            body.length(),
            "application/json",
            [this](uint64_t, uint64_t) {
                return !_cancelled.load();
            });

        {
            std::lock_guard<std::mutex> lock(_http_client_mutex);
            _http_client.reset();
        }

        if (_cancelled)
            return localization::tr("Error: Operation cancelled.", "Ошибка: Операция отменена.");

        if (!res)
        {
            auto err = res.error();
            if (err == httplib::Error::Canceled) {
                return localization::tr("Error: Operation cancelled.", "Ошибка: Операция отменена.");
            }
            return std::string(localization::tr("Error: HTTP request failed: ", "Ошибка: HTTP-запрос завершился неудачей: "))
                + httplib::to_string(err);
        }
        if (res->status != 200)
        {
            qstring error_details = "No details in response body.";
            if (!res->body.empty())
            {
                try
                {
                    error_details = json::parse(res->body).dump(2).c_str();
                }
                catch (const json::parse_error&)
                {
                    error_details = res->body.c_str();
                }
            }
            msg(localization::tr(
                "AiDA: API Error. Host: %s, Status: %d\nResponse body: %s\n",
                "AiDA: Ошибка API. Хост: %s, Статус: %d\nТело ответа: %s\n"),
                host.c_str(), res->status, error_details.c_str());
            return std::string(localization::tr("Error: API returned status ", "Ошибка: API вернул статус "))
                + std::to_string(res->status);
        }
        json jres = json::parse(res->body);
        return response_parser(jres);
    }
    catch (const std::exception& e)
    {
        {
            std::lock_guard<std::mutex> lock(_http_client_mutex);
            _http_client.reset();
        }
        warning(localization::tr(
            "AI Assistant: API call to %s failed: %s\n",
            "AI Assistant: Вызов API к %s завершился ошибкой: %s\n"),
            host.c_str(), e.what());
        return std::string(localization::tr("Error: API call failed. Details: ", "Ошибка: Вызов API завершился неудачей. Детали: "))
            + e.what();
    }
}

std::string AIClient::_blocking_generate(const std::string& prompt_text, double temperature)
{
    if (!is_available())
        return "Error: AI client is not initialized. Check API key.";

    auto payload = _get_api_payload(prompt_text, temperature);
    auto headers = _get_api_headers();
    auto host = _get_api_host();
    auto path = _get_api_path(_model_name);
    auto parser = [this](const json& jres) { return _parse_api_response(jres); };

    return _http_post_request(host, path, headers, payload.dump(), parser);
}

void AIClient::analyze_function(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? ANALYZE_FUNCTION_PROMPT_PRO
        : ANALYZE_FUNCTION_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);

    _generate(prompt, callback, _settings.temperature, "function analysis");
}

void AIClient::suggest_name(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? SUGGEST_NAME_PROMPT_PRO
        : SUGGEST_NAME_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);
    _generate(prompt, callback, 0.0, "name suggestion");
}

void AIClient::generate_struct(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea, true);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? GENERATE_STRUCT_PROMPT_PRO
        : GENERATE_STRUCT_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);
    _generate(prompt, callback, 0.0, "struct generation");
}

void AIClient::generate_hook(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    qstring q_func_name;
    get_func_name(&q_func_name, ea);
    std::string func_name = q_func_name.c_str();
    
    static const std::regex non_alnum_re("[^a-zA-Z0-9_]");
    std::string clean_func_name = std::regex_replace(func_name, non_alnum_re, "_");
    
    context["func_name"] = clean_func_name;

    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? GENERATE_HOOK_PROMPT_PRO
        : GENERATE_HOOK_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);
    _generate(prompt, callback, 0.0, "hook generation");
}

void AIClient::generate_comments(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? GENERATE_COMMENTS_PROMPT_PRO
        : GENERATE_COMMENTS_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);
    _generate(prompt, callback, 0.0, "comment generation");
}

void AIClient::custom_query(ea_t ea, const std::string& question, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    context["user_question"] = question;
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? CUSTOM_QUERY_PROMPT_PRO
        : CUSTOM_QUERY_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);
    _generate(prompt, callback, _settings.temperature, "custom query");
}

void AIClient::locate_global_pointer(ea_t ea, const std::string& target_name, addr_callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea, false, 16000);
    if (!context["ok"].get<bool>())
    {
        callback(BADADDR);
        return;
    }
    context["target_name"] = target_name;
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? LOCATE_GLOBAL_POINTER_PROMPT_PRO
        : LOCATE_GLOBAL_POINTER_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);

    auto on_result = [callback, target_name](const std::string& result) {
        if (!result.empty() && result.find("Error:") == std::string::npos && result.find("None") == std::string::npos)
        {
            try
            {
                static const std::regex backtick_re("`");
                std::string clean_result = std::regex_replace(result, backtick_re, "");
                clean_result.erase(0, clean_result.find_first_not_of(" \t\n\r"));
                clean_result.erase(clean_result.find_last_not_of(" \t\n\r") + 1);
                ea_t addr = std::stoull(clean_result, nullptr, 16);
                callback(addr);
            }
            catch (const std::exception&)
            {
                msg(localization::tr(
                    "AI Assistant: AI returned a non-address value for %s: %s\n",
                    "AI Assistant: AI вернул не адресное значение для %s: %s\n"),
                    target_name.c_str(), result.c_str());
                callback(BADADDR);
            }
        }
        else
        {
            callback(BADADDR);
        }
    };
    _generate(prompt, on_result, 0.0, "global pointer location");
}

void AIClient::rename_all(ea_t ea, callback_t callback)
{
    json context = ida_utils::get_context_for_prompt(ea, true);
    if (!context["ok"].get<bool>())
    {
        callback(context["message"].get<std::string>());
        return;
    }
    const char* prompt_template = g_settings.prompt_profile == "pro"
        ? RENAME_ALL_PROMPT_PRO
        : RENAME_ALL_PROMPT;
    std::string prompt = ida_utils::format_prompt(prompt_template, context);
    _generate(prompt, callback, 0.0, "renaming");
}

GeminiClient::GeminiClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.gemini_model_name;
}

bool GeminiClient::is_available() const
{
    return !_settings.gemini_api_key.empty();
}


std::string GeminiClient::_get_api_host() const
{
    if (!_settings.gemini_base_url.empty())
        return _settings.gemini_base_url;
    return "https://generativelanguage.googleapis.com";
}

std::string GeminiClient::_get_api_path(const std::string& model_name) const { return "/v1beta/models/" + model_name + ":generateContent?key=" + _settings.gemini_api_key; }
httplib::Headers GeminiClient::_get_api_headers() const { return {}; }
json GeminiClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"contents", {{{"role", "user"}, {"parts", {{{"text", prompt_text}}}}}}},
        {"generationConfig", {{"temperature", temperature}}}
    };
}

std::string GeminiClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = localization::tr("Gemini API Error: ", "Ошибка Gemini API: ");
        if (jres["error"].is_object() && jres["error"].contains("message"))
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += jres.dump(2);
        }
        msg(localization::tr("AiDA: %s\n", "AiDA: %s\n"), error_msg.c_str());
        return std::string(localization::tr("Error: ", "Ошибка: ")) + error_msg;
    }

    const auto candidates = jres.value("candidates", json::array());
    if (candidates.empty() || !candidates[0].is_object())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason")) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(localization::tr(
                "AiDA: Gemini API blocked the prompt. Reason: %s\n",
                "AiDA: Gemini API заблокировал промпт. Причина: %s\n"),
                reason.c_str());
            return std::string(localization::tr(
                "Error: Prompt was blocked by API for reason: ",
                "Ошибка: Промпт был заблокирован API по причине: "))
                + reason;
        }
        msg(localization::tr(
            "AiDA: Invalid Gemini API response: 'candidates' array is missing or empty.\nResponse body: %s\n",
            "AiDA: Некорректный ответ Gemini API: массив 'candidates' отсутствует или пуст.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'candidates' array from API.",
            "Ошибка: Получен некорректный массив 'candidates' от API.");
    }

    const auto& first_candidate = candidates[0];
    std::string finish_reason = first_candidate.value("finishReason", "UNKNOWN");

    if (finish_reason != "STOP")
    {
        msg(localization::tr(
            "AiDA: Gemini API returned a non-STOP finish reason: %s\n",
            "AiDA: Gemini API вернул причину завершения не STOP: %s\n"),
            finish_reason.c_str());
        return std::string(localization::tr(
            "Error: API request finished unexpectedly. Reason: ",
            "Ошибка: Запрос API завершился неожиданно. Причина: "))
            + finish_reason;
    }

    const auto content = first_candidate.value("content", json::object());
    if (!content.is_object())
    {
        msg(localization::tr(
            "AiDA: Invalid Gemini API response: 'content' object is missing or invalid.\nResponse body: %s\n",
            "AiDA: Некорректный ответ Gemini API: объект 'content' отсутствует или неверен.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'content' object from API.",
            "Ошибка: Получен некорректный объект 'content' от API.");
    }

    const auto parts = content.value("parts", json::array());
    if (parts.empty() || !parts[0].is_object())
    {
        msg(localization::tr(
            "AiDA: Invalid Gemini API response: 'parts' array is missing, empty, or invalid.\nResponse body: %s\n",
            "AiDA: Некорректный ответ Gemini API: массив 'parts' отсутствует, пуст или неверен.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'parts' array from API.",
            "Ошибка: Получен некорректный массив 'parts' от API.");
    }

    return parts[0].value("text", localization::tr(
        "Error: 'text' field not found in API response.",
        "Ошибка: Поле 'text' не найдено в ответе API."));
}

OpenAIClient::OpenAIClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.openai_model_name;
}

bool OpenAIClient::is_available() const
{
    return !_settings.openai_api_key.empty();
}

std::string OpenAIClient::_get_api_host() const
{
    if (!_settings.openai_base_url.empty())
        return _settings.openai_base_url;
    return "https://api.openai.com";
}

std::string OpenAIClient::_get_api_path(const std::string&) const { return "/v1/chat/completions"; }
httplib::Headers OpenAIClient::_get_api_headers() const
{
    return {
        {"Authorization", "Bearer " + _settings.openai_api_key},
        {"Content-Type", "application/json"}
    };
}
json OpenAIClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string model = _model_name;
    json payload = {        
        {"messages", {
            {{"role", "system"}, {"content", get_base_prompt_text()}},
            {{"role", "user"}, {"content", prompt_text}}
        }}
    };

    if (model == "gpt-5")
    {
        payload["model"] = "gpt-5";
        payload["reasoning_effort"] = "minimal";
    }
    else if (model == "gpt-5.1 Instant")
    {

        payload["model"] = "gpt-5.1";
        payload["reasoning_effort"] = "none";
    }
    else if (model == "gpt-5.1 Thinking")
    {
        payload["model"] = "gpt-5.1";
        payload["reasoning_effort"] = "high";
    }
    else
    {
        payload["model"] = _model_name;
        payload["temperature"] = temperature;
    }
    return payload;
}

std::string OpenAIClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = localization::tr("OpenAI API Error: ", "Ошибка OpenAI API: ");
        if (jres["error"].is_object() && jres["error"].contains("message"))
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += jres.dump(2);
        }
        msg(localization::tr("AiDA: %s\n", "AiDA: %s\n"), error_msg.c_str());
        return std::string(localization::tr("Error: ", "Ошибка: ")) + error_msg;
    }

    const auto choices = jres.value("choices", json::array());
    if (choices.empty() || !choices[0].is_object())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason")) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(localization::tr(
                "AiDA: OpenAI API blocked the prompt. Reason: %s\n",
                "AiDA: OpenAI API заблокировал промпт. Причина: %s\n"),
                reason.c_str());
            return std::string(localization::tr(
                "Error: Prompt was blocked by API for reason: ",
                "Ошибка: Промпт был заблокирован API по причине: "))
                + reason;
        }
        msg(localization::tr(
            "AiDA: Invalid OpenAI API response: 'choices' array is missing or empty.\nResponse body: %s\n",
            "AiDA: Некорректный ответ OpenAI API: массив 'choices' отсутствует или пуст.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'choices' array from API.",
            "Ошибка: Получен некорректный массив 'choices' от API.");
    }

    const auto& first_choice = choices[0];
    std::string finish_reason = first_choice.value("finish_reason", "UNKNOWN");

    if (finish_reason != "stop" && finish_reason != "STOP")
    {
        msg(localization::tr(
            "AiDA: OpenAI API returned a non-STOP finish reason: %s\n",
            "AiDA: OpenAI API вернул причину завершения не STOP: %s\n"),
            finish_reason.c_str());
        return std::string(localization::tr(
            "Error: API request finished unexpectedly. Reason: ",
            "Ошибка: Запрос API завершился неожиданно. Причина: "))
            + finish_reason;
    }

    const auto message = first_choice.value("message", json::object());
    if (!message.is_object())
    {
        msg(localization::tr(
            "AiDA: Invalid OpenAI API response: 'message' object is missing or invalid.\nResponse body: %s\n",
            "AiDA: Некорректный ответ OpenAI API: объект 'message' отсутствует или неверен.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'message' object from API.",
            "Ошибка: Получен некорректный объект 'message' от API.");
    }

    return message.value("content", localization::tr(
        "Error: 'content' field not found in API response.",
        "Ошибка: Поле 'content' не найдено в ответе API."));
}

OpenRouterClient::OpenRouterClient(const settings_t& settings) : OpenAIClient(settings)
{
    _model_name = _settings.openrouter_model_name;
}

bool OpenRouterClient::is_available() const
{
    return !_settings.openrouter_api_key.empty();
}

std::string OpenRouterClient::_get_api_host() const { return "https://openrouter.ai"; }
std::string OpenRouterClient::_get_api_path(const std::string&) const { return "/api/v1/chat/completions"; }
httplib::Headers OpenRouterClient::_get_api_headers() const
{
    std::string auth = _settings.openrouter_api_key;
    if (auth.find("Bearer ") != 0) {
        auth = "Bearer " + auth;
    }
    return {
        {"Authorization", auth},
        {"Content-Type", "application/json"}
    };
}

OllamaClient::OllamaClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.ollama_model_name;
}

bool OllamaClient::is_available() const
{
    return !_model_name.empty();
}

std::string OllamaClient::_get_api_host() const
{
    if (!_settings.ollama_base_url.empty())
        return _settings.ollama_base_url;
    return "http://127.0.0.1:11434";
}

std::string OllamaClient::_get_api_path(const std::string&) const { return "/api/chat"; }
httplib::Headers OllamaClient::_get_api_headers() const { return {{"Content-Type", "application/json"}}; }
json OllamaClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"model", _model_name},
        {"messages", {
            {{"role", "system"}, {"content", get_base_prompt_text()}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"stream", false},
        {"options", {{"temperature", temperature}}}
    };
}

std::string OllamaClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = localization::tr("Ollama API Error: ", "Ошибка Ollama API: ");
        if (jres["error"].is_string())
        {
            error_msg += jres["error"].get<std::string>();
        }
        else
        {
            error_msg += jres["error"].dump(2);
        }
        msg(localization::tr("AiDA: %s\n", "AiDA: %s\n"), error_msg.c_str());
        return std::string(localization::tr("Error: ", "Ошибка: ")) + error_msg;
    }

    if (jres.contains("message") && jres["message"].is_object())
    {
        const auto message = jres["message"];
        if (message.contains("content"))
            return message.value("content", localization::tr(
                "Error: 'content' field not found in API response.",
                "Ошибка: Поле 'content' не найдено в ответе API."));
    }

    if (jres.contains("response") && jres["response"].is_string())
        return jres["response"].get<std::string>();

    msg(localization::tr(
        "AiDA: Invalid Ollama API response.\nResponse body: %s\n",
        "AiDA: Некорректный ответ Ollama API.\nТело ответа: %s\n"),
        jres.dump(2).c_str());
    return localization::tr(
        "Error: Received invalid response from Ollama API.",
        "Ошибка: Получен некорректный ответ от Ollama API.");
}

AnthropicClient::AnthropicClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.anthropic_model_name;
}

bool AnthropicClient::is_available() const
{
    return !_settings.anthropic_api_key.empty();
}

std::string AnthropicClient::_get_api_host() const
{
    if (!_settings.anthropic_base_url.empty())
        return _settings.anthropic_base_url;
    return "https://api.anthropic.com";
}

std::string AnthropicClient::_get_api_path(const std::string&) const { return "/v1/messages"; }
httplib::Headers AnthropicClient::_get_api_headers() const
{
    httplib::Headers headers = {
        {"x-api-key", _settings.anthropic_api_key},
        {"anthropic-version", "2023-06-01"},
        {"Content-Type", "application/json"}
    };

    if (_model_name.find("claude-opus-4-5") != std::string::npos)
    {
        headers.emplace("anthropic-beta", "effort-2025-11-24");
    }
    else if (_model_name.find("claude-3-7-sonnet") != std::string::npos)
    {
        headers.emplace("anthropic-beta", "output-128k-2025-02-19");
    }

    return headers;
}
json AnthropicClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    std::string model_id = _model_name;
    std::string effort = "";
    bool use_thinking = false;

    if (model_id == "claude-opus-4-5 (High Effort)")
    {
        model_id = "claude-opus-4-5";
        effort = "high";
    }
    else if (model_id == "claude-opus-4-5 (Medium Effort)")
    {
        model_id = "claude-opus-4-5";
        effort = "medium";
    }
    else if (model_id == "claude-opus-4-5 (Low Effort)")
    {
        model_id = "claude-opus-4-5";
        effort = "low";
    }
    else if (model_id == "claude-3-7-sonnet-thought")
    {
        model_id = "claude-3-7-sonnet";
        use_thinking = true;
    }

    json payload = {
        {"model", model_id},
        {"system", get_base_prompt_text()},
        {"messages", {{{"role", "user"}, {"content", prompt_text}}}},
        {"max_tokens", 4096}
    };

    if (!effort.empty())
    {
        payload["output_config"] = { {"effort", effort} };
    }
    else if (use_thinking)
    {
        payload["thinking"] = { {"type", "enabled"}, {"budget_tokens", 4096} };
        payload["max_tokens"] = 8192; // Increase limit for thoughts
    }
    else
    {
        payload["temperature"] = temperature;
    }

    return payload;
}

std::string AnthropicClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = localization::tr("Anthropic API Error: ", "Ошибка Anthropic API: ");
        if (jres["error"].is_object() && jres["error"].contains("message"))
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += jres.dump(2);
        }
        msg(localization::tr("AiDA: %s\n", "AiDA: %s\n"), error_msg.c_str());
        return std::string(localization::tr("Error: ", "Ошибка: ")) + error_msg;
    }

    const auto content = jres.value("content", json::array());
    if (content.empty())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason")) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(localization::tr(
                "AiDA: Anthropic API blocked the prompt. Reason: %s\n",
                "AiDA: Anthropic API заблокировал промпт. Причина: %s\n"),
                reason.c_str());
            return std::string(localization::tr(
                "Error: Prompt was blocked by API for reason: ",
                "Ошибка: Промпт был заблокирован API по причине: "))
                + reason;
        }
        msg(localization::tr(
            "AiDA: Invalid Anthropic API response: 'content' array is missing or empty.\nResponse body: %s\n",
            "AiDA: Некорректный ответ Anthropic API: массив 'content' отсутствует или пуст.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'content' array from API.",
            "Ошибка: Получен некорректный массив 'content' от API.");
    }

    std::string stop_reason = jres.value("stop_reason", "UNKNOWN");
    if (stop_reason != "end_turn" && stop_reason != "max_tokens")
    {
        msg(localization::tr(
            "AiDA: Anthropic API returned a non-success stop reason: %s\n",
            "AiDA: Anthropic API вернул неуспешную причину завершения: %s\n"),
            stop_reason.c_str());
        return std::string(localization::tr(
            "Error: API request finished unexpectedly. Reason: ",
            "Ошибка: Запрос API завершился неожиданно. Причина: "))
            + stop_reason;
    }

    std::string result_text;
    for (const auto& block : content)
    {
        if (block.is_object() && block.value("type", "") == "text")
        {
            result_text += block.value("text", "");
        }
    }

    if (result_text.empty())
    {
        msg(localization::tr(
            "AiDA: No text content found in Anthropic API response.\nResponse body: %s\n",
            "AiDA: В ответе Anthropic API не найден текст.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: No text content found in API response.",
            "Ошибка: В ответе API не найден текст.");
    }

    return result_text;
}

CopilotClient::CopilotClient(const settings_t& settings) : AIClient(settings)
{
    _model_name = _settings.copilot_model_name;
}

bool CopilotClient::is_available() const
{
    return !_settings.copilot_proxy_address.empty();
}

std::string CopilotClient::_get_api_host() const { return _settings.copilot_proxy_address; }
std::string CopilotClient::_get_api_path(const std::string&) const { return "/v1/chat/completions"; }
httplib::Headers CopilotClient::_get_api_headers() const { return {{"Content-Type", "application/json"}}; }
json CopilotClient::_get_api_payload(const std::string& prompt_text, double temperature) const
{
    return {
        {"model", _model_name},
        {"messages", {
            {{"role", "system"}, {"content", get_base_prompt_text()}},
            {{"role", "user"}, {"content", prompt_text}}
        }},
        {"temperature", temperature}
    };
}
std::string CopilotClient::_parse_api_response(const json& jres) const
{
    if (jres.contains("error"))
    {
        std::string error_msg = localization::tr("Copilot API Error: ", "Ошибка Copilot API: ");
        if (jres["error"].is_object() && jres["error"].contains("message"))
        {
            error_msg += jres["error"]["message"].get<std::string>();
        }
        else
        {
            error_msg += jres.dump(2);
        }
        msg(localization::tr("AiDA: %s\n", "AiDA: %s\n"), error_msg.c_str());
        return std::string(localization::tr("Error: ", "Ошибка: ")) + error_msg;
    }

    const auto choices = jres.value("choices", json::array());
    if (choices.empty() || !choices[0].is_object())
    {
        if (jres.contains("promptFeedback") && jres["promptFeedback"].contains("blockReason")) {
            std::string reason = jres["promptFeedback"]["blockReason"].get<std::string>();
            msg(localization::tr(
                "AiDA: Copilot API blocked the prompt. Reason: %s\n",
                "AiDA: Copilot API заблокировал промпт. Причина: %s\n"),
                reason.c_str());
            return std::string(localization::tr(
                "Error: Prompt was blocked by API for reason: ",
                "Ошибка: Промпт был заблокирован API по причине: "))
                + reason;
        }
        msg(localization::tr(
            "AiDA: Invalid Copilot API response: 'choices' array is missing or empty.\nResponse body: %s\n",
            "AiDA: Некорректный ответ Copilot API: массив 'choices' отсутствует или пуст.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'choices' array from API.",
            "Ошибка: Получен некорректный массив 'choices' от API.");
    }

    const auto& first_choice = choices[0];
    std::string finish_reason = first_choice.value("finish_reason", "UNKNOWN");

    if (finish_reason != "stop" && finish_reason != "STOP")
    {
        msg(localization::tr(
            "AiDA: Copilot API returned a non-STOP finish reason: %s\n",
            "AiDA: Copilot API вернул причину завершения не STOP: %s\n"),
            finish_reason.c_str());
        return std::string(localization::tr(
            "Error: API request finished unexpectedly. Reason: ",
            "Ошибка: Запрос API завершился неожиданно. Причина: "))
            + finish_reason;
    }

    const auto message = first_choice.value("message", json::object());
    if (!message.is_object())
    {
        msg(localization::tr(
            "AiDA: Invalid Copilot API response: 'message' object is missing or invalid.\nResponse body: %s\n",
            "AiDA: Некорректный ответ Copilot API: объект 'message' отсутствует или неверен.\nТело ответа: %s\n"),
            jres.dump(2).c_str());
        return localization::tr(
            "Error: Received invalid 'message' object from API.",
            "Ошибка: Получен некорректный объект 'message' от API.");
    }

    return message.value("content", localization::tr(
        "Error: 'content' field not found in API response.",
        "Ошибка: Поле 'content' не найдено в ответе API."));
}

std::unique_ptr<AIClient> get_ai_client(const settings_t& settings)
{
    qstring provider = ida_utils::qstring_tolower(settings.api_provider.c_str());

    msg(localization::tr(
        "AI Assistant: Initializing AI provider: %s\n",
        "AI Assistant: Инициализация провайдера AI: %s\n"),
        provider.c_str());

    if (provider == "gemini")
    {
        return std::make_unique<GeminiClient>(settings);
    }
    else if (provider == "openai")
    {
        return std::make_unique<OpenAIClient>(settings);
    }
    else if (provider == "openrouter")
    {
        return std::make_unique<OpenRouterClient>(settings);
    }
    else if (provider == "ollama")
    {
        return std::make_unique<OllamaClient>(settings);
    }
    else if (provider == "anthropic")
    {
        return std::make_unique<AnthropicClient>(settings);
    }
    else if (provider == "copilot")
    {
        return std::make_unique<CopilotClient>(settings);
    }
    else
    {
        warning(localization::tr(
            "AI Assistant: Unknown AI provider '%s' in settings. No AI features will be available.",
            "AI Assistant: Неизвестный провайдер AI '%s' в настройках. Функции AI будут недоступны."),
            provider.c_str());
        return nullptr;
    }
}
