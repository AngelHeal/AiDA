#include "aida_pro.hpp"

aida_plugin_t::aida_plugin_t()
{
    msg(localization::tr("--- AI Assistant Plugin Loading ---\n", "--- Загрузка плагина AI Assistant ---\n"));
    g_settings.load(this);
    reinit_ai_client();
    register_actions();
    hook_to_notification_point(HT_UI, ui_callback, this);
    msg(localization::tr("--- AI Assistant Plugin Loaded Successfully ---\n", "--- Плагин AI Assistant успешно загружен ---\n"));
}

aida_plugin_t::~aida_plugin_t()
{
    unhook_from_notification_point(HT_UI, ui_callback, this);
    unregister_actions();
    msg(localization::tr("--- AI Assistant Plugin has been unloaded ---\n", "--- Плагин AI Assistant выгружен ---\n"));
}

void aida_plugin_t::reinit_ai_client()
{
    ai_client = get_ai_client(g_settings);
    if (!ai_client || !ai_client->is_available())
    {
        msg(localization::tr(
            "AI Assistant: No AI client is available. AI features will be limited.\n",
            "AI Assistant: Нет доступного AI клиента. Функции AI будут ограничены.\n"));
    }
}

bool idaapi aida_plugin_t::run(size_t /*arg*/)
{
    info(localization::tr(
        "AI Assistant is active. Use the right-click context menu in a code view or Tools->AI Assistant.",
        "AI Assistant активен. Используйте контекстное меню в окне кода или Tools->AI Assistant."));
    return true;
}

void aida_plugin_t::register_actions()
{
    struct action_def_t {
        const char* name;
        const char* label_en;
        const char* label_ru;
        action_handler::action_func_t handler;
        const char* shortcut;
    };

    static const action_def_t action_definitions[] = {
        {"ai_assistant:analyze", "Analyze function...", "Анализировать функцию...", handle_analyze_function, "Ctrl+Alt+A"},
        {"ai_assistant:rename", "Suggest new name...", "Предложить новое имя...", handle_rename_function, "Ctrl+Alt+S"},
        {"ai_assistant:comment", "Add AI-generated comments", "Добавить комментарии от AI", handle_auto_comment, "Ctrl+Alt+C"},
        {"ai_assistant:gen_struct", "Generate struct from function", "Сгенерировать структуру из функции", handle_generate_struct, "Ctrl+Alt+G"},
        {"ai_assistant:gen_hook", "Generate MinHook C++ snippet", "Сгенерировать C++ сниппет MinHook", handle_generate_hook, "Ctrl+Alt+H"},
        {"ai_assistant:custom_query", "Custom query...", "Пользовательский запрос...", handle_custom_query, "Ctrl+Alt+Q"},
        {"ai_assistant:copy_context", "Copy Context", "Скопировать контекст", handle_copy_context, "Ctrl+Alt+X"},
        {"ai_assistant:rename_all", "Rename variables/functions...", "Переименовать переменные/функции...", handle_rename_all, "Ctrl+Alt+R"},
        {"ai_assistant:scan_for_offsets", "Scan for Engine Pointers (Coming Soon!)", "Сканировать указатели движка (скоро)", handle_scan_for_offsets, ""},
        {"ai_assistant:settings", "Settings...", "Настройки...", handle_show_settings, "Ctrl+Alt+O"},
    };

    const char* menu_root = localization::tr("AI Assistant/", "AI Ассистент/");

    for (const auto& def : action_definitions)
    {
        actions_list.push_back(def.name);
        action_desc_t adesc = ACTION_DESC_LITERAL_PLUGMOD(
            def.name,
            localization::tr(def.label_en, def.label_ru),
            new action_handler(def.handler, this),
            this,
            def.shortcut,
            nullptr,
            -1);
        adesc.flags |= ADF_OWN_HANDLER;

        if (!register_action(adesc))
        {
            msg(localization::tr("AI Assistant: Failed to register action %s\n",
                "AI Assistant: Не удалось зарегистрировать действие %s\n"), def.name);
            continue;
        }
        attach_action_to_menu(menu_root, def.name, SETMENU_APP);
    }
}

void aida_plugin_t::unregister_actions()
{
    for (const auto& action_name : actions_list)
    {
        unregister_action(action_name.c_str());
    }
    actions_list.clear();
}

static plugmod_t* idaapi init()
{
    PLUGIN.comment = localization::tr("AI-powered game reversing assistant", "AI-помощник для реверс-инжиниринга");
    PLUGIN.help = localization::tr("Right-click in code views or use the Tools->AI Assistant menu",
        "Кликните правой кнопкой в окне кода или используйте меню Tools->AI Assistant");
    PLUGIN.wanted_name = localization::tr("AI Assistant", "AI Ассистент");
    return new aida_plugin_t();
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "AI-powered game reversing assistant",
  "Right-click in code views or use the Tools->AI Assistant menu",
  "AI Assistant",
  ""
};
