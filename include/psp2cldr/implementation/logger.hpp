/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_LOGGER_H
#define PSP2CLDR_LOGGER_H

#ifndef NDEBUG
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#else
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_ERROR
#endif
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

class psp2cldr_logger_wrap
{
  public:
    static std::shared_ptr<spdlog::logger> get_instance()
    {
        if (!m_logger.get())
        {
            m_logger = spdlog::stdout_color_mt("psp2cldr");
            spdlog::set_level(spdlog::level::info);
#ifndef NDEBUG
            m_logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%^%=9l%$] [%n %!@%s:%#] %v");
#else
            m_logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%^%4!l%$] [%n %!@%s:%#] %v");
#endif
        }
        return m_logger;
    }

  private:
    static inline std::shared_ptr<spdlog::logger> m_logger;
};

#ifndef LOG
#define LOG(level, ...) SPDLOG_LOGGER_##level(psp2cldr_logger_wrap::get_instance(), __VA_ARGS__)
#else
#warning "LOG was defined before including logger.hpp"
#endif

class psp2cldr_panic_logger_wrap
{
  public:
    static std::shared_ptr<spdlog::logger> get_instance()
    {
        if (!m_logger.get())
        {
            m_logger = spdlog::stderr_color_mt("psp2cldr panic");
            m_logger->set_pattern("PANIC > %v");
        }
        return m_logger;
    }

  private:
    static inline std::shared_ptr<spdlog::logger> m_logger;
};

#ifndef PANIC_LOG
#define PANIC_LOG(...) SPDLOG_LOGGER_CRITICAL(psp2cldr_panic_logger_wrap::get_instance(), __VA_ARGS__)
#else
#warning "PANIC_LOG was defined before including logger.hpp"
#endif

#endif
